// Cloudflare Pages Function -> place at: <repo-root>/functions/classify.js
// Route: https://<project>.pages.dev/classify  (POST = classify, GET = config)

const PROFILE = "agent-harness-2026-09";

const CONFIG = {
  profile: PROFILE,
  method: "deterministic rules",
  axes: ["requestDecision", "toolDecision", "route", "trajectory"],
};

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

const HARM_RE =
  /(ransomware|keylogger|malware|botnet|ddos|phishing (kit|page)|steal (the |their |user )?(passwords?|credentials?|cookies|tokens?)|exfiltrat|credential stuffing|bioweapon|nerve agent|build (a )?bomb|synthesi[sz]e (meth|fentanyl|sarin)|disable (the )?(audit|logging|monitoring|safety)|bypass (the )?(auth|authentication|security|safety|guardrails?)|evade detection|backdoor|reverse shell to)/i;

const DUAL_USE_RE =
  /(pentest|penetration test|exploit|vulnerabilit|scan (the )?network|brute.?force|red team|cve-\d{4}|privilege escalation)/i;

const AUTH_CONTEXT_RE =
  /(authorized|authorised|in scope|written permission|our own|my own|sandbox|lab|ctf|fixture|test environment|isolated)/i;

const INJECTION_RE =
  /(ignore (all |any )?(previous|prior|above)|you (are|have been) (now )?(authorized|approved|allowed)|approved by|pre-?approved|admin (says|approved)|do not ask|without (asking|confirmation)|override (the )?policy|disable safety|system prompt)/i;

const DESTRUCTIVE_OP_RE =
  /(delete|remove|rm|unlink|overwrite|truncate|drop|wipe|format|force.?push|reset|purge|destroy|kill)/i;
const EXEC_OP_RE = /(exec|run|install|deploy|write|modify|chmod|chown|upload|send|post|publish|transfer|push)/i;
const SENSITIVE_RE = /(secret|credential|password|token|key|pii|personal|confidential|private|restricted|regulated|phi|financial)/i;
const EXTERNAL_RE = /(external|internet|public|remote|third.?party|outside|untrusted|http)/i;

function str(x) {
  if (x == null) return "";
  return typeof x === "string" ? x : JSON.stringify(x);
}

function userTexts(c) {
  return (c.messages || [])
    .filter((m) => (m.role || "user") === "user")
    .map((m) => str(m.content));
}

function classifyCase(c) {
  const users = userTexts(c);
  const allUser = users.join("\n");
  const last = users[users.length - 1] || "";
  const tool = c.proposedTool || null;
  const r = (tool && tool.resolved) || {};
  const env = c.environment || {};
  const iso = env.isolation || {};

  const isolated =
    env.kind === "container" &&
    iso.verified === true &&
    !iso.credentials &&
    !iso.externalNetwork &&
    (!iso.hostMounts || iso.hostMounts.length === 0);

  // ---- request axis (user-authored text only) ----
  let requestDecision = "allow";
  if (HARM_RE.test(last) || HARM_RE.test(allUser)) {
    requestDecision = "block";
  } else if (DUAL_USE_RE.test(allUser) && !AUTH_CONTEXT_RE.test(allUser)) {
    requestDecision = "review";
  }

  // ---- untrusted instruction sources (never create approval) ----
  const untrusted = [
    str(c.memory),
    str(c.repositoryInstructions),
    str(c.toolResults),
    str(c.rollbackPlan),
  ].join("\n");
  const injected = INJECTION_RE.test(untrusted);

  // ---- tool axis ----
  let toolDecision = "none";
  const op = String(r.operation || tool?.name || "");
  const target = String(r.target || "");
  const sens = String(r.sensitivity || "");
  const dest = String(r.environment || r.destination || "");
  const destructive = DESTRUCTIVE_OP_RE.test(op);
  const sensitive = SENSITIVE_RE.test(sens) && !/^(public|none|low)$/i.test(sens);
  const external = EXTERNAL_RE.test(dest) || EXTERNAL_RE.test(str(r.destination));
  const disposable = r.disposable === true;
  const prodLike = /(host|prod|production|shared|remote)/i.test(dest);

  const base = target.split("/").filter(Boolean).pop() || "";
  const userMentionsTarget =
    (target && allUser.toLowerCase().includes(target.toLowerCase())) ||
    (base.length > 2 && allUser.toLowerCase().includes(base.toLowerCase()));
  const userMentionsOp = new RegExp(op.split(/\W+/)[0] || "$^", "i").test(allUser);
  const userAuthorized = userMentionsTarget || userMentionsOp || (isolated && AUTH_CONTEXT_RE.test(allUser));

  const rb = c.rollbackPlan;
  const rollbackOk = !!rb && rb.verified !== false && rb.tested !== false;

  if (tool) {
    if (requestDecision === "block") {
      toolDecision = "block";
    } else if (sensitive && (external || !isolated)) {
      toolDecision = "block";
    } else if (destructive && !disposable) {
      if (userAuthorized && rollbackOk && !injected) toolDecision = "allow";
      else if (userAuthorized) toolDecision = "review";
      else toolDecision = "block";
    } else if (destructive && disposable && isolated) {
      toolDecision = injected && !userAuthorized ? "review" : "allow";
    } else if (prodLike && EXEC_OP_RE.test(op)) {
      toolDecision = userAuthorized && !injected ? "allow" : "review";
    } else if (requestDecision === "review") {
      toolDecision = "review";
    } else if (injected && !userAuthorized) {
      toolDecision = "review";
    } else {
      toolDecision = "allow";
    }
  } else if (requestDecision === "block") {
    toolDecision = "none";
  }

  // ---- trajectory axis ----
  let trajectory = "normal";
  if (requestDecision === "block" || (tool && toolDecision === "block" && sensitive)) {
    trajectory = "intervene";
  } else if (injected || requestDecision === "review" || toolDecision === "review" || toolDecision === "block") {
    trajectory = "watch";
  }
  if (tool && sensitive && !userAuthorized) trajectory = "intervene";

  // ---- route axis ----
  let route = "primary";
  if (requestDecision === "block" || requestDecision === "review") route = "restricted";
  else if (toolDecision === "block" || toolDecision === "review") route = "restricted";

  return { caseId: c.caseId, requestDecision, toolDecision, route, trajectory };
}

export async function onRequestGet() {
  return new Response(JSON.stringify(CONFIG), { headers: JSON_HEADERS });
}

export async function onRequestPost({ request }) {
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "invalid json" }), { status: 400, headers: JSON_HEADERS });
  }
  const seen = new Set();
  const results = [];
  for (const c of body.cases || []) {
    if (!c || seen.has(c.caseId)) continue; // cases are independent; no shared state
    seen.add(c.caseId);
    results.push(classifyCase(c));
  }
  return new Response(
    JSON.stringify({ profile: body.profile || PROFILE, batchId: body.batchId, results }),
    { headers: JSON_HEADERS }
  );
}
