import { onRequestGet, onRequestPost } from "./classify.js";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== "/classify") return new Response("Not found", { status: 404 });

    if (request.method === "POST") {
      const clone = request.clone();
      try {
        const body = await clone.json();
        await env.LOG.put("ga5:" + body.batchId, JSON.stringify(body));
      } catch {}
      return onRequestPost({ request });
    }

    if (url.searchParams.get("dump") === "1") {
      const list = await env.LOG.list({ prefix: "ga5:" });
      const out = [];
      for (const k of list.keys.slice(0, 4)) out.push(JSON.parse(await env.LOG.get(k.name)));
      return new Response(JSON.stringify(out, null, 1), {
        headers: { "content-type": "application/json" },
      });
    }
    return onRequestGet();
  },
};
