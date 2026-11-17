import { onRequestGet, onRequestPost } from "./classify.js";

export default {
  async fetch(request) {
    const { pathname } = new URL(request.url);
    if (pathname === "/classify") {
      if (request.method === "POST") return onRequestPost({ request });
      if (request.method === "GET") return onRequestGet();
      return new Response("Method not allowed", { status: 405 });
    }
    return new Response("Not found", { status: 404 });
  },
};
