const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }
});

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/health") {
      return json({ ok: true, app: "Voxora", hosting: "Cloudflare Workers", databaseConfigured: Boolean(env.VOXORA_DB && env.VOXORA_DB.prepare) });
    }
    if (url.pathname.startsWith("/api/")) {
      if (!env.VOXORA_DB || !env.VOXORA_DB.prepare) {
        return json({ error: "Voxora's Cloudflare D1 database is not connected yet. Create the database and add its ID to wrangler.toml." }, 503);
      }
      if (url.pathname === "/api/communities" && request.method === "GET") {
        const result = await env.VOXORA_DB.prepare(
          "SELECT id, name, invite_code FROM communities ORDER BY created_at DESC LIMIT 50"
        ).all();
        return json({ communities: result.results || [] });
      }
      return json({ error: "This API endpoint is part of the next Voxora development milestone." }, 501);
    }
    return env.ASSETS.fetch(request);
  }
};
