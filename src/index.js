const HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store"
};
const COOKIE = "voxora_session";
const DAYS = 30;
const ITERATIONS = 210000;
const encoder = new TextEncoder();

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...HEADERS, ...extra } });
}
const fail = (message, status = 400) => json({ error: message }, status);
const bytes = n => crypto.getRandomValues(new Uint8Array(n));
const hex = a => Array.from(a, x => x.toString(16).padStart(2, "0")).join("");
function b64(a) {
  let s = "";
  for (const x of a) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function un64(s) {
  return Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), c => c.charCodeAt(0));
}
const uid = () => crypto.randomUUID();
async function digest(s) {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(s))));
}
async function passwordHash(password) {
  const salt = bytes(16);
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const result = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" }, key, 256);
  return "pbkdf2$" + ITERATIONS + "$" + b64(salt) + "$" + b64(new Uint8Array(result));
}
async function passwordMatches(password, stored) {
  try {
    const p = stored.split("$");
    if (p.length !== 4 || p[0] !== "pbkdf2") return false;
    const rounds = Number(p[1]);
    if (!Number.isInteger(rounds) || rounds < 100000 || rounds > 600000) return false;
    const expected = un64(p[3]);
    const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
    const actual = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", salt: un64(p[2]), iterations: rounds, hash: "SHA-256" }, key, expected.length * 8));
    if (actual.length !== expected.length) return false;
    let diff = 0;
    for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
    return diff === 0;
  } catch { return false; }
}
function cookie(request, value, age = DAYS * 86400) {
  const secure = new URL(request.url).protocol === "https:" ? "; Secure" : "";
  return COOKIE + "=" + value + "; HttpOnly; Path=/; SameSite=Lax; Max-Age=" + age + secure;
}
function readCookie(request) {
  for (const part of (request.headers.get("Cookie") || "").split(";")) {
    const i = part.indexOf("=");
    if (i >= 0 && part.slice(0, i).trim() === COOKIE) return part.slice(i + 1).trim();
  }
  return null;
}
async function session(db, request) {
  const token = readCookie(request);
  if (!token) return null;
  return db.prepare(
    "SELECT u.id, u.username, u.display_name, u.email, u.avatar_url FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=? AND s.expires_at>? LIMIT 1"
  ).bind(await digest(token), new Date().toISOString()).first();
}
async function newSession(db, userId, request) {
  const token = b64(bytes(32));
  await db.prepare("INSERT INTO sessions (id,user_id,expires_at) VALUES (?,?,?)")
    .bind(await digest(token), userId, new Date(Date.now() + DAYS * 86400000).toISOString()).run();
  return cookie(request, token);
}
async function body(request) {
  if (Number(request.headers.get("content-length") || 0) > 16000) return { error: "Request is too large." };
  try {
    const value = await request.json();
    return value && typeof value === "object" && !Array.isArray(value) ? value : { error: "Invalid request body." };
  } catch { return { error: "Please send valid JSON." }; }
}
const text = (v, n) => typeof v === "string" ? v.trim().slice(0, n) : "";
const originOK = (request, url) => {
  const origin = request.headers.get("Origin");
  if (!origin) return true;
  try { return new URL(origin).origin === url.origin; } catch { return false; }
};
const emailOK = value => value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
const usernameOK = value => /^[a-z0-9_]{3,24}$/.test(value);
const channelOK = value => /^[a-z0-9][a-z0-9_-]{0,31}$/.test(value);
async function member(db, communityId, userId) {
  return db.prepare("SELECT role FROM community_members WHERE community_id=? AND user_id=? LIMIT 1")
    .bind(communityId, userId).first();
}

async function api(request, env, url) {
  const db = env.VOXORA_DB;
  if (!db || typeof db.prepare !== "function") return fail("The Voxora database is not connected.", 503);

  if (url.pathname === "/api/auth/me" && request.method === "GET") {
    const user = await session(db, request);
    return user ? json({ user }) : fail("You are not signed in.", 401);
  }
  if (url.pathname === "/api/auth/logout" && request.method === "POST") {
    const token = readCookie(request);
    if (token) await db.prepare("DELETE FROM sessions WHERE id=?").bind(await digest(token)).run();
    return json({ ok: true }, 200, { "set-cookie": cookie(request, "", 0) });
  }
  if (url.pathname === "/api/auth/register" && request.method === "POST") {
    if (!originOK(request, url)) return fail("Request origin is not allowed.", 403);
    const b = await body(request);
    if (b.error) return fail(b.error);
    const username = text(b.username, 24).toLowerCase();
    const displayName = text(b.displayName, 32);
    const email = text(b.email, 254).toLowerCase();
    const password = typeof b.password === "string" ? b.password : "";
    if (!usernameOK(username)) return fail("Username must be 3–24 characters using letters, numbers, or underscores.");
    if (displayName.length < 2) return fail("Display name must be at least 2 characters.");
    if (!emailOK(email)) return fail("Enter a valid email address.");
    if (password.length < 8 || password.length > 128) return fail("Password must be 8–128 characters.");
    const id = uid();
    try {
      await db.prepare("INSERT INTO users (id,username,display_name,email,password_hash) VALUES (?,?,?,?,?)")
        .bind(id, username, displayName, email, await passwordHash(password)).run();
    } catch { return fail("That username or email is already registered.", 409); }
    const setCookie = await newSession(db, id, request);
    const user = await db.prepare("SELECT id,username,display_name,email,avatar_url FROM users WHERE id=?").bind(id).first();
    return json({ user }, 201, { "set-cookie": setCookie });
  }
  if (url.pathname === "/api/auth/login" && request.method === "POST") {
    if (!originOK(request, url)) return fail("Request origin is not allowed.", 403);
    const b = await body(request);
    if (b.error) return fail(b.error);
    const email = text(b.email, 254).toLowerCase();
    const password = typeof b.password === "string" ? b.password : "";
    if (!emailOK(email) || !password || password.length > 128) return fail("Email or password is incorrect.", 401);
    const row = await db.prepare("SELECT id,username,display_name,email,avatar_url,password_hash FROM users WHERE lower(email)=? LIMIT 1").bind(email).first();
    if (!row || !(await passwordMatches(password, row.password_hash))) return fail("Email or password is incorrect.", 401);
    const setCookie = await newSession(db, row.id, request);
    delete row.password_hash;
    return json({ user: row }, 200, { "set-cookie": setCookie });
  }

  const user = await session(db, request);
  if (!user) return fail("Your session has expired. Please sign in again.", 401);

  if (url.pathname === "/api/communities" && request.method === "GET") {
    const result = await db.prepare(
      "SELECT c.id,c.name,c.created_at,cm.role,CASE WHEN cm.role='owner' THEN c.invite_code ELSE NULL END AS invite_code FROM communities c JOIN community_members cm ON cm.community_id=c.id WHERE cm.user_id=? ORDER BY c.created_at ASC"
    ).bind(user.id).all();
    return json({ communities: result.results || [] });
  }
  if (url.pathname === "/api/communities" && request.method === "POST") {
    if (!originOK(request, url)) return fail("Request origin is not allowed.", 403);
    const b = await body(request);
    if (b.error) return fail(b.error);
    const name = text(b.name, 32);
    if (name.length < 2) return fail("Community name must be at least 2 characters.");
    const id = uid(), invite = hex(bytes(6)), channelId = uid();
    try {
      await db.batch([
        db.prepare("INSERT INTO communities (id,name,owner_id,invite_code) VALUES (?,?,?,?)").bind(id, name, user.id, invite),
        db.prepare("INSERT INTO community_members (community_id,user_id,role) VALUES (?,?,'owner')").bind(id, user.id),
        db.prepare("INSERT INTO channels (id,community_id,name,kind,position) VALUES (?,?,'general','text',0)").bind(channelId, id)
      ]);
    } catch { return fail("We couldn't create that community. Please try again.", 500); }
    return json({ community: { id, name, role: "owner", invite_code: invite }, channel: { id: channelId, name: "general", kind: "text", position: 0 } }, 201);
  }
  if (url.pathname === "/api/invites/join" && request.method === "POST") {
    if (!originOK(request, url)) return fail("Request origin is not allowed.", 403);
    const b = await body(request);
    if (b.error) return fail(b.error);
    const code = text(b.code, 32).toLowerCase();
    if (!/^[a-f0-9]{12}$/.test(code)) return fail("That invite code is invalid.");
    const community = await db.prepare("SELECT id,name FROM communities WHERE invite_code=? LIMIT 1").bind(code).first();
    if (!community) return fail("That invite link is invalid or expired.", 404);
    await db.prepare("INSERT OR IGNORE INTO community_members (community_id,user_id,role) VALUES (?,?,'member')").bind(community.id, user.id).run();
    return json({ community });
  }

  const match = url.pathname.match(/^\/api\/communities\/([a-f0-9-]+)(?:\/(channels|members|messages|invite))?$/i);
  if (!match) return fail("API route not found.", 404);
  const communityId = match[1], resource = match[2] || "";
  const membership = await member(db, communityId, user.id);
  if (!membership) return fail("You don't have access to this community.", 403);

  if (resource === "channels" && request.method === "GET") {
    const r = await db.prepare("SELECT id,name,kind,position FROM channels WHERE community_id=? ORDER BY position,name").bind(communityId).all();
    return json({ channels: r.results || [] });
  }
  if (resource === "channels" && request.method === "POST") {
    if (!originOK(request, url)) return fail("Request origin is not allowed.", 403);
    if (membership.role !== "owner" && membership.role !== "moderator") return fail("Only moderators can create channels.", 403);
    const b = await body(request);
    if (b.error) return fail(b.error);
    const name = text(b.name, 32).toLowerCase().replace(/\s+/g, "-");
    if (!channelOK(name)) return fail("Use 1–32 lowercase letters, numbers, hyphens, or underscores.");
    const exists = await db.prepare("SELECT id FROM channels WHERE community_id=? AND name=? LIMIT 1").bind(communityId, name).first();
    if (exists) return fail("That channel already exists.", 409);
    const pos = await db.prepare("SELECT COALESCE(MAX(position),-1)+1 AS n FROM channels WHERE community_id=?").bind(communityId).first();
    const id = uid();
    await db.prepare("INSERT INTO channels (id,community_id,name,kind,position) VALUES (?,?,?,'text',?)").bind(id, communityId, name, Number(pos.n)).run();
    return json({ channel: { id, name, kind: "text", position: Number(pos.n) } }, 201);
  }
  if (resource === "members" && request.method === "GET") {
    const r = await db.prepare(
      "SELECT u.id,u.username,u.display_name,u.avatar_url,cm.role,cm.joined_at FROM community_members cm JOIN users u ON u.id=cm.user_id WHERE cm.community_id=? ORDER BY CASE cm.role WHEN 'owner' THEN 0 WHEN 'moderator' THEN 1 ELSE 2 END,u.display_name COLLATE NOCASE"
    ).bind(communityId).all();
    return json({ members: r.results || [] });
  }
  if (resource === "invite" && request.method === "POST") {
    if (!originOK(request, url)) return fail("Request origin is not allowed.", 403);
    if (membership.role !== "owner") return fail("Only the owner can refresh this invite.", 403);
    const invite = hex(bytes(6));
    await db.prepare("UPDATE communities SET invite_code=? WHERE id=?").bind(invite, communityId).run();
    return json({ invite_code: invite });
  }
  if (resource === "messages" && request.method === "GET") {
    const channelId = text(url.searchParams.get("channelId"), 64);
    const channel = await db.prepare("SELECT id FROM channels WHERE id=? AND community_id=? LIMIT 1").bind(channelId, communityId).first();
    if (!channel) return fail("Choose a valid channel.", 404);
    const r = await db.prepare(
      "SELECT m.id,m.body,m.created_at,u.id AS author_id,u.username,u.display_name,u.avatar_url FROM messages m JOIN users u ON u.id=m.author_id WHERE m.channel_id=? ORDER BY m.created_at DESC,m.id DESC LIMIT 100"
    ).bind(channelId).all();
    return json({ messages: (r.results || []).reverse() });
  }
  if (resource === "messages" && request.method === "POST") {
    if (!originOK(request, url)) return fail("Request origin is not allowed.", 403);
    const b = await body(request);
    if (b.error) return fail(b.error);
    const channelId = text(b.channelId, 64);
    const message = typeof b.body === "string" ? b.body.trim() : "";
    if (!message) return fail("Write a message before sending.");
    if (message.length > 2000) return fail("Messages can be up to 2,000 characters.");
    const channel = await db.prepare("SELECT id FROM channels WHERE id=? AND community_id=? LIMIT 1").bind(channelId, communityId).first();
    if (!channel) return fail("Choose a valid channel.", 404);
    const id = uid();
    await db.prepare("INSERT INTO messages (id,channel_id,author_id,body) VALUES (?,?,?,?)").bind(id, channelId, user.id, message).run();
    const saved = await db.prepare(
      "SELECT m.id,m.body,m.created_at,u.id AS author_id,u.username,u.display_name,u.avatar_url FROM messages m JOIN users u ON u.id=m.author_id WHERE m.id=? LIMIT 1"
    ).bind(id).first();
    return json({ message: saved }, 201);
  }
  if (!resource && request.method === "GET") {
    const community = await db.prepare(
      "SELECT c.id,c.name,c.created_at,cm.role,CASE WHEN cm.role='owner' THEN c.invite_code ELSE NULL END AS invite_code FROM communities c JOIN community_members cm ON cm.community_id=c.id WHERE c.id=? AND cm.user_id=?"
    ).bind(communityId, user.id).first();
    return community ? json({ community }) : fail("Community not found.", 404);
  }
  return fail("API route not found.", 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/health" && request.method === "GET") {
      return json({ ok: true, app: "Voxora", databaseConfigured: Boolean(env.VOXORA_DB && typeof env.VOXORA_DB.prepare === "function") });
    }
    if (url.pathname.startsWith("/api/")) {
      try { return await api(request, env, url); }
      catch { return fail("Something went wrong. Please try again.", 500); }
    }
    if (!env.ASSETS || typeof env.ASSETS.fetch !== "function") return new Response("Voxora web assets are not configured.", { status: 503 });
    return env.ASSETS.fetch(request);
  }
};
