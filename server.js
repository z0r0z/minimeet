const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { verifyMessage } = require("ethers");

const app = express();
const server = http.createServer(app);

const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",").map(s => s.trim())
  : ["http://localhost:3001", "https://minimeet.cc"];

const io = new Server(server, {
  cors: { origin: ALLOWED_ORIGINS, methods: ["GET", "POST"] },
  pingTimeout: 30000,
  pingInterval: 10000,
  maxHttpBufferSize: 1e6,
});

// ─── Supabase / JSON fallback ───────────────────────────────────────────────

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
let supabase = null;

if (SUPABASE_URL && SUPABASE_KEY) {
  const { createClient } = require("@supabase/supabase-js");
  supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
  console.log("✅ Supabase connected");
} else {
  console.log("⚠️ No Supabase — falling back to local JSON");
}

// ─── X (Twitter) OAuth 2.0 ─────────────────────────────────────────────────

const X_CLIENT_ID = process.env.X_CLIENT_ID;
const X_CLIENT_SECRET = process.env.X_CLIENT_SECRET;
const X_CALLBACK_URL = process.env.X_CALLBACK_URL || "http://localhost:3001/auth/x/callback";

const oauthStates = new Map();  // state → { codeVerifier, createdAt }
const authTokens = new Map();   // token → { xId, username, displayName, avatar, expiresAt }

// Clean up expired states/tokens every 5 min
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of oauthStates) { if (now - v.createdAt > 600_000) oauthStates.delete(k); }
  for (const [k, v] of authTokens) { if (now > v.expiresAt) authTokens.delete(k); }
}, 300_000);

function base64url(buffer) {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function generatePKCE() {
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(crypto.createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

// Route: Start OAuth flow
app.get("/auth/x", (req, res) => {
  if (!X_CLIENT_ID) return res.status(500).send("X OAuth not configured");

  const state = base64url(crypto.randomBytes(16));
  const { verifier, challenge } = generatePKCE();

  oauthStates.set(state, { codeVerifier: verifier, createdAt: Date.now() });

  const params = new URLSearchParams({
    response_type: "code",
    client_id: X_CLIENT_ID,
    redirect_uri: X_CALLBACK_URL,
    scope: "users.read tweet.read offline.access",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });

  res.redirect(`https://twitter.com/i/oauth2/authorize?${params}`);
});

// Route: OAuth callback
app.get("/auth/x/callback", async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    console.warn("X OAuth error:", error);
    return res.redirect("/?auth_error=" + encodeURIComponent(error));
  }

  if (!code || !state || !oauthStates.has(state)) {
    return res.redirect("/?auth_error=invalid_state");
  }

  const { codeVerifier } = oauthStates.get(state);
  oauthStates.delete(state);

  try {
    // Exchange code for access token
    const tokenRes = await fetch("https://api.twitter.com/2/oauth2/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: "Basic " + Buffer.from(`${X_CLIENT_ID}:${X_CLIENT_SECRET}`).toString("base64"),
      },
      body: new URLSearchParams({
        code,
        grant_type: "authorization_code",
        redirect_uri: X_CALLBACK_URL,
        code_verifier: codeVerifier,
      }),
    });

    if (!tokenRes.ok) {
      const errBody = await tokenRes.text();
      console.error("Token exchange failed:", tokenRes.status, errBody);
      return res.redirect("/?auth_error=token_exchange_failed");
    }

    const tokenData = await tokenRes.json();
    const accessToken = tokenData.access_token;

    // Fetch user profile
    const userRes = await fetch("https://api.twitter.com/2/users/me?user.fields=profile_image_url,name,username", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!userRes.ok) {
      console.error("User fetch failed:", userRes.status);
      return res.redirect("/?auth_error=user_fetch_failed");
    }

    const userData = await userRes.json();
    const xUser = userData.data;

    // Get higher-res profile image (replace _normal with _400x400)
    const avatar = xUser.profile_image_url
      ? xUser.profile_image_url.replace("_normal", "_400x400")
      : null;

    // Store X profile in Supabase
    await dbSetXProfile(xUser.username, {
      xId: xUser.id,
      username: xUser.username,
      displayName: xUser.name,
      avatar,
    });

    // Create a temporary auth token the client can use
    const authToken = base64url(crypto.randomBytes(24));
    authTokens.set(authToken, {
      xId: xUser.id,
      username: xUser.username,
      displayName: xUser.name,
      avatar,
      expiresAt: Date.now() + 300_000, // 5 min to use it
    });

    console.log(`✅ X auth success: @${xUser.username} (${xUser.name})`);
    res.redirect(`/?auth_token=${authToken}`);
  } catch (e) {
    console.error("OAuth callback error:", e);
    res.redirect("/?auth_error=server_error");
  }
});

// API: Resolve auth token (called by client via fetch)
app.get("/auth/resolve/:token", (req, res) => {
  const profile = authTokens.get(req.params.token);
  if (!profile) return res.status(404).json({ error: "Token expired or invalid" });
  // Don't delete — let it expire naturally so page refreshes work briefly
  res.json({
    xId: profile.xId,
    username: profile.username,
    displayName: profile.displayName,
    avatar: profile.avatar,
  });
});

// ─── TURN credentials endpoint ───────────────────────────────────────────────

const TURN_SECRET = process.env.TURN_SECRET; // shared secret for HMAC-based TURN auth (Cloudflare/coturn)
const TURN_URLS = process.env.TURN_URLS ? process.env.TURN_URLS.split(",").map(s => s.trim()) : null;
const TURN_TTL = 86400; // 24h credential lifetime

app.get("/api/turn-credentials", (req, res) => {
  if (!TURN_SECRET || !TURN_URLS) {
    // Fallback: return nothing, client will use its hardcoded STUN-only
    return res.json({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
  }
  const username = Math.floor(Date.now() / 1000 + TURN_TTL) + ":" + crypto.randomBytes(4).toString("hex");
  const credential = crypto.createHmac("sha1", TURN_SECRET).update(username).digest("base64");
  res.json({
    iceServers: [
      { urls: "stun:stun.l.google.com:19302" },
      { urls: TURN_URLS, username, credential },
    ],
  });
});

// ─── Wallet signature verification ───────────────────────────────────────────

const walletNonces = new Map(); // address → { nonce, createdAt }

// Clean up expired nonces every 5 min
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of walletNonces) { if (now - v.createdAt > 300_000) walletNonces.delete(k); }
}, 300_000);

app.get("/auth/wallet/nonce", (req, res) => {
  const address = (req.query.address || "").toLowerCase().trim();
  if (!/^0x[0-9a-f]{40}$/.test(address)) return res.status(400).json({ error: "Invalid address" });
  const nonce = base64url(crypto.randomBytes(16));
  walletNonces.set(address, { nonce, createdAt: Date.now() });
  const message = `Sign in to minimeet.cc\n\nNonce: ${nonce}`;
  res.json({ message, nonce });
});

function verifyWalletSignature(address, signature, nonce) {
  const addr = address.toLowerCase();
  const stored = walletNonces.get(addr);
  if (!stored || stored.nonce !== nonce) return false;
  const message = `Sign in to minimeet.cc\n\nNonce: ${nonce}`;
  try {
    const recovered = verifyMessage(message, signature).toLowerCase();
    if (recovered === addr) {
      walletNonces.delete(addr); // single-use
      return true;
    }
  } catch (e) { console.warn("Wallet signature verification failed:", e.message); }
  return false;
}

// ─── X Profile persistence ──────────────────────────────────────────────────

async function dbGetXProfile(username) {
  const key = username.toLowerCase().trim();
  if (supabase) {
    try {
      const { data } = await supabase.from("x_profiles").select("*").eq("username", key).single();
      if (data) return data;
    } catch {}
    return null;
  }
  const stored = jsonGet("x_profiles", key);
  try { return stored ? JSON.parse(stored) : null; } catch { return null; }
}

async function dbSetXProfile(username, profile) {
  const key = username.toLowerCase().trim();
  if (supabase) {
    try {
      await supabase.from("x_profiles").upsert({
        username: key,
        x_id: profile.xId,
        display_name: profile.displayName,
        avatar: profile.avatar,
        updated_at: new Date().toISOString(),
      });
    } catch (e) { console.warn("X profile write error:", e.message); }
    return;
  }
  jsonSet("x_profiles", key, JSON.stringify(profile));
}

// ─── Avatar persistence ─────────────────────────────────────────────────────

const avatarCache = new Map();

async function dbGetAvatar(name) {
  const key = name.toLowerCase().trim();
  if (avatarCache.has(key)) return avatarCache.get(key);
  if (supabase) {
    try {
      const { data } = await supabase.from("avatars").select("data").eq("name", key).single();
      if (data) { avatarCache.set(key, data.data); return data.data; }
    } catch {}
    return null;
  }
  return jsonGet("avatars", key);
}

async function dbSetAvatar(name, dataUrl) {
  const key = name.toLowerCase().trim();
  if (dataUrl) avatarCache.set(key, dataUrl); else avatarCache.delete(key);
  if (supabase) {
    try {
      if (dataUrl) await supabase.from("avatars").upsert({ name: key, data: dataUrl, updated_at: new Date().toISOString() });
      else await supabase.from("avatars").delete().eq("name", key);
    } catch (e) { console.warn("Avatar write error:", e.message); }
    return;
  }
  jsonSet("avatars", key, dataUrl);
}

// ─── Call stats persistence ─────────────────────────────────────────────────

const statsCache = new Map();

function defaultStats() {
  return { received: 0, accepted: 0, declined: 0, missed: 0, streak: 0, best_streak: 0, totalMeets: 0, totalOnlineMs: 0 };
}

async function dbGetStats(name) {
  const key = name.toLowerCase().trim();
  if (statsCache.has(key)) return statsCache.get(key);
  if (supabase) {
    try {
      const { data } = await supabase.from("call_stats").select("*").eq("name", key).single();
      if (data) {
        const stats = { received: data.received||0, accepted: data.accepted||0, declined: data.declined||0, missed: data.missed||0, streak: data.streak||0, best_streak: data.best_streak||0, totalMeets: data.total_meets||0, totalOnlineMs: data.total_online_ms||0 };
        statsCache.set(key, stats);
        return stats;
      }
    } catch {}
    const fresh = defaultStats();
    statsCache.set(key, fresh);
    return fresh;
  }
  const stored = jsonGet("stats", key);
  let stats; try { stats = stored ? JSON.parse(stored) : defaultStats(); } catch { stats = defaultStats(); }
  statsCache.set(key, stats);
  return stats;
}

async function dbSetStats(name, stats) {
  const key = name.toLowerCase().trim();
  statsCache.set(key, stats);
  if (supabase) {
    try {
      await supabase.from("call_stats").upsert({ name: key, received: stats.received, accepted: stats.accepted, declined: stats.declined, missed: stats.missed, streak: stats.streak, best_streak: stats.best_streak, total_meets: stats.totalMeets, total_online_ms: stats.totalOnlineMs, updated_at: new Date().toISOString() });
    } catch (e) { console.warn("Stats write error:", e.message); }
    return;
  }
  jsonSet("stats", key, JSON.stringify(stats));
}

async function recordCallOutcome(calleeName, outcome) {
  const stats = await dbGetStats(calleeName);
  stats.received++;
  if (outcome === "accepted") { stats.accepted++; stats.totalMeets++; stats.streak++; if (stats.streak > stats.best_streak) stats.best_streak = stats.streak; }
  else if (outcome === "declined") { stats.declined++; stats.streak = 0; }
  else if (outcome === "missed") { stats.missed++; stats.streak = 0; }
  await dbSetStats(calleeName, stats);
  return stats;
}

// ─── Contacts (saved users) persistence ─────────────────────────────────────

const contactsCache = new Map(); // owner key → Set of contact names

async function dbGetContacts(ownerName) {
  const key = ownerName.toLowerCase().trim();
  if (contactsCache.has(key)) return [...contactsCache.get(key)];
  if (supabase) {
    try {
      const { data } = await supabase.from("contacts").select("contact_name").eq("owner", key);
      const names = (data || []).map(r => r.contact_name);
      contactsCache.set(key, new Set(names));
      return names;
    } catch (e) { console.warn("Contacts read error:", e.message); }
    contactsCache.set(key, new Set());
    return [];
  }
  const stored = jsonGet("contacts", key);
  let names; try { names = stored ? JSON.parse(stored) : []; } catch { names = []; }
  contactsCache.set(key, new Set(names));
  return names;
}

async function dbAddContact(ownerName, contactName) {
  const key = ownerName.toLowerCase().trim();
  const contact = contactName.toLowerCase().trim();
  if (!contactsCache.has(key)) await dbGetContacts(ownerName);
  contactsCache.get(key).add(contact);
  if (supabase) {
    try {
      await supabase.from("contacts").upsert({ owner: key, contact_name: contact, created_at: new Date().toISOString() });
    } catch (e) { console.warn("Contact add error:", e.message); }
    return;
  }
  jsonSet("contacts", key, JSON.stringify([...contactsCache.get(key)]));
}

async function dbRemoveContact(ownerName, contactName) {
  const key = ownerName.toLowerCase().trim();
  const contact = contactName.toLowerCase().trim();
  if (!contactsCache.has(key)) await dbGetContacts(ownerName);
  contactsCache.get(key).delete(contact);
  if (supabase) {
    try {
      await supabase.from("contacts").delete().eq("owner", key).eq("contact_name", contact);
    } catch (e) { console.warn("Contact remove error:", e.message); }
    return;
  }
  jsonSet("contacts", key, JSON.stringify([...contactsCache.get(key)]));
}

// ─── JSON file fallback ─────────────────────────────────────────────────────

const DATA_DIR = path.join(__dirname, "data");
const jsonStores = {};

function jsonGet(store, key) {
  const file = path.join(DATA_DIR, `${store}.json`);
  if (!jsonStores[store]) {
    try {
      if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
      if (fs.existsSync(file)) jsonStores[store] = JSON.parse(fs.readFileSync(file, "utf-8"));
      else jsonStores[store] = {};
    } catch { jsonStores[store] = {}; }
  }
  const v = jsonStores[store][key];
  return v !== undefined ? v : null;
}

function jsonSet(store, key, value) {
  if (!jsonStores[store]) jsonStores[store] = {};
  if (value !== null && value !== undefined) jsonStores[store][key] = value; else delete jsonStores[store][key];
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(path.join(DATA_DIR, `${store}.json`), JSON.stringify(jsonStores[store]), "utf-8");
  } catch (e) { console.warn(`JSON write error (${store}):`, e.message); }
}

// ─── Public chat persistence ─────────────────────────────────────────────────

async function dbSavePublicMsg(msg) {
  if (supabase) {
    try {
      await supabase.from("public_messages").insert({
        id: msg.id, name: msg.name, avatar: msg.avatar,
        x_username: msg.xUsername || null, wallet_address: msg.walletAddress || null,
        text: msg.text, created_at: new Date(msg.ts).toISOString(),
      });
    } catch (e) { console.warn("Public msg write error:", e.message); }
    return;
  }
  // JSON fallback: append to file
  const stored = jsonGet("public_messages", "_all");
  let msgs; try { msgs = stored ? JSON.parse(stored) : []; } catch { msgs = []; }
  msgs.push(msg);
  if (msgs.length > MAX_CHAT_HISTORY) msgs.splice(0, msgs.length - MAX_CHAT_HISTORY);
  jsonSet("public_messages", "_all", JSON.stringify(msgs));
}

async function dbLoadPublicMsgs(limit = 50) {
  if (supabase) {
    try {
      const { data } = await supabase.from("public_messages")
        .select("*").order("created_at", { ascending: false }).limit(limit);
      if (data) return data.reverse().map(d => ({
        id: d.id, name: d.name, avatar: d.avatar,
        xUsername: d.x_username || null, walletAddress: d.wallet_address || null,
        text: d.text, ts: new Date(d.created_at).getTime(),
      }));
    } catch (e) { console.warn("Public msg read error:", e.message); }
    return [];
  }
  const stored = jsonGet("public_messages", "_all");
  let msgs; try { msgs = stored ? JSON.parse(stored) : []; } catch { msgs = []; }
  return msgs.slice(-limit);
}

// ─── Last-call timestamps (per pair) ─────────────────────────────────────────

async function dbGetLastCall(nameA, nameB) {
  const pair = [nameA, nameB].map(n => n.toLowerCase().trim()).sort().join(":");
  if (supabase) {
    try {
      const { data } = await supabase.from("last_calls").select("called_at").eq("pair", pair).single();
      if (data) return new Date(data.called_at).getTime();
    } catch {}
    return 0;
  }
  const stored = jsonGet("last_calls", pair);
  return stored ? parseInt(stored, 10) : 0;
}

async function dbSetLastCall(nameA, nameB) {
  const pair = [nameA, nameB].map(n => n.toLowerCase().trim()).sort().join(":");
  const now = Date.now();
  if (supabase) {
    try {
      await supabase.from("last_calls").upsert({ pair, called_at: new Date(now).toISOString() });
    } catch (e) { console.warn("Last-call write error:", e.message); }
    return;
  }
  jsonSet("last_calls", pair, String(now));
}

// ─── User preferences persistence ────────────────────────────────────────────

async function dbGetPrefs(name) {
  const key = name.toLowerCase().trim();
  if (supabase) {
    try {
      const { data } = await supabase.from("user_prefs").select("*").eq("name", key).single();
      if (data) return { autoMeet: !!data.auto_reach, cooldownHours: data.auto_reach_cooldown_hours || 24 };
    } catch {}
    return { autoMeet: false, cooldownHours: 24 };
  }
  const stored = jsonGet("user_prefs", key);
  try { return stored ? JSON.parse(stored) : { autoMeet: false, cooldownHours: 24 }; } catch { return { autoMeet: false, cooldownHours: 24 }; }
}

async function dbSetPrefs(name, prefs) {
  const key = name.toLowerCase().trim();
  if (supabase) {
    try {
      await supabase.from("user_prefs").upsert({
        name: key,
        auto_reach: prefs.autoMeet,
        auto_reach_cooldown_hours: prefs.cooldownHours,
        updated_at: new Date().toISOString(),
      });
    } catch (e) { console.warn("Prefs write error:", e.message); }
    return;
  }
  jsonSet("user_prefs", key, JSON.stringify(prefs));
}

// ─── Session tokens (guest identity protection) ─────────────────────────────

const sessionTokens = new Map(); // lowercase name -> token hash

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

async function dbGetSessionToken(name) {
  const key = name.toLowerCase().trim();
  if (supabase) {
    try {
      const { data } = await supabase.from("session_tokens").select("token_hash").eq("name", key).single();
      if (data) return data.token_hash;
    } catch {}
    return null;
  }
  return jsonGet("session_tokens", key);
}

async function dbSetSessionToken(name, tokenHash) {
  const key = name.toLowerCase().trim();
  if (supabase) {
    try {
      await supabase.from("session_tokens").upsert({ name: key, token_hash: tokenHash, updated_at: new Date().toISOString() });
    } catch (e) { console.warn("Session token write error:", e.message); }
    return;
  }
  jsonSet("session_tokens", key, tokenHash);
}

// ─── Wallet address persistence ──────────────────────────────────────────────

async function dbGetWallet(name) {
  const key = name.toLowerCase().trim();
  if (supabase) {
    try {
      const { data } = await supabase.from("wallet_addresses").select("wallet_address").eq("name", key).single();
      if (data) return data.wallet_address;
    } catch {}
    return null;
  }
  return jsonGet("wallet_addresses", key);
}

async function dbSetWallet(name, walletAddress) {
  const key = name.toLowerCase().trim();
  if (supabase) {
    try {
      if (walletAddress) {
        await supabase.from("wallet_addresses").upsert({ name: key, wallet_address: walletAddress, updated_at: new Date().toISOString() });
      } else {
        await supabase.from("wallet_addresses").delete().eq("name", key);
      }
    } catch (e) { console.warn("Wallet write error:", e.message); }
    return;
  }
  jsonSet("wallet_addresses", key, walletAddress);
}

// ─── Rate limiting ───────────────────────────────────────────────────────────

const rateLimitBuckets = new Map(); // socketId -> { event -> { count, resetAt } }

function rateLimit(socket, event, maxPerWindow, windowMs = 10_000) {
  const sid = socket.id;
  if (!rateLimitBuckets.has(sid)) rateLimitBuckets.set(sid, {});
  const buckets = rateLimitBuckets.get(sid);
  const now = Date.now();
  if (!buckets[event] || now > buckets[event].resetAt) {
    buckets[event] = { count: 1, resetAt: now + windowMs };
    return true;
  }
  buckets[event].count++;
  if (buckets[event].count > maxPerWindow) return false;
  return true;
}

// Clean up rate limit data for disconnected sockets every 60s
setInterval(() => {
  const activeSockets = new Set(io.sockets.sockets.keys());
  for (const sid of rateLimitBuckets.keys()) {
    if (!activeSockets.has(sid)) rateLimitBuckets.delete(sid);
  }
}, 60_000);

const MAX_NAME_LENGTH = 30;
const MAX_AVATAR_BYTES = 200_000; // ~200KB for a 128x128 JPEG

// ─── State ──────────────────────────────────────────────────────────────────

const onlineUsers = new Map();
const activeCalls = new Map();
const activeStreams = new Map(); // streamId -> { streamerId, streamerName, streamerAvatar, streamerXUsername, title, startedAt, viewers: Set<userId> }
const takenNames = new Map();
const disconnectTimers = new Map();

const CALL_DURATION_MS = 60_000;
const RING_TIMEOUT_MS = 30_000;
const RECONNECT_GRACE_MS = 30_000;
const DEFAULT_COOLDOWN_HOURS = parseInt(process.env.AUTO_REACH_COOLDOWN_HOURS, 10) || 24;
const AUTO_REACH_CHECK_MS = 30_000; // check every 30s
const autoMeetPending = new Set(); // "nameA:nameB" pairs currently being auto-called
const MAX_CHAT_HISTORY = 100;
const publicChat = []; // rolling buffer of { id, userId, name, avatar, text, ts }
const streamChats = new Map(); // streamId -> [ messages ]

// ─── Helpers ────────────────────────────────────────────────────────────────

function broadcastUserList() {
  const users = [];
  for (const [userId, data] of onlineUsers) {
    if (!data.disconnectedAt) {
      // Check if user is streaming
      let streaming = null;
      for (const [streamId, s] of activeStreams) {
        if (s.streamerId === userId) {
          streaming = { streamId, title: s.title, viewerCount: s.viewers.size };
          break;
        }
      }
      // Check if user is in a call
      let inCallWith = null;
      for (const [, call] of activeCalls) {
        if (call.startedAt && (call.callerId === userId || call.calleeId === userId)) {
          const partnerId = call.callerId === userId ? call.calleeId : call.callerId;
          const partner = onlineUsers.get(partnerId);
          if (partner) inCallWith = { userId: partnerId, name: partner.name, avatar: partner.avatar || null };
          break;
        }
      }
      users.push({
        userId, name: data.name, status: data.status,
        avatar: data.avatar || null, stats: data.stats || null,
        xUsername: data.xUsername || null, walletAddress: data.walletAddress || null,
        customStatus: data.customStatus || null, autoMeet: data.autoMeet || false,
        streaming, inCallWith,
      });
    }
  }
  io.emit("user-list", users);
  io.emit("online-count", users.length);
}

function getSocketByUserId(userId) {
  const userData = onlineUsers.get(userId);
  if (!userData) return null;
  return io.sockets.sockets.get(userData.socketId) || null;
}

function cleanupCall(callId) {
  const call = activeCalls.get(callId);
  if (!call) return;
  clearTimeout(call.timerId);
  clearTimeout(call.ringTimerId);
  // Clear auto-meet pending flag
  const callerData = onlineUsers.get(call.callerId);
  const calleeData = onlineUsers.get(call.calleeId);
  if (callerData && calleeData) {
    const pairKey = [callerData.name, calleeData.name].map(n => n.toLowerCase().trim()).sort().join(":");
    autoMeetPending.delete(pairKey);
  }
  activeCalls.delete(callId);
}

function isNameTaken(name, excludeUserId = null) {
  const lower = name.toLowerCase().trim();
  const existingUserId = takenNames.get(lower);
  if (!existingUserId) return false;
  if (excludeUserId && existingUserId === excludeUserId) return false;
  if (!onlineUsers.has(existingUserId)) { takenNames.delete(lower); return false; }
  return true;
}

function isUserInCall(userId) {
  for (const [, call] of activeCalls) {
    if (call.callerId === userId || call.calleeId === userId) return true;
  }
  return false;
}

function isUserStreaming(userId) {
  for (const [, stream] of activeStreams) {
    if (stream.streamerId === userId || stream.viewers.has(userId)) return true;
  }
  return false;
}

function getUserStream(userId) {
  for (const [streamId, stream] of activeStreams) {
    if (stream.streamerId === userId) return { streamId, stream };
  }
  return null;
}

function cleanupStream(streamId) {
  const stream = activeStreams.get(streamId);
  if (!stream) return;
  for (const viewerId of stream.viewers) {
    const vs = getSocketByUserId(viewerId);
    if (vs) vs.emit("stream-ended", { streamId });
  }
  activeStreams.delete(streamId);
  streamChats.delete(streamId);
  broadcastUserList();
}

function broadcastStreamViewers(streamId) {
  const stream = activeStreams.get(streamId);
  if (!stream) return;
  const viewers = [];
  for (const vid of stream.viewers) {
    const vd = onlineUsers.get(vid);
    if (vd) viewers.push({ userId: vid, name: vd.name, avatar: vd.avatar || null });
  }
  // Send to streamer + all viewers
  const ss = getSocketByUserId(stream.streamerId);
  if (ss) ss.emit("stream-viewers", { streamId, viewers, viewerCount: viewers.length });
  for (const vid of stream.viewers) {
    const vs = getSocketByUserId(vid);
    if (vs) vs.emit("stream-viewers", { streamId, viewers, viewerCount: viewers.length });
  }
}

async function refreshUserStats(userId) {
  const userData = onlineUsers.get(userId);
  if (!userData) return;
  userData.stats = await dbGetStats(userData.name);
  broadcastUserList();
}

// ─── Socket.IO Events ──────────────────────────────────────────────────────

io.on("connection", (socket) => {

  socket.on("register", async ({ name, reconnectUserId, avatar, xUsername, walletAddress, walletSignature, walletNonce, sessionToken }) => {
    if (!name || typeof name !== "string") return;
    const trimmedName = name.trim().slice(0, MAX_NAME_LENGTH);
    if (!trimmedName) { socket.emit("register-error", { message: "Name cannot be empty" }); return; }
    const safeAvatar = (avatar && typeof avatar === "string" && avatar.length <= MAX_AVATAR_BYTES) ? avatar : null;
    let safeWallet = (walletAddress && typeof walletAddress === "string" && /^0x[0-9a-fA-F]{40}$/.test(walletAddress)) ? walletAddress.toLowerCase() : null;

    // Verify wallet signature if wallet is being used for first-time login (not reconnect)
    if (safeWallet && walletSignature && walletNonce) {
      if (!verifyWalletSignature(safeWallet, walletSignature, walletNonce)) {
        socket.emit("register-error", { message: "Wallet signature verification failed" });
        return;
      }
    } else if (safeWallet && !reconnectUserId && !sessionToken) {
      // First-time wallet login without signature — reject
      socket.emit("register-error", { message: "Wallet signature required" });
      return;
    }

    if (reconnectUserId && onlineUsers.has(reconnectUserId)) {
      const eu = onlineUsers.get(reconnectUserId);
      if (eu.name.toLowerCase() !== trimmedName.toLowerCase()) { socket.emit("register-error", { message: "Name mismatch on reconnect" }); return; }
      if (disconnectTimers.has(reconnectUserId)) { clearTimeout(disconnectTimers.get(reconnectUserId)); disconnectTimers.delete(reconnectUserId); }
      eu.socketId = socket.id; eu.disconnectedAt = null; eu.status = "online"; eu.connectedAt = Date.now();
      if (safeAvatar) { eu.avatar = safeAvatar; await dbSetAvatar(eu.name, safeAvatar); }
      if (safeWallet && !eu.walletAddress) { eu.walletAddress = safeWallet; await dbSetWallet(eu.name, safeWallet); }
      socket.userId = reconnectUserId;
      const resolvedAvatar = eu.avatar || await dbGetAvatar(eu.name);
      eu.avatar = resolvedAvatar;
      eu.stats = await dbGetStats(eu.name);
      const prefs = await dbGetPrefs(eu.name);
      eu.autoMeet = prefs.autoMeet;
      eu.cooldownHours = prefs.cooldownHours;
      socket.emit("registered", { userId: reconnectUserId, name: eu.name, reconnected: true, avatar: resolvedAvatar, stats: eu.stats, xUsername: eu.xUsername || null, walletAddress: eu.walletAddress || null, autoMeet: eu.autoMeet, cooldownHours: eu.cooldownHours });
      broadcastUserList();
      return;
    }

    if (isNameTaken(trimmedName)) {
      socket.emit("register-error", { message: `"${trimmedName}" is already taken. Try a different name.` });
      return;
    }

    // Wallet-authenticated: verify wallet owns the name
    if (safeWallet) {
      const existingWallet = await dbGetWallet(trimmedName);
      if (existingWallet && existingWallet !== safeWallet) {
        socket.emit("register-error", { message: `"${trimmedName}" is claimed by a different wallet.` });
        return;
      }
    }

    // Guest session token: if this name has a stored token, verify it
    // Skip for X-authenticated or wallet-authenticated users
    if (!xUsername && !safeWallet) {
      const storedHash = await dbGetSessionToken(trimmedName);
      if (storedHash) {
        if (!sessionToken || hashToken(sessionToken) !== storedHash) {
          socket.emit("register-error", { message: `"${trimmedName}" is claimed. Pick a different name or sign in with X.` });
          return;
        }
      }
    }

    const userId = uuidv4().slice(0, 8);
    socket.userId = userId;
    const storedAvatar = await dbGetAvatar(trimmedName);
    const resolvedAvatar = safeAvatar || storedAvatar || null;
    if (safeAvatar && safeAvatar !== storedAvatar) await dbSetAvatar(trimmedName, safeAvatar);
    const stats = await dbGetStats(trimmedName);
    const prefs = await dbGetPrefs(trimmedName);

    const storedWallet = safeWallet || await dbGetWallet(trimmedName);
    if (safeWallet && safeWallet !== storedWallet) await dbSetWallet(trimmedName, safeWallet);

    onlineUsers.set(userId, {
      socketId: socket.id, name: trimmedName, status: "online",
      avatar: resolvedAvatar, stats, disconnectedAt: null, connectedAt: Date.now(),
      xUsername: xUsername || null, walletAddress: storedWallet || null,
      autoMeet: prefs.autoMeet, cooldownHours: prefs.cooldownHours,
    });
    takenNames.set(trimmedName.toLowerCase(), userId);

    // Issue session token for guest users
    let newSessionToken = null;
    if (!xUsername) {
      newSessionToken = sessionToken || base64url(crypto.randomBytes(24));
      await dbSetSessionToken(trimmedName, hashToken(newSessionToken));
    }

    socket.emit("registered", { userId, name: trimmedName, reconnected: false, avatar: resolvedAvatar, stats, xUsername: xUsername || null, walletAddress: storedWallet || null, autoMeet: prefs.autoMeet, cooldownHours: prefs.cooldownHours, sessionToken: newSessionToken });
    broadcastUserList();
    console.log(`✅ ${trimmedName}${xUsername ? " (@" + xUsername + ")" : ""}${storedWallet ? " [" + storedWallet.slice(0,6) + "...]" : ""} registered as ${userId}`);
  });

  socket.on("update-avatar", async ({ avatar }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (avatar && (typeof avatar !== "string" || avatar.length > MAX_AVATAR_BYTES)) return;
    userData.avatar = avatar || null;
    await dbSetAvatar(userData.name, avatar);
    broadcastUserList();
  });

  socket.on("set-status", ({ status, customStatus }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    // Update presence status
    if (status === "online" || status === "idle") {
      userData.status = status;
    }
    // Update custom status text (like Discord)
    if (customStatus !== undefined) {
      userData.customStatus = (typeof customStatus === "string") ? customStatus.trim().slice(0, 50) : null;
    }
    broadcastUserList();
  });

  socket.on("link-wallet", async ({ walletAddress, walletSignature, walletNonce }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const safeWallet = (walletAddress && typeof walletAddress === "string" && /^0x[0-9a-fA-F]{40}$/.test(walletAddress)) ? walletAddress.toLowerCase() : null;
    if (!safeWallet) return;
    // Verify signature
    if (!walletSignature || !walletNonce || !verifyWalletSignature(safeWallet, walletSignature, walletNonce)) {
      socket.emit("wallet-link-error", { message: "Wallet signature verification failed" });
      return;
    }
    userData.walletAddress = safeWallet;
    await dbSetWallet(userData.name, safeWallet);
    socket.emit("wallet-linked", { walletAddress: safeWallet });
    broadcastUserList();
  });

  // ── Contacts management ───────────────────────────────────────────────
  socket.on("get-contacts", async () => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const contacts = await dbGetContacts(userData.name);
    socket.emit("contacts-list", contacts);
  });

  socket.on("add-contact", async ({ contactName }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    await dbAddContact(userData.name, contactName);
    const contacts = await dbGetContacts(userData.name);
    socket.emit("contacts-list", contacts);
  });

  socket.on("remove-contact", async ({ contactName }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    await dbRemoveContact(userData.name, contactName);
    const contacts = await dbGetContacts(userData.name);
    socket.emit("contacts-list", contacts);
  });

  // ── Auto-Meet toggle ──────────────────────────────────────────────────
  socket.on("set-auto-meet", async ({ enabled, cooldownHours }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    userData.autoMeet = !!enabled;
    if (cooldownHours !== undefined && cooldownHours >= 1 && cooldownHours <= 168) {
      userData.cooldownHours = cooldownHours;
    }
    await dbSetPrefs(userData.name, { autoMeet: userData.autoMeet, cooldownHours: userData.cooldownHours || DEFAULT_COOLDOWN_HOURS });
    broadcastUserList();
  });

  // ── Streaming ────────────────────────────────────────────────────────────
  socket.on("start-stream", ({ title }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (isUserInCall(userId) || isUserStreaming(userId)) { socket.emit("stream-error", { message: "You're already in a call or stream" }); return; }

    const streamId = uuidv4().slice(0, 12);
    activeStreams.set(streamId, {
      streamerId: userId, streamerName: userData.name,
      streamerAvatar: userData.avatar || null, streamerXUsername: userData.xUsername || null,
      title: title || `${userData.name}'s stream`, startedAt: Date.now(),
      viewers: new Set(),
    });
    socket.emit("stream-started", { streamId });
    broadcastUserList();
    console.log(`📺 ${userData.name} started streaming: ${title || userData.name + "'s stream"}`);
  });

  socket.on("end-stream", ({ streamId }) => {
    const userId = socket.userId; if (!userId) return;
    const stream = activeStreams.get(streamId);
    if (!stream || stream.streamerId !== userId) return;
    cleanupStream(streamId);
    console.log(`📺 ${stream.streamerName} ended stream`);
  });

  socket.on("join-stream", ({ streamId }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (isUserInCall(userId) || isUserStreaming(userId)) { socket.emit("stream-error", { message: "You're already in a call or stream" }); return; }

    const stream = activeStreams.get(streamId);
    if (!stream) { socket.emit("stream-error", { message: "Stream not found" }); return; }

    stream.viewers.add(userId);
    // Build viewer list with profiles
    const viewerProfiles = [];
    for (const vid of stream.viewers) {
      const vd = onlineUsers.get(vid);
      if (vd) viewerProfiles.push({ userId: vid, name: vd.name, avatar: vd.avatar || null });
    }

    socket.emit("stream-joined", {
      streamId, streamerName: stream.streamerName, streamerAvatar: stream.streamerAvatar,
      streamerUserId: stream.streamerId, title: stream.title,
      viewerCount: stream.viewers.size, viewers: viewerProfiles,
    });

    // Tell streamer about new viewer (so they create a PeerConnection)
    const ss = getSocketByUserId(stream.streamerId);
    if (ss) ss.emit("viewer-joined", { streamId, viewerId: userId, viewerName: userData.name, viewerAvatar: userData.avatar || null });

    // Broadcast updated viewer list to all stream participants
    broadcastStreamViewers(streamId);
    broadcastUserList();
  });

  socket.on("leave-stream", ({ streamId }) => {
    const userId = socket.userId; if (!userId) return;
    const stream = activeStreams.get(streamId);
    if (!stream) return;
    stream.viewers.delete(userId);
    const ss = getSocketByUserId(stream.streamerId);
    if (ss) ss.emit("viewer-left", { streamId, viewerId: userId });
    broadcastStreamViewers(streamId);
    broadcastUserList();
  });

  // Stream WebRTC signaling
  socket.on("stream-offer", ({ streamId, viewerId, sdp }) => {
    const stream = activeStreams.get(streamId); if (!stream) return;
    const vs = getSocketByUserId(viewerId);
    if (vs) vs.emit("stream-offer", { streamId, sdp });
  });

  socket.on("stream-answer", ({ streamId, sdp }) => {
    const userId = socket.userId;
    const stream = activeStreams.get(streamId); if (!stream) return;
    const ss = getSocketByUserId(stream.streamerId);
    if (ss) ss.emit("stream-answer", { streamId, viewerId: userId, sdp });
  });

  socket.on("stream-ice-candidate", ({ streamId, viewerId, candidate }) => {
    const userId = socket.userId;
    const stream = activeStreams.get(streamId); if (!stream) return;
    if (userId === stream.streamerId) {
      // Streamer -> viewer
      const vs = getSocketByUserId(viewerId);
      if (vs) vs.emit("stream-ice-candidate", { streamId, candidate });
    } else {
      // Viewer -> streamer
      const ss = getSocketByUserId(stream.streamerId);
      if (ss) ss.emit("stream-ice-candidate", { streamId, viewerId: userId, candidate });
    }
  });

  // ── Chat ─────────────────────────────────────────────────────────────────
  socket.on("chat-public", async ({ text }) => {
    if (!rateLimit(socket, "chat", 10, 10_000)) return;
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const trimmed = (text || "").trim().slice(0, 500);
    if (!trimmed) return;
    const msg = { id: uuidv4().slice(0, 10), userId, name: userData.name, avatar: userData.avatar || null, xUsername: userData.xUsername || null, walletAddress: userData.walletAddress || null, text: trimmed, ts: Date.now() };
    publicChat.push(msg);
    if (publicChat.length > MAX_CHAT_HISTORY) publicChat.shift();
    io.emit("chat-public", msg);
    dbSavePublicMsg(msg); // persist (non-blocking)
  });

  socket.on("chat-history", () => {
    socket.emit("chat-history", publicChat.slice(-50));
  });

  socket.on("chat-stream", ({ streamId, text }) => {
    if (!rateLimit(socket, "chat", 10, 10_000)) return;
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const stream = activeStreams.get(streamId); if (!stream) return;
    // Must be streamer or viewer
    if (stream.streamerId !== userId && !stream.viewers.has(userId)) return;
    const trimmed = (text || "").trim().slice(0, 500);
    if (!trimmed) return;
    const msg = { id: uuidv4().slice(0, 10), userId, name: userData.name, avatar: userData.avatar || null, xUsername: userData.xUsername || null, walletAddress: userData.walletAddress || null, text: trimmed, ts: Date.now() };
    if (!streamChats.has(streamId)) streamChats.set(streamId, []);
    const chat = streamChats.get(streamId);
    chat.push(msg);
    if (chat.length > MAX_CHAT_HISTORY) chat.shift();
    // Send to streamer + all viewers
    const ss = getSocketByUserId(stream.streamerId);
    if (ss) ss.emit("chat-stream", { streamId, ...msg });
    for (const vid of stream.viewers) {
      const vs = getSocketByUserId(vid);
      if (vs) vs.emit("chat-stream", { streamId, ...msg });
    }
  });

  socket.on("chat-stream-history", ({ streamId }) => {
    const chat = streamChats.get(streamId) || [];
    socket.emit("chat-stream-history", { streamId, messages: chat.slice(-50) });
  });

  // P2P direct messages (ephemeral — not stored)
  socket.on("chat-dm", ({ toUserId, text }) => {
    if (!rateLimit(socket, "chat", 10, 10_000)) return;
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const target = onlineUsers.get(toUserId); if (!target || target.disconnectedAt) return;
    const trimmed = (text || "").trim().slice(0, 500);
    if (!trimmed) return;
    const msg = { id: uuidv4().slice(0, 10), fromUserId: userId, fromName: userData.name, fromAvatar: userData.avatar || null, text: trimmed, ts: Date.now() };
    const ts = getSocketByUserId(toUserId);
    if (ts) ts.emit("chat-dm", msg);
    // Echo back to sender for display
    socket.emit("chat-dm-sent", { toUserId, toName: target.name, ...msg });
  });

  // Poke — lightweight nudge
  socket.on("poke", ({ toUserId }) => {
    if (!rateLimit(socket, "poke", 3, 30_000)) return; // 3 pokes per 30s
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const target = onlineUsers.get(toUserId); if (!target || target.disconnectedAt) return;
    const ts = getSocketByUserId(toUserId);
    if (ts) ts.emit("poke", { fromUserId: userId, fromName: userData.name, fromAvatar: userData.avatar || null });
  });

  socket.on("call-user", ({ calleeId }) => {
    if (!rateLimit(socket, "call-user", 3, 10_000)) return; // 3 calls per 10s
    const callerId = socket.userId; if (!callerId) return;
    const caller = onlineUsers.get(callerId); if (!caller) return;
    const callee = onlineUsers.get(calleeId);
    if (!callee || callee.disconnectedAt) { socket.emit("call-error", { message: "User is offline" }); return; }
    if (isUserInCall(calleeId) || isUserStreaming(calleeId)) { socket.emit("call-error", { message: `${callee.name} is busy` }); return; }
    if (isUserInCall(callerId) || isUserStreaming(callerId)) { socket.emit("call-error", { message: "You're already in a call or stream" }); return; }

    const callId = uuidv4().slice(0, 12);
    const ringTimerId = setTimeout(async () => {
      const call = activeCalls.get(callId);
      if (call && !call.startedAt) {
        await recordCallOutcome(callee.name, "missed");
        await refreshUserStats(calleeId);
        socket.emit("call-not-answered", { callId });
        const cs = getSocketByUserId(calleeId); if (cs) cs.emit("call-cancelled", { callId });
        cleanupCall(callId);
      }
    }, RING_TIMEOUT_MS);

    activeCalls.set(callId, { callerId, calleeId, startedAt: null, timerId: null, ringTimerId });
    const cs = getSocketByUserId(calleeId);
    if (cs) cs.emit("incoming-call", { callId, callerId, callerName: caller.name, callerAvatar: caller.avatar || null, callerXUsername: caller.xUsername || null, callerWalletAddress: caller.walletAddress || null });
    socket.emit("call-ringing", { callId, calleeId, calleeName: callee.name, calleeAvatar: callee.avatar || null });
  });

  socket.on("accept-call", async ({ callId }) => {
    const call = activeCalls.get(callId); if (!call) return;
    clearTimeout(call.ringTimerId); call.startedAt = Date.now();
    const callee = onlineUsers.get(call.calleeId);
    const caller = onlineUsers.get(call.callerId);
    if (callee) { await recordCallOutcome(callee.name, "accepted"); await refreshUserStats(call.calleeId); }
    // Also count for the caller
    if (caller) { const cs = await dbGetStats(caller.name); cs.totalMeets++; await dbSetStats(caller.name, cs); await refreshUserStats(call.callerId); }
    if (caller && callee) await dbSetLastCall(caller.name, callee.name);
    call.timerId = setTimeout(() => {
      const s1 = getSocketByUserId(call.callerId); const s2 = getSocketByUserId(call.calleeId);
      if (s1) s1.emit("call-timeout", { callId }); if (s2) s2.emit("call-timeout", { callId });
      cleanupCall(callId);
    }, CALL_DURATION_MS);
    const s1 = getSocketByUserId(call.callerId); if (s1) s1.emit("call-accepted", { callId });
    socket.emit("call-accepted", { callId });
  });

  socket.on("decline-call", async ({ callId }) => {
    const call = activeCalls.get(callId); if (!call) return;
    const callee = onlineUsers.get(call.calleeId);
    if (callee) { await recordCallOutcome(callee.name, "declined"); await refreshUserStats(call.calleeId); }
    const s = getSocketByUserId(call.callerId); if (s) s.emit("call-declined", { callId });
    cleanupCall(callId);
  });

  socket.on("end-call", ({ callId }) => {
    const call = activeCalls.get(callId); if (!call) return;
    const dur = call.startedAt ? Math.floor((Date.now() - call.startedAt) / 1000) : 0;
    const oid = call.callerId === socket.userId ? call.calleeId : call.callerId;
    const os = getSocketByUserId(oid); if (os) os.emit("call-ended", { callId, duration: dur });
    socket.emit("call-ended", { callId, duration: dur });
    cleanupCall(callId);
  });

  socket.on("webrtc-offer", ({ callId, sdp }) => { const c = activeCalls.get(callId); if (!c) return; const t = c.callerId === socket.userId ? c.calleeId : c.callerId; const s = getSocketByUserId(t); if (s) s.emit("webrtc-offer", { callId, sdp }); });
  socket.on("webrtc-answer", ({ callId, sdp }) => { const c = activeCalls.get(callId); if (!c) return; const t = c.callerId === socket.userId ? c.calleeId : c.callerId; const s = getSocketByUserId(t); if (s) s.emit("webrtc-answer", { callId, sdp }); });
  socket.on("webrtc-ice-candidate", ({ callId, candidate }) => { const c = activeCalls.get(callId); if (!c) return; const t = c.callerId === socket.userId ? c.calleeId : c.callerId; const s = getSocketByUserId(t); if (s) s.emit("webrtc-ice-candidate", { callId, candidate }); });

  // Video toggle relay
  socket.on("video-toggle", ({ callId, videoOff }) => { const c = activeCalls.get(callId); if (!c) return; const t = c.callerId === socket.userId ? c.calleeId : c.callerId; const s = getSocketByUserId(t); if (s) s.emit("video-toggle", { callId, videoOff }); });

  socket.on("disconnect", () => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;

    // Clean up streams immediately (no grace period for streams)
    const userStream = getUserStream(userId);
    if (userStream) cleanupStream(userStream.streamId);
    // Remove from any stream they're viewing
    for (const [streamId, stream] of activeStreams) {
      if (stream.viewers.has(userId)) {
        stream.viewers.delete(userId);
        const ss = getSocketByUserId(stream.streamerId);
        if (ss) ss.emit("viewer-left", { streamId, viewerId: userId });
        broadcastStreamViewers(streamId);
      }
    }

    userData.disconnectedAt = Date.now(); broadcastUserList();
    const timer = setTimeout(async () => {
      for (const [callId, call] of activeCalls) {
        if (call.callerId === userId || call.calleeId === userId) {
          const oid = call.callerId === userId ? call.calleeId : call.callerId;
          const os = getSocketByUserId(oid);
          if (os) os.emit("call-ended", { callId, duration: call.startedAt ? Math.floor((Date.now() - call.startedAt) / 1000) : 0 });
          cleanupCall(callId);
        }
      }
      // Flush accumulated online time
      if (userData.connectedAt) {
        const sessionMs = Date.now() - userData.connectedAt;
        const stats = await dbGetStats(userData.name);
        stats.totalOnlineMs = (stats.totalOnlineMs || 0) + sessionMs;
        await dbSetStats(userData.name, stats);
      }
      takenNames.delete(userData.name.toLowerCase());
      onlineUsers.delete(userId); disconnectTimers.delete(userId);
      broadcastUserList();
    }, RECONNECT_GRACE_MS);
    disconnectTimers.set(userId, timer);
  });
});

app.use(express.static(path.join(__dirname, "public")));

// ─── Auto-Meet: periodic matcher ───────────────────────────────────────────

async function areMutualContacts(nameA, nameB) {
  const contactsA = await dbGetContacts(nameA);
  const contactsB = await dbGetContacts(nameB);
  return contactsA.includes(nameB.toLowerCase().trim()) && contactsB.includes(nameA.toLowerCase().trim());
}

setInterval(async () => {
  // Collect online users with autoMeet enabled who are not in a call
  const candidates = [];
  for (const [userId, data] of onlineUsers) {
    if (data.autoMeet && !data.disconnectedAt && !isUserInCall(userId) && !isUserStreaming(userId)) {
      candidates.push({ userId, name: data.name, cooldownHours: data.cooldownHours || DEFAULT_COOLDOWN_HOURS });
    }
  }
  if (candidates.length < 2) return;

  // Check each pair
  const matched = new Set();
  for (let i = 0; i < candidates.length; i++) {
    if (matched.has(candidates[i].userId)) continue;
    for (let j = i + 1; j < candidates.length; j++) {
      if (matched.has(candidates[j].userId)) continue;

      const a = candidates[i], b = candidates[j];
      const pairKey = [a.name, b.name].map(n => n.toLowerCase().trim()).sort().join(":");
      if (autoMeetPending.has(pairKey)) continue;

      // Must be mutual contacts
      if (!(await areMutualContacts(a.name, b.name))) continue;

      // Check cooldown (use the shorter of the two users' cooldown preferences)
      const cooldownMs = Math.min(a.cooldownHours, b.cooldownHours) * 60 * 60 * 1000;
      const lastCall = await dbGetLastCall(a.name, b.name);
      if (Date.now() - lastCall < cooldownMs) continue;

      // Match found — initiate auto-call
      autoMeetPending.add(pairKey);
      matched.add(a.userId);
      matched.add(b.userId);

      // Caller is whichever comes first alphabetically (deterministic)
      const [caller, callee] = a.name.toLowerCase() < b.name.toLowerCase() ? [a, b] : [b, a];
      const callerData = onlineUsers.get(caller.userId);
      const calleeData = onlineUsers.get(callee.userId);
      if (!callerData || !calleeData) { autoMeetPending.delete(pairKey); continue; }

      const callId = uuidv4().slice(0, 12);
      const ringTimerId = setTimeout(async () => {
        const call = activeCalls.get(callId);
        if (call && !call.startedAt) {
          await recordCallOutcome(calleeData.name, "missed");
          await refreshUserStats(callee.userId);
          const s1 = getSocketByUserId(caller.userId); if (s1) s1.emit("call-not-answered", { callId });
          const s2 = getSocketByUserId(callee.userId); if (s2) s2.emit("call-cancelled", { callId });
          cleanupCall(callId);
        }
        autoMeetPending.delete(pairKey);
      }, RING_TIMEOUT_MS);

      activeCalls.set(callId, { callerId: caller.userId, calleeId: callee.userId, startedAt: null, timerId: null, ringTimerId });

      const s1 = getSocketByUserId(caller.userId);
      const s2 = getSocketByUserId(callee.userId);
      if (s1) s1.emit("auto-meet-call", { callId, remoteUserId: callee.userId, remoteName: calleeData.name, remoteAvatar: calleeData.avatar || null });
      if (s2) s2.emit("incoming-call", { callId, callerId: caller.userId, callerName: callerData.name, callerAvatar: callerData.avatar || null, callerXUsername: callerData.xUsername || null, callerWalletAddress: callerData.walletAddress || null, autoMeet: true });

      console.log(`🔄 Auto-Meet: ${caller.name} ↔ ${callee.name}`);
      break; // only one match per candidate per cycle
    }
  }
}, AUTO_REACH_CHECK_MS);

const PORT = process.env.PORT || 3001;
server.listen(PORT, async () => {
  // Load persisted public chat into memory
  const savedMsgs = await dbLoadPublicMsgs(MAX_CHAT_HISTORY);
  publicChat.push(...savedMsgs);
  console.log(`\n  📞 minimeet.cc on http://localhost:${PORT} | DB: ${supabase ? "Supabase" : "JSON"} | X OAuth: ${X_CLIENT_ID ? "✅" : "❌"} | Chat: ${savedMsgs.length} msgs loaded\n`);
});
