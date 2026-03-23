const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const ethers = require("ethers");
const { verifyMessage, computeAddress } = ethers;

const app = express();
const server = http.createServer(app);

const IS_PROD = process.env.NODE_ENV === "production";

const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(",").map(s => s.trim())
  : IS_PROD ? ["https://minimeet.cc"] : ["http://localhost:3001", "https://minimeet.cc"];

// ─── Security headers ────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  if (IS_PROD) res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  next();
});

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
const WALLET_DERIVATION_SECRET = (() => {
  if (process.env.WALLET_DERIVATION_SECRET) return process.env.WALLET_DERIVATION_SECRET;
  if (process.env.NODE_ENV === "production") throw new Error("WALLET_DERIVATION_SECRET is required in production");
  console.warn("⚠️  WALLET_DERIVATION_SECRET not set — X user wallets will change on restart!");
  return crypto.randomBytes(32).toString("hex");
})();
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
    // Also store avatar in the avatars table so dbGetAvatar finds it
    if (avatar) await dbSetAvatar(xUser.name, avatar);

    // Derive deterministic app wallet from X ID
    const derivedWallet = deriveWalletFromXId(xUser.id);
    // Store the derived wallet address in the profile
    const profile = await dbGetProfile(xUser.name.toLowerCase());
    if (!profile.appWalletAddress) {
      profile.appWalletAddress = derivedWallet.address;
      await dbSetProfile(xUser.name.toLowerCase(), profile);
    }

    // Create a temporary auth token the client can use
    const authToken = base64url(crypto.randomBytes(24));
    authTokens.set(authToken, {
      xId: xUser.id,
      username: xUser.username,
      displayName: xUser.name,
      avatar,
      appWalletAddress: derivedWallet.address,
      expiresAt: Date.now() + 300_000,
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
    appWalletAddress: profile.appWalletAddress || null,
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

// ─── Deterministic wallet derivation from X ID ──────────────────────────────

function deriveWalletFromXId(xId) {
  // HMAC-SHA256(server_secret, "minimeet-wallet:" + xId) → 32 bytes → derive address only
  const privateKeyBytes = crypto.createHmac("sha256", WALLET_DERIVATION_SECRET)
    .update("minimeet-wallet:" + xId).digest();
  const address = computeAddress("0x" + privateKeyBytes.toString("hex"));
  return { address: address.toLowerCase() };
}

// Endpoint: get the deterministic address for any X username (no auth needed — address is public)
app.get("/api/x-wallet/:username", async (req, res) => {
  const username = (req.params.username || "").toLowerCase().trim();
  if (!username) return res.status(400).json({ error: "Username required" });
  // Look up X ID from x_profiles
  const xProfile = await dbGetXProfile(username);
  if (xProfile?.xId || xProfile?.x_id) {
    const xId = xProfile.xId || xProfile.x_id;
    const { address } = deriveWalletFromXId(xId);
    return res.json({ username, address });
  }
  res.status(404).json({ error: "X user not found — they need to sign in first" });
});

// ─── Wallet signature verification ───────────────────────────────────────────

const walletNonces = new Map(); // address → { nonce, createdAt }

// Clean up expired nonces every 5 min
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of walletNonces) { if (now - v.createdAt > 300_000) walletNonces.delete(k); }
}, 300_000);

const nonceRateLimit = new Map(); // IP → { count, resetAt }
// Clean up stale rate-limit entries every 5 min
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of nonceRateLimit) { if (now > v.resetAt) nonceRateLimit.delete(k); }
}, 300_000);
app.get("/auth/wallet/nonce", (req, res) => {
  // Rate limit: max 10 nonce requests per IP per minute
  const ip = req.ip || req.connection.remoteAddress;
  const rl = nonceRateLimit.get(ip) || { count: 0, resetAt: Date.now() + 60000 };
  if (Date.now() > rl.resetAt) { rl.count = 0; rl.resetAt = Date.now() + 60000; }
  rl.count++;
  nonceRateLimit.set(ip, rl);
  if (rl.count > 10) return res.status(429).json({ error: "Too many requests" });
  // Evict oldest nonces to prevent memory exhaustion (not clear-all — avoids DoS)
  if (walletNonces.size > 10000) {
    const sorted = [...walletNonces.entries()].sort((a, b) => a[1].createdAt - b[1].createdAt);
    for (let i = 0; i < 2000; i++) walletNonces.delete(sorted[i][0]);
  }

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

// ─── Cache size limits ──────────────────────────────────────────────────────
const MAX_CACHE_SIZE = 5000;
function cacheSet(map, key, value) {
  if (map.size >= MAX_CACHE_SIZE) { const first = map.keys().next().value; map.delete(first); }
  map.set(key, value);
}

// Sanitizer for PostgREST filter interpolation.
// Strips characters that are PostgREST operators (,.()) and SQL wildcards (%_\)
// while preserving characters that can appear in usernames/wallet addresses.
function safeFilterKey(s) { return String(s).replace(/[,.()\[\]%_\\]/g, ""); }

// ─── Avatar persistence ─────────────────────────────────────────────────────

const avatarCache = new Map();

async function dbGetAvatar(name) {
  const key = name.toLowerCase().trim();
  if (avatarCache.has(key)) return avatarCache.get(key);
  if (supabase) {
    try {
      const { data } = await supabase.from("avatars").select("data").eq("name", key).single();
      if (data) { cacheSet(avatarCache,key, data.data); return data.data; }
    } catch {}
    return null;
  }
  return jsonGet("avatars", key);
}

async function dbSetAvatar(name, dataUrl) {
  const key = name.toLowerCase().trim();
  if (dataUrl) cacheSet(avatarCache,key, dataUrl); else avatarCache.delete(key);
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
  return { received: 0, accepted: 0, declined: 0, missed: 0, streak: 0, best_streak: 0, totalMeets: 0, totalOnlineMs: 0, creditSeconds: 0 };
}

async function dbGetStats(name) {
  const key = name.toLowerCase().trim();
  if (statsCache.has(key)) return statsCache.get(key);
  if (supabase) {
    try {
      const { data } = await supabase.from("call_stats").select("*").eq("name", key).single();
      if (data) {
        const stats = { received: data.received||0, accepted: data.accepted||0, declined: data.declined||0, missed: data.missed||0, streak: data.streak||0, best_streak: data.best_streak||0, totalMeets: data.total_meets||0, totalOnlineMs: data.total_online_ms||0, creditSeconds: data.credit_seconds||0 };
        cacheSet(statsCache,key, stats);
        return stats;
      }
    } catch {}
    const fresh = defaultStats();
    cacheSet(statsCache,key, fresh);
    return fresh;
  }
  const stored = jsonGet("stats", key);
  let stats; try { stats = stored ? JSON.parse(stored) : defaultStats(); } catch { stats = defaultStats(); }
  cacheSet(statsCache,key, stats);
  return stats;
}

async function dbSetStats(name, stats) {
  const key = name.toLowerCase().trim();
  cacheSet(statsCache,key, stats);
  if (supabase) {
    try {
      await supabase.from("call_stats").upsert({ name: key, received: stats.received, accepted: stats.accepted, declined: stats.declined, missed: stats.missed, streak: stats.streak, best_streak: stats.best_streak, total_meets: stats.totalMeets, total_online_ms: stats.totalOnlineMs, credit_seconds: stats.creditSeconds || 0, updated_at: new Date().toISOString() });
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
      cacheSet(contactsCache,key, new Set(names));
      return names;
    } catch (e) { console.warn("Contacts read error:", e.message); }
    cacheSet(contactsCache,key, new Set());
    return [];
  }
  const stored = jsonGet("contacts", key);
  let names; try { names = stored ? JSON.parse(stored) : []; } catch { names = []; }
  cacheSet(contactsCache,key, new Set(names));
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
      const row = { id: msg.id, name: msg.name, avatar: msg.avatar, text: msg.text, created_at: new Date(msg.ts).toISOString() };
      // Only include optional columns if they exist (avoids failing on older schemas)
      if (msg.xUsername) row.x_username = msg.xUsername;
      if (msg.walletAddress) row.wallet_address = msg.walletAddress;
      const { error } = await supabase.from("public_messages").insert(row);
      if (error) console.warn("Public msg write error:", error.message);
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

async function dbSaveReaction(msgId, reactions) {
  if (supabase) {
    try {
      await supabase.from("chat_reactions").upsert({
        msg_id: msgId,
        reactions: JSON.stringify(reactions),
        updated_at: new Date().toISOString(),
      });
    } catch (e) { console.warn("Reaction write error:", e.message); }
    return;
  }
  jsonSet("chat_reactions", msgId, JSON.stringify(reactions));
}

async function dbLoadReactions(msgIds) {
  if (!msgIds || msgIds.length === 0) return {};
  const result = {};
  if (supabase) {
    try {
      const { data } = await supabase.from("chat_reactions").select("msg_id, reactions").in("msg_id", msgIds);
      if (data) {
        for (const row of data) {
          try { result[row.msg_id] = JSON.parse(row.reactions); } catch {}
        }
      }
    } catch (e) { console.warn("Reaction read error:", e.message); }
    return result;
  }
  for (const id of msgIds) {
    const stored = jsonGet("chat_reactions", id);
    if (stored) { try { result[id] = JSON.parse(stored); } catch {} }
  }
  return result;
}

// ─── DM persistence ─────────────────────────────────────────────────────────

async function dbSaveDM(senderName, receiverName, msg) {
  const pair = [senderName, receiverName].map(n => n.toLowerCase().trim()).sort().join(":");
  if (supabase) {
    try {
      const row = { id: msg.id, pair, sender: senderName.toLowerCase().trim(), sender_name: msg.fromName, text: msg.text, created_at: new Date(msg.ts).toISOString() };
      if (msg.encrypted) row.encrypted = true;
      if (msg.image) row.image = msg.image;
      const { error } = await supabase.from("direct_messages").insert(row);
      if (error && msg.image) {
        // Retry without image in case the column doesn't exist yet
        delete row.image;
        await supabase.from("direct_messages").insert(row);
      }
    } catch (e) { console.warn("DM write error:", e.message); }
    return;
  }
  const stored = jsonGet("direct_messages", pair);
  let msgs; try { msgs = stored ? JSON.parse(stored) : []; } catch { msgs = []; }
  msgs.push({ id: msg.id, sender: senderName.toLowerCase().trim(), senderName: msg.fromName, text: msg.text, image: msg.image || null, encrypted: msg.encrypted || false, ts: msg.ts });
  if (msgs.length > 100) msgs.splice(0, msgs.length - 100);
  jsonSet("direct_messages", pair, JSON.stringify(msgs));
}

async function dbLoadDMs(nameA, nameB, limit = 50, before = null) {
  const pair = [nameA, nameB].map(n => n.toLowerCase().trim()).sort().join(":");
  if (supabase) {
    try {
      let query = supabase.from("direct_messages")
        .select("*").eq("pair", pair)
        .order("created_at", { ascending: false }).limit(limit);
      if (before) query = query.lt("created_at", new Date(before).toISOString());
      const { data } = await query;
      if (data) return data.reverse().map(d => ({
        id: d.id, sender: d.sender, senderName: d.sender_name, text: d.text, image: d.image || null, encrypted: d.encrypted || false, ts: new Date(d.created_at).getTime(),
      }));
    } catch (e) { console.warn("DM read error:", e.message); }
    return [];
  }
  const stored = jsonGet("direct_messages", pair);
  let msgs; try { msgs = stored ? JSON.parse(stored) : []; } catch { msgs = []; }
  if (before) msgs = msgs.filter(m => m.ts < before);
  return msgs.slice(-limit);
}

// ─── DM read cursors ─────────────────────────────────────────────────────────

const readCursorCache = new Map(); // "name:peer" -> timestamp

async function dbSetReadCursor(name, peerName, readAt) {
  const key = name + ":" + peerName;
  const prev = readCursorCache.get(key) || 0;
  if (readAt <= prev) return; // already up to date
  cacheSet(readCursorCache, key, readAt);
  if (supabase) {
    try {
      await supabase.from("dm_read_cursors").upsert({ name, peer_name: peerName, read_at: new Date(readAt).toISOString() });
    } catch (e) { console.warn("Read cursor write error:", e.message); }
    return;
  }
  jsonSet("dm_read_cursors", key, String(readAt));
}

async function dbGetReadCursor(name, peerName) {
  const key = name + ":" + peerName;
  if (readCursorCache.has(key)) return readCursorCache.get(key);
  if (supabase) {
    try {
      const { data } = await supabase.from("dm_read_cursors").select("read_at").eq("name", name).eq("peer_name", peerName).single();
      if (data) { const ts = new Date(data.read_at).getTime(); readCursorCache.set(key, ts); return ts; }
    } catch {}
    return 0;
  }
  const stored = jsonGet("dm_read_cursors", key);
  const ts = stored ? parseInt(stored, 10) : 0;
  cacheSet(readCursorCache, key, ts);
  return ts;
}

// ─── User profiles (bio + banner) ────────────────────────────────────────────

const profileCache = new Map();

async function dbGetProfile(name) {
  const key = name.toLowerCase().trim();
  if (profileCache.has(key)) return profileCache.get(key);
  if (supabase) {
    try {
      const { data } = await supabase.from("user_profiles").select("*").eq("name", key).single();
      if (data) { const p = { bio: data.bio || null, banner: data.banner || null, customStatus: data.custom_status || null, e2eKey: data.e2e_key || null, appWallet: data.app_wallet || null, appWalletAddress: data.app_wallet_address || null, callRate: data.call_rate || null }; cacheSet(profileCache,key, p); return p; }
    } catch {}
    return { bio: null, banner: null, customStatus: null, e2eKey: null, appWallet: null, appWalletAddress: null, callRate: null };
  }
  const stored = jsonGet("user_profiles", key);
  const defaultProfile = { bio: null, banner: null, customStatus: null, e2eKey: null, appWallet: null, appWalletAddress: null, callRate: null };
  let p; try { p = stored ? { ...defaultProfile, ...JSON.parse(stored) } : { ...defaultProfile }; } catch { p = { ...defaultProfile }; }
  cacheSet(profileCache,key, p);
  return p;
}

async function dbSetProfile(name, profile) {
  const key = name.toLowerCase().trim();
  cacheSet(profileCache,key, profile);
  if (supabase) {
    try {
      const row = { name: key, bio: profile.bio, banner: profile.banner, custom_status: profile.customStatus || null, updated_at: new Date().toISOString() };
      if (profile.appWallet !== undefined) row.app_wallet = profile.appWallet;
      if (profile.appWalletAddress !== undefined) row.app_wallet_address = profile.appWalletAddress;
      if (profile.e2eKey !== undefined) row.e2e_key = profile.e2eKey;
      if (profile.callRate !== undefined) row.call_rate = profile.callRate;
      await supabase.from("user_profiles").upsert(row);
    } catch (e) { console.warn("Profile write error:", e.message); }
    return;
  }
  jsonSet("user_profiles", key, JSON.stringify(profile));
}

// ─── Group chats ─────────────────────────────────────────────────────────────

async function dbCreateGroup(id, name, creator, avatar) {
  if (supabase) {
    try { await supabase.from("group_chats").insert({ id, name, creator, avatar: avatar || null, created_at: new Date().toISOString() }); } catch (e) { console.warn("Group create error:", e.message); }
    try { await supabase.from("group_members").insert({ group_id: id, user_name: creator, role: "admin", joined_at: new Date().toISOString() }); } catch (e) { console.warn("Group member add error:", e.message); }
    return;
  }
  const groups = jsonGet("group_chats", "_all");
  let list; try { list = groups ? JSON.parse(groups) : []; } catch { list = []; }
  list.push({ id, name, creator, createdAt: Date.now(), members: [{ userName: creator, role: "admin" }] });
  jsonSet("group_chats", "_all", JSON.stringify(list));
}

async function dbGetGroup(groupId) {
  if (supabase) {
    try {
      const { data } = await supabase.from("group_chats").select("*").eq("id", groupId).single();
      if (data) return { id: data.id, name: data.name, creator: data.creator, avatar: data.avatar || null, createdAt: new Date(data.created_at).getTime() };
    } catch {}
    return null;
  }
  const groups = jsonGet("group_chats", "_all");
  try { const list = groups ? JSON.parse(groups) : []; return list.find(g => g.id === groupId) || null; } catch { return null; }
}

async function dbGetGroupMembers(groupId) {
  if (supabase) {
    try {
      const { data } = await supabase.from("group_members").select("user_name, role").eq("group_id", groupId);
      return (data || []).map(d => ({ userName: d.user_name, role: d.role }));
    } catch {}
    return [];
  }
  const groups = jsonGet("group_chats", "_all");
  try { const list = groups ? JSON.parse(groups) : []; const g = list.find(g => g.id === groupId); return g ? g.members : []; } catch { return []; }
}

async function dbAddGroupMember(groupId, userName, role = "member") {
  if (supabase) {
    try { await supabase.from("group_members").upsert({ group_id: groupId, user_name: userName.toLowerCase().trim(), role, joined_at: new Date().toISOString() }); } catch (e) { console.warn("Group member add error:", e.message); }
    return;
  }
  const groups = jsonGet("group_chats", "_all");
  let list; try { list = groups ? JSON.parse(groups) : []; } catch { list = []; }
  const g = list.find(g => g.id === groupId);
  if (g) { if (!g.members.find(m => m.userName === userName.toLowerCase().trim())) g.members.push({ userName: userName.toLowerCase().trim(), role }); jsonSet("group_chats", "_all", JSON.stringify(list)); }
}

async function dbRemoveGroupMember(groupId, userName) {
  if (supabase) {
    try { await supabase.from("group_members").delete().eq("group_id", groupId).eq("user_name", userName.toLowerCase().trim()); } catch (e) { console.warn("Group member remove error:", e.message); }
    return;
  }
  const groups = jsonGet("group_chats", "_all");
  let list; try { list = groups ? JSON.parse(groups) : []; } catch { list = []; }
  const g = list.find(g => g.id === groupId);
  if (g) { g.members = g.members.filter(m => m.userName !== userName.toLowerCase().trim()); jsonSet("group_chats", "_all", JSON.stringify(list)); }
}

async function dbGetUserGroups(userName) {
  const key = userName.toLowerCase().trim();
  if (supabase) {
    try {
      const { data } = await supabase.from("group_members").select("group_id").eq("user_name", key);
      if (!data || data.length === 0) return [];
      const groupIds = data.map(d => d.group_id);
      const { data: groups } = await supabase.from("group_chats").select("*").in("id", groupIds);
      return (groups || []).map(g => ({ id: g.id, name: g.name, creator: g.creator, avatar: g.avatar || null, createdAt: new Date(g.created_at).getTime() }));
    } catch {}
    return [];
  }
  const groups = jsonGet("group_chats", "_all");
  try { const list = groups ? JSON.parse(groups) : []; return list.filter(g => g.members.some(m => m.userName === key)); } catch { return []; }
}

async function dbSaveGroupMsg(groupId, msg) {
  if (supabase) {
    try {
      const row = { id: msg.id, group_id: groupId, sender: msg.sender, sender_name: msg.senderName, text: msg.text, created_at: new Date(msg.ts).toISOString() };
      if (msg.image) row.image = msg.image;
      await supabase.from("group_messages").insert(row);
    } catch (e) { console.warn("Group msg write error:", e.message); }
    return;
  }
  const stored = jsonGet("group_messages", groupId);
  let msgs; try { msgs = stored ? JSON.parse(stored) : []; } catch { msgs = []; }
  msgs.push(msg);
  if (msgs.length > 200) msgs.splice(0, msgs.length - 200);
  jsonSet("group_messages", groupId, JSON.stringify(msgs));
}

async function dbLoadGroupMsgs(groupId, limit = 50, before = null) {
  if (supabase) {
    try {
      let query = supabase.from("group_messages").select("*").eq("group_id", groupId).order("created_at", { ascending: false }).limit(limit);
      if (before) query = query.lt("created_at", new Date(before).toISOString());
      const { data } = await query;
      if (data) return data.reverse().map(d => ({ id: d.id, sender: d.sender, senderName: d.sender_name, text: d.text, image: d.image || null, ts: new Date(d.created_at).getTime() }));
    } catch (e) { console.warn("Group msg read error:", e.message); }
    return [];
  }
  const stored = jsonGet("group_messages", groupId);
  let msgs; try { msgs = stored ? JSON.parse(stored) : []; } catch { msgs = []; }
  if (before) msgs = msgs.filter(m => m.ts < before);
  return msgs.slice(-limit);
}

async function dbDeleteGroup(groupId) {
  if (supabase) {
    try {
      await supabase.from("group_messages").delete().eq("group_id", groupId);
      await supabase.from("group_members").delete().eq("group_id", groupId);
      await supabase.from("group_chats").delete().eq("id", groupId);
    } catch (e) { console.warn("Group delete error:", e.message); }
    return;
  }
  const groups = jsonGet("group_chats", "_all");
  let list; try { list = groups ? JSON.parse(groups) : []; } catch { list = []; }
  jsonSet("group_chats", "_all", JSON.stringify(list.filter(g => g.id !== groupId)));
  jsonSet("group_messages", groupId, null);
}

async function dbGetGroupLastMsg(groupId) {
  if (supabase) {
    try {
      const { data } = await supabase.from("group_messages").select("text, sender_name, created_at").eq("group_id", groupId).order("created_at", { ascending: false }).limit(1);
      if (data && data[0]) return { text: data[0].text, senderName: data[0].sender_name, ts: new Date(data[0].created_at).getTime() };
    } catch {}
    return null;
  }
  const stored = jsonGet("group_messages", groupId);
  try { const msgs = stored ? JSON.parse(stored) : []; return msgs.length > 0 ? msgs[msgs.length - 1] : null; } catch { return null; }
}

// ─── Token-gated rooms ───────────────────────────────────────────────────────

const ERC20_ABI = ["function balanceOf(address) view returns (uint256)"];
const ERC721_ABI = ["function balanceOf(address) view returns (uint256)"];
const TOKEN_RPC = "https://1rpc.io/eth";

async function checkTokenBalance(tokenAddress, tokenType, walletAddress) {
  const RPCS = [TOKEN_RPC, "https://ethereum.publicnode.com", "https://eth.drpc.org"];
  for (const rpc of RPCS) {
    try {
      const provider = new ethers.JsonRpcProvider(rpc, 1, { staticNetwork: true });
      const abi = tokenType === "NFT" ? ERC721_ABI : ERC20_ABI;
      const contract = new ethers.Contract(tokenAddress, abi, provider);
      const balance = await contract.balanceOf(walletAddress);
      return balance;
    } catch (e) { console.warn(`Token balance check error (${rpc}):`, e.message); }
  }
  return null; // all RPCs failed — caller should handle as retry
}

async function dbCreateGatedRoom(id, name, creator, tokenAddress, tokenType, minBalance, avatar, creatorWallet) {
  const wallet = creatorWallet || "creator";
  if (supabase) {
    try {
      await supabase.from("gated_rooms").insert({ id, name, creator, token_address: tokenAddress, token_type: tokenType, min_balance: minBalance, avatar: avatar || null, created_at: new Date().toISOString() });
      await supabase.from("gated_room_members").insert({ room_id: id, user_name: creator, wallet_address: wallet, joined_at: new Date().toISOString() });
    } catch (e) { console.warn("Gated room create error:", e.message); }
    return;
  }
  const rooms = jsonGet("gated_rooms", "_all");
  let list; try { list = rooms ? JSON.parse(rooms) : []; } catch { list = []; }
  list.push({ id, name, creator, tokenAddress, tokenType, minBalance, avatar, createdAt: Date.now(), members: [{ userName: creator, walletAddress: wallet }] });
  jsonSet("gated_rooms", "_all", JSON.stringify(list));
}

async function dbGetGatedRoom(roomId) {
  if (supabase) {
    try {
      const { data } = await supabase.from("gated_rooms").select("*").eq("id", roomId).single();
      if (data) return { id: data.id, name: data.name, creator: data.creator, tokenAddress: data.token_address, tokenType: data.token_type, minBalance: data.min_balance, avatar: data.avatar || null, createdAt: new Date(data.created_at).getTime() };
    } catch {}
    return null;
  }
  const rooms = jsonGet("gated_rooms", "_all");
  try { const list = rooms ? JSON.parse(rooms) : []; return list.find(r => r.id === roomId) || null; } catch { return null; }
}

async function dbGetGatedRoomMembers(roomId) {
  if (supabase) {
    try {
      const { data } = await supabase.from("gated_room_members").select("user_name, wallet_address").eq("room_id", roomId);
      return (data || []).map(d => ({ userName: d.user_name, walletAddress: d.wallet_address }));
    } catch {}
    return [];
  }
  const rooms = jsonGet("gated_rooms", "_all");
  try { const list = rooms ? JSON.parse(rooms) : []; const r = list.find(r => r.id === roomId); return r ? r.members : []; } catch { return []; }
}

async function dbAddGatedRoomMember(roomId, userName, walletAddress) {
  if (supabase) {
    try { await supabase.from("gated_room_members").upsert({ room_id: roomId, user_name: userName.toLowerCase().trim(), wallet_address: walletAddress.toLowerCase(), joined_at: new Date().toISOString() }); } catch (e) { console.warn("Gated room member add error:", e.message); }
    return;
  }
  const rooms = jsonGet("gated_rooms", "_all");
  let list; try { list = rooms ? JSON.parse(rooms) : []; } catch { list = []; }
  const r = list.find(r => r.id === roomId);
  if (r) { if (!r.members.find(m => m.userName === userName.toLowerCase().trim())) r.members.push({ userName: userName.toLowerCase().trim(), walletAddress: walletAddress.toLowerCase() }); jsonSet("gated_rooms", "_all", JSON.stringify(list)); }
}

async function dbRemoveGatedRoomMember(roomId, userName) {
  if (supabase) {
    try { await supabase.from("gated_room_members").delete().eq("room_id", roomId).eq("user_name", userName.toLowerCase().trim()); } catch {}
    return;
  }
  const rooms = jsonGet("gated_rooms", "_all");
  let list; try { list = rooms ? JSON.parse(rooms) : []; } catch { list = []; }
  const r = list.find(r => r.id === roomId);
  if (r) { r.members = r.members.filter(m => m.userName !== userName.toLowerCase().trim()); jsonSet("gated_rooms", "_all", JSON.stringify(list)); }
}

async function dbGetUserGatedRooms(userName) {
  const key = userName.toLowerCase().trim();
  if (supabase) {
    try {
      const { data } = await supabase.from("gated_room_members").select("room_id").eq("user_name", key);
      if (!data || data.length === 0) return [];
      const roomIds = data.map(d => d.room_id);
      const { data: rooms } = await supabase.from("gated_rooms").select("*").in("id", roomIds);
      return (rooms || []).map(r => ({ id: r.id, name: r.name, creator: r.creator, tokenAddress: r.token_address, tokenType: r.token_type, minBalance: r.min_balance, avatar: r.avatar || null, createdAt: new Date(r.created_at).getTime() }));
    } catch {}
    return [];
  }
  const rooms = jsonGet("gated_rooms", "_all");
  try { const list = rooms ? JSON.parse(rooms) : []; return list.filter(r => r.members.some(m => m.userName === key)); } catch { return []; }
}

async function dbSaveGatedRoomMsg(roomId, msg) {
  if (supabase) {
    try {
      const row = { id: msg.id, room_id: roomId, sender: msg.sender, sender_name: msg.senderName, text: msg.text, created_at: new Date(msg.ts).toISOString() };
      if (msg.image) row.image = msg.image;
      await supabase.from("gated_room_messages").insert(row);
    } catch (e) { console.warn("Gated room msg write error:", e.message); }
    return;
  }
  const stored = jsonGet("gated_room_messages", roomId);
  let msgs; try { msgs = stored ? JSON.parse(stored) : []; } catch { msgs = []; }
  msgs.push(msg);
  if (msgs.length > 200) msgs.splice(0, msgs.length - 200);
  jsonSet("gated_room_messages", roomId, JSON.stringify(msgs));
}

async function dbLoadGatedRoomMsgs(roomId, limit = 50, before = null) {
  if (supabase) {
    try {
      let query = supabase.from("gated_room_messages").select("*").eq("room_id", roomId).order("created_at", { ascending: false }).limit(limit);
      if (before) query = query.lt("created_at", new Date(before).toISOString());
      const { data } = await query;
      if (data) return data.reverse().map(d => ({ id: d.id, sender: d.sender, senderName: d.sender_name, text: d.text, image: d.image || null, ts: new Date(d.created_at).getTime() }));
    } catch (e) { console.warn("Gated room msg read error:", e.message); }
    return [];
  }
  const stored = jsonGet("gated_room_messages", roomId);
  let msgs; try { msgs = stored ? JSON.parse(stored) : []; } catch { msgs = []; }
  if (before) msgs = msgs.filter(m => m.ts < before);
  return msgs.slice(-limit);
}

async function dbDeleteGatedRoom(roomId) {
  if (supabase) {
    try {
      await supabase.from("gated_room_messages").delete().eq("room_id", roomId);
      await supabase.from("gated_room_members").delete().eq("room_id", roomId);
      await supabase.from("gated_rooms").delete().eq("id", roomId);
    } catch (e) { console.warn("Gated room delete error:", e.message); }
    return;
  }
  const rooms = jsonGet("gated_rooms", "_all");
  let list; try { list = rooms ? JSON.parse(rooms) : []; } catch { list = []; }
  jsonSet("gated_rooms", "_all", JSON.stringify(list.filter(r => r.id !== roomId)));
  jsonSet("gated_room_messages", roomId, null);
}

async function dbGetGatedRoomLastMsg(roomId) {
  if (supabase) {
    try {
      const { data } = await supabase.from("gated_room_messages").select("text, sender_name, created_at").eq("room_id", roomId).order("created_at", { ascending: false }).limit(1);
      if (data && data[0]) return { text: data[0].text, senderName: data[0].sender_name, ts: new Date(data[0].created_at).getTime() };
    } catch {}
    return null;
  }
  const stored = jsonGet("gated_room_messages", roomId);
  try { const msgs = stored ? JSON.parse(stored) : []; return msgs.length > 0 ? msgs[msgs.length - 1] : null; } catch { return null; }
}

// ─── Posts ───────────────────────────────────────────────────────────────────

async function dbCreatePost(author, text, parentId = null, image = null) {
  const id = uuidv4().slice(0, 12);
  const key = author.toLowerCase().trim();
  const now = Date.now();
  let rootId = null;

  if (parentId) {
    const parent = await dbGetPost(parentId);
    if (parent) rootId = parent.rootId || parent.id;
  }

  const post = { id, author: key, text, parentId, rootId, image: image || null, likeCount: 0, replyCount: 0, createdAt: now };

  if (supabase) {
    try {
      const row = { id, author: key, text, parent_id: parentId, root_id: rootId, like_count: 0, reply_count: 0, created_at: new Date(now).toISOString() };
      if (image) row.image = image;
      await supabase.from("posts").insert(row);
      if (parentId) {
        try { await supabase.rpc("increment_post_reply_count", { pid: parentId }); } catch {
          const parentPost = await dbGetPost(parentId);
          if (parentPost) await supabase.from("posts").update({ reply_count: (parentPost.replyCount || 0) + 1 }).eq("id", parentId);
        }
      }
    } catch (e) { console.warn("Post create error:", e.message); }
  } else {
    const stored = jsonGet("posts", "_all");
    let posts; try { posts = stored ? JSON.parse(stored) : []; } catch { posts = []; }
    posts.push(post);
    jsonSet("posts", "_all", JSON.stringify(posts));
    if (parentId) {
      const parent = posts.find(p => p.id === parentId);
      if (parent) { parent.replyCount = (parent.replyCount || 0) + 1; jsonSet("posts", "_all", JSON.stringify(posts)); }
    }
  }
  return post;
}

async function dbGetPost(postId) {
  if (supabase) {
    try {
      const { data } = await supabase.from("posts").select("*").eq("id", postId).single();
      if (data) return { id: data.id, author: data.author, text: data.text, parentId: data.parent_id, rootId: data.root_id, image: data.image || null, likeCount: data.like_count || 0, replyCount: data.reply_count || 0, createdAt: new Date(data.created_at).getTime() };
    } catch {}
    return null;
  }
  const stored = jsonGet("posts", "_all");
  let posts; try { posts = stored ? JSON.parse(stored) : []; } catch { posts = []; }
  return posts.find(p => p.id === postId) || null;
}

async function dbGetUserPosts(author, limit = 20, offset = 0) {
  const key = author.toLowerCase().trim();
  if (supabase) {
    try {
      const { data, count } = await supabase.from("posts").select("*", { count: "exact" }).eq("author", key).is("parent_id", null).order("created_at", { ascending: false }).range(offset, offset + limit - 1);
      const posts = (data || []).map(d => ({ id: d.id, author: d.author, text: d.text, parentId: d.parent_id, rootId: d.root_id, image: d.image || null, likeCount: d.like_count || 0, replyCount: d.reply_count || 0, createdAt: new Date(d.created_at).getTime() }));
      return { posts, total: count || 0 };
    } catch (e) { console.warn("Posts read error:", e.message); }
    return { posts: [], total: 0 };
  }
  const stored = jsonGet("posts", "_all");
  let posts; try { posts = stored ? JSON.parse(stored) : []; } catch { posts = []; }
  const userPosts = posts.filter(p => p.author === key && !p.parentId).sort((a, b) => b.createdAt - a.createdAt);
  return { posts: userPosts.slice(offset, offset + limit), total: userPosts.length };
}

async function dbGetUserReplies(author, limit = 20, offset = 0) {
  const key = author.toLowerCase().trim();
  if (supabase) {
    try {
      const { data, count } = await supabase.from("posts").select("*", { count: "exact" }).eq("author", key).not("parent_id", "is", null).order("created_at", { ascending: false }).range(offset, offset + limit - 1);
      return { posts: (data || []).map(d => ({ id: d.id, author: d.author, text: d.text, parentId: d.parent_id, rootId: d.root_id, image: d.image || null, likeCount: d.like_count || 0, replyCount: d.reply_count || 0, createdAt: new Date(d.created_at).getTime() })), total: count || 0 };
    } catch (e) { console.warn("Replies read error:", e.message); }
    return { posts: [], total: 0 };
  }
  const stored = jsonGet("posts", "_all");
  let posts; try { posts = stored ? JSON.parse(stored) : []; } catch { posts = []; }
  const userReplies = posts.filter(p => p.author === key && p.parentId).sort((a, b) => b.createdAt - a.createdAt);
  return { posts: userReplies.slice(offset, offset + limit), total: userReplies.length };
}

async function dbGetThread(rootId) {
  if (supabase) {
    try {
      const safeId = rootId.replace(/[^a-zA-Z0-9_-]/g, "");
      const { data } = await supabase.from("posts").select("*").or(`id.eq.${safeId},root_id.eq.${safeId}`).order("created_at", { ascending: true });
      return (data || []).map(d => ({ id: d.id, author: d.author, text: d.text, parentId: d.parent_id, rootId: d.root_id, image: d.image || null, likeCount: d.like_count || 0, replyCount: d.reply_count || 0, createdAt: new Date(d.created_at).getTime() }));
    } catch (e) { console.warn("Thread read error:", e.message); }
    return [];
  }
  const stored = jsonGet("posts", "_all");
  let posts; try { posts = stored ? JSON.parse(stored) : []; } catch { posts = []; }
  return posts.filter(p => p.id === rootId || p.rootId === rootId).sort((a, b) => a.createdAt - b.createdAt);
}

async function dbDeletePost(postId, author) {
  const key = author.toLowerCase().trim();
  if (supabase) {
    try {
      const post = await dbGetPost(postId);
      if (!post || post.author !== key) return false;
      // Delete likes, child replies, and the post
      await supabase.from("post_likes").delete().eq("post_id", postId);
      await supabase.from("posts").delete().eq("root_id", postId); // delete replies
      await supabase.from("posts").delete().eq("id", postId);
      if (post.parentId) {
        try { await supabase.rpc("decrement_post_reply_count", { pid: post.parentId }); } catch {
          const parentPost = await dbGetPost(post.parentId);
          if (parentPost) await supabase.from("posts").update({ reply_count: Math.max(0, (parentPost.replyCount || 0) - 1) }).eq("id", post.parentId);
        }
      }
      await supabase.from("notifications").delete().eq("post_id", postId);
      return true;
    } catch (e) { console.warn("Post delete error:", e.message); return false; }
  }
  const stored = jsonGet("posts", "_all");
  let posts; try { posts = stored ? JSON.parse(stored) : []; } catch { posts = []; }
  const post = posts.find(p => p.id === postId);
  if (!post || post.author !== key) return false;
  const parentId = post.parentId;
  // Remove post and its replies
  const filtered = posts.filter(p => p.id !== postId && p.rootId !== postId);
  if (parentId) {
    const parent = filtered.find(p => p.id === parentId);
    if (parent) parent.replyCount = Math.max(0, (parent.replyCount || 0) - 1);
  }
  jsonSet("posts", "_all", JSON.stringify(filtered));
  // Clean likes
  const likesStored = jsonGet("post_likes", "_all");
  let likes; try { likes = likesStored ? JSON.parse(likesStored) : []; } catch { likes = []; }
  jsonSet("post_likes", "_all", JSON.stringify(likes.filter(l => l.postId !== postId)));
  return true;
}

async function dbToggleLike(postId, userName) {
  const user = userName.toLowerCase().trim();
  if (supabase) {
    try {
      const { data: existing } = await supabase.from("post_likes").select("post_id").eq("post_id", postId).eq("user_name", user).maybeSingle();
      if (existing) {
        await supabase.from("post_likes").delete().eq("post_id", postId).eq("user_name", user);
        try { await supabase.rpc("decrement_post_like_count", { pid: postId }); } catch {
          const post = await dbGetPost(postId);
          if (post) await supabase.from("posts").update({ like_count: Math.max(0, post.likeCount - 1) }).eq("id", postId);
        }
        return { liked: false };
      } else {
        await supabase.from("post_likes").insert({ post_id: postId, user_name: user, created_at: new Date().toISOString() });
        try { await supabase.rpc("increment_post_like_count", { pid: postId }); } catch {
          const post = await dbGetPost(postId);
          if (post) await supabase.from("posts").update({ like_count: post.likeCount + 1 }).eq("id", postId);
        }
        return { liked: true };
      }
    } catch (e) { console.warn("Like toggle error:", e.message); return { liked: false }; }
  }
  const stored = jsonGet("post_likes", "_all");
  let likes; try { likes = stored ? JSON.parse(stored) : []; } catch { likes = []; }
  const idx = likes.findIndex(l => l.postId === postId && l.userName === user);
  const postsStored = jsonGet("posts", "_all");
  let posts; try { posts = postsStored ? JSON.parse(postsStored) : []; } catch { posts = []; }
  const post = posts.find(p => p.id === postId);
  if (idx >= 0) {
    likes.splice(idx, 1);
    if (post) post.likeCount = Math.max(0, (post.likeCount || 0) - 1);
    jsonSet("post_likes", "_all", JSON.stringify(likes));
    jsonSet("posts", "_all", JSON.stringify(posts));
    return { liked: false };
  } else {
    likes.push({ postId, userName: user, createdAt: Date.now() });
    if (post) post.likeCount = (post.likeCount || 0) + 1;
    jsonSet("post_likes", "_all", JSON.stringify(likes));
    jsonSet("posts", "_all", JSON.stringify(posts));
    return { liked: true };
  }
}

async function dbGetPostLikes(postId) {
  if (supabase) {
    try {
      const { data } = await supabase.from("post_likes").select("user_name").eq("post_id", postId);
      return (data || []).map(d => d.user_name);
    } catch {}
    return [];
  }
  const stored = jsonGet("post_likes", "_all");
  let likes; try { likes = stored ? JSON.parse(stored) : []; } catch { likes = []; }
  return likes.filter(l => l.postId === postId).map(l => l.userName);
}

async function dbToggleRepost(postId, userName) {
  const user = userName.toLowerCase().trim();
  if (supabase) {
    try {
      const { data: existing } = await supabase.from("reposts").select("post_id").eq("post_id", postId).eq("user_name", user).maybeSingle();
      if (existing) {
        await supabase.from("reposts").delete().eq("post_id", postId).eq("user_name", user);
        return { reposted: false };
      } else {
        await supabase.from("reposts").insert({ post_id: postId, user_name: user, created_at: new Date().toISOString() });
        return { reposted: true };
      }
    } catch (e) { console.warn("Repost toggle error:", e.message); return { reposted: false }; }
  }
  const stored = jsonGet("reposts", "_all");
  let reposts; try { reposts = stored ? JSON.parse(stored) : []; } catch { reposts = []; }
  const idx = reposts.findIndex(r => r.postId === postId && r.userName === user);
  if (idx >= 0) {
    reposts.splice(idx, 1);
    jsonSet("reposts", "_all", JSON.stringify(reposts));
    return { reposted: false };
  } else {
    reposts.push({ postId, userName: user, createdAt: Date.now() });
    jsonSet("reposts", "_all", JSON.stringify(reposts));
    return { reposted: true };
  }
}

async function dbGetUserReposts(userName, limit = 20) {
  const user = userName.toLowerCase().trim();
  if (supabase) {
    try {
      const { data } = await supabase.from("reposts").select("post_id, created_at").eq("user_name", user).order("created_at", { ascending: false }).limit(limit);
      if (!data || data.length === 0) return [];
      const postIds = data.map(d => d.post_id);
      const repostTimes = {};
      data.forEach(d => { repostTimes[d.post_id] = new Date(d.created_at).getTime(); });
      const { data: posts } = await supabase.from("posts").select("*").in("id", postIds);
      return (posts || []).map(d => ({
        id: d.id, author: d.author, text: d.text, parentId: d.parent_id, rootId: d.root_id,
        image: d.image || null, likeCount: d.like_count || 0, replyCount: d.reply_count || 0,
        createdAt: new Date(d.created_at).getTime(), repostedAt: repostTimes[d.id] || 0, repostedBy: user
      })).sort((a, b) => b.repostedAt - a.repostedAt);
    } catch (e) { console.warn("Get reposts error:", e.message); }
    return [];
  }
  const stored = jsonGet("reposts", "_all");
  let reposts; try { reposts = stored ? JSON.parse(stored) : []; } catch { reposts = []; }
  const userReposts = reposts.filter(r => r.userName === user).sort((a, b) => b.createdAt - a.createdAt).slice(0, limit);
  const postsStored = jsonGet("posts", "_all");
  let posts; try { posts = postsStored ? JSON.parse(postsStored) : []; } catch { posts = []; }
  return userReposts.map(r => {
    const p = posts.find(pp => pp.id === r.postId);
    if (!p) return null;
    return { ...p, repostedAt: r.createdAt, repostedBy: user };
  }).filter(Boolean);
}

async function dbGetPostReposters(postId) {
  if (supabase) {
    try {
      const { data } = await supabase.from("reposts").select("user_name").eq("post_id", postId);
      return (data || []).map(d => d.user_name);
    } catch {}
    return [];
  }
  const stored = jsonGet("reposts", "_all");
  let reposts; try { reposts = stored ? JSON.parse(stored) : []; } catch { reposts = []; }
  return reposts.filter(r => r.postId === postId).map(r => r.userName);
}

async function dbGetGlobalFeed(limit = 30) {
  if (supabase) {
    try {
      const { data } = await supabase.from("posts").select("*").is("parent_id", null).order("created_at", { ascending: false }).limit(limit);
      return (data || []).map(d => ({ id: d.id, author: d.author, text: d.text, parentId: d.parent_id, rootId: d.root_id, image: d.image || null, likeCount: d.like_count || 0, replyCount: d.reply_count || 0, createdAt: new Date(d.created_at).getTime() }));
    } catch (e) { console.warn("Global feed error:", e.message); }
    return [];
  }
  const stored = jsonGet("posts", "_all");
  let posts; try { posts = stored ? JSON.parse(stored) : []; } catch { posts = []; }
  return posts.filter(p => !p.parentId).sort((a, b) => b.createdAt - a.createdAt).slice(0, limit);
}

// ─── Notifications ──────────────────────────────────────────────────────────

async function dbCreateNotification(recipient, type, fromUser, postId, preview) {
  const id = uuidv4().slice(0, 12);
  const key = recipient.toLowerCase().trim();
  // Don't notify yourself
  if (key === fromUser.toLowerCase().trim()) return null;
  const notif = { id, recipient: key, type, fromUser: fromUser.toLowerCase().trim(), postId, preview: (preview || "").slice(0, 80), read: false, createdAt: Date.now() };
  if (supabase) {
    try {
      await supabase.from("notifications").insert({ id, recipient: key, type, from_user: notif.fromUser, post_id: postId, preview: notif.preview, read: false, created_at: new Date().toISOString() });
    } catch (e) { console.warn("Notification write error:", e.message); }
  } else {
    const stored = jsonGet("notifications", key);
    let notifs; try { notifs = stored ? JSON.parse(stored) : []; } catch { notifs = []; }
    notifs.push(notif);
    if (notifs.length > 200) notifs.splice(0, notifs.length - 200);
    jsonSet("notifications", key, JSON.stringify(notifs));
  }
  return notif;
}

async function dbGetNotifications(name, limit = 50) {
  const key = name.toLowerCase().trim();
  if (supabase) {
    try {
      const { data } = await supabase.from("notifications").select("*").eq("recipient", key).order("created_at", { ascending: false }).limit(limit);
      return (data || []).map(d => ({ id: d.id, type: d.type, fromUser: d.from_user, postId: d.post_id, preview: d.preview, read: d.read, createdAt: new Date(d.created_at).getTime() }));
    } catch (e) { console.warn("Notification read error:", e.message); }
    return [];
  }
  const stored = jsonGet("notifications", key);
  let notifs; try { notifs = stored ? JSON.parse(stored) : []; } catch { notifs = []; }
  return notifs.slice(-limit).reverse();
}

async function dbMarkNotificationsRead(name) {
  const key = name.toLowerCase().trim();
  if (supabase) {
    try { await supabase.from("notifications").update({ read: true }).eq("recipient", key).eq("read", false); } catch {}
    return;
  }
  const stored = jsonGet("notifications", key);
  let notifs; try { notifs = stored ? JSON.parse(stored) : []; } catch { notifs = []; }
  notifs.forEach(n => n.read = true);
  jsonSet("notifications", key, JSON.stringify(notifs));
}

async function dbGetUnreadCount(name) {
  const key = name.toLowerCase().trim();
  if (supabase) {
    try {
      const { count } = await supabase.from("notifications").select("id", { count: "exact", head: true }).eq("recipient", key).eq("read", false);
      return count || 0;
    } catch {}
    return 0;
  }
  const stored = jsonGet("notifications", key);
  let notifs; try { notifs = stored ? JSON.parse(stored) : []; } catch { notifs = []; }
  return notifs.filter(n => !n.read).length;
}

// Helper: send real-time notification if user is online
function emitNotification(recipientName, notif) {
  if (!notif) return;
  for (const [userId, data] of onlineUsers) {
    if (data.name.toLowerCase() === recipientName.toLowerCase() && !data.disconnectedAt) {
      const s = getSocketByUserId(userId);
      if (s) s.emit("new-notification", notif);
      break;
    }
  }
}

// ─── E2E encryption public keys ──────────────────────────────────────────────

async function dbSetPublicKey(name, publicKey) {
  const key = name.toLowerCase().trim();
  const keyStr = typeof publicKey === "string" ? publicKey : JSON.stringify(publicKey);
  if (supabase) {
    try {
      // Use upsert to handle users not yet in directory
      await supabase.from("user_directory").upsert({ name: key, display_name: name, public_key: keyStr, last_seen: new Date().toISOString() }, { onConflict: "name" });
    } catch (e) { console.warn("PubKey write error:", e.message); }
    return;
  }
  jsonSet("public_keys", key, keyStr);
}

async function dbGetPublicKey(name) {
  const key = name.toLowerCase().trim();
  if (supabase) {
    try {
      const { data } = await supabase.from("user_directory").select("public_key").eq("name", key).single();
      if (data?.public_key) { try { return JSON.parse(data.public_key); } catch { return data.public_key; } }
    } catch {}
    return null;
  }
  const stored = jsonGet("public_keys", key);
  if (stored) { try { return JSON.parse(stored); } catch { return stored; } }
  return null;
}

// ─── Wallet inbox claiming ───────────────────────────────────────────────────

async function claimWalletInbox(walletAddress, userName, socket) {
  const addr = walletAddress.toLowerCase();
  const name = userName.toLowerCase().trim();
  if (addr === name) return; // already using address as name

  if (supabase) {
    try {
      // Find DM pairs that used the raw wallet address
      const { data: dms } = await supabase.from("direct_messages").select("id, pair, sender, sender_name, text, encrypted, created_at")
        .like("pair", `%${safeFilterKey(addr)}%`).order("created_at", { ascending: true });
      if (dms && dms.length > 0) {
        let claimed = 0;
        for (const dm of dms) {
          // Rewrite pair: replace wallet address with username
          const newPair = dm.pair.replace(addr, name);
          if (newPair !== dm.pair) {
            await supabase.from("direct_messages").update({ pair: newPair }).eq("id", dm.id);
            claimed++;
          }
        }
        // Also migrate notifications
        await supabase.from("notifications").update({ recipient: name }).eq("recipient", addr);
        if (claimed > 0) {
          socket.emit("wallet-inbox-claimed", { count: claimed, walletAddress: addr });
          console.log(`📬 ${userName} claimed ${claimed} messages sent to ${addr.slice(0,6)}...`);
        }
      }
    } catch (e) { console.warn("Wallet inbox claim error:", e.message); }
  } else {
    // JSON fallback: scan all DM pairs
    const store = jsonStores["direct_messages"] || {};
    let claimed = 0;
    const keysToRename = [];
    for (const [pair, val] of Object.entries(store)) {
      if (pair.includes(addr)) {
        const newPair = pair.replace(addr, name);
        keysToRename.push([pair, newPair, val]);
      }
    }
    for (const [oldPair, newPair, val] of keysToRename) {
      delete store[oldPair];
      // Merge with any existing DMs under the new pair
      const existing = store[newPair];
      if (existing) {
        try {
          const oldMsgs = JSON.parse(val);
          const existMsgs = JSON.parse(existing);
          store[newPair] = JSON.stringify([...existMsgs, ...oldMsgs].sort((a, b) => a.ts - b.ts));
        } catch { store[newPair] = val; }
      } else {
        store[newPair] = val;
      }
      claimed++;
    }
    if (claimed > 0) {
      jsonSet("direct_messages", "_all", JSON.stringify(store));
      socket.emit("wallet-inbox-claimed", { count: claimed, walletAddress: addr });
      console.log(`📬 ${userName} claimed ${claimed} DM threads sent to ${addr.slice(0,6)}...`);
    }
  }
}

// ─── Pair meeting history ────────────────────────────────────────────────────

async function dbRecordPairMeeting(nameA, nameB, earnedSeconds = 30) {
  const pair = [nameA, nameB].map(n => n.toLowerCase().trim()).sort().join(":");
  if (supabase) {
    try {
      const { data } = await supabase.from("pair_meetings").select("meet_count, credit_seconds").eq("pair", pair).single();
      if (data) {
        await supabase.from("pair_meetings").update({ meet_count: data.meet_count + 1, credit_seconds: (data.credit_seconds || 0) + earnedSeconds, last_met: new Date().toISOString() }).eq("pair", pair);
      } else {
        await supabase.from("pair_meetings").insert({ pair, meet_count: 1, credit_seconds: earnedSeconds, last_met: new Date().toISOString() });
      }
    } catch (e) { console.warn("Pair meeting record error:", e.message); }
    return;
  }
  const stored = jsonGet("pair_meetings", pair);
  let pm; try { pm = stored ? JSON.parse(stored) : { meetCount: 0, creditSeconds: 0 }; } catch { pm = { meetCount: 0, creditSeconds: 0 }; }
  pm.meetCount++; pm.creditSeconds += earnedSeconds; pm.lastMet = Date.now();
  jsonSet("pair_meetings", pair, JSON.stringify(pm));
}

async function dbSpendPairCredit(nameA, nameB, seconds) {
  const pair = [nameA, nameB].map(n => n.toLowerCase().trim()).sort().join(":");
  if (supabase) {
    try {
      const { data } = await supabase.from("pair_meetings").select("credit_seconds").eq("pair", pair).single();
      if (!data || (data.credit_seconds || 0) < seconds) return false;
      await supabase.from("pair_meetings").update({ credit_seconds: data.credit_seconds - seconds }).eq("pair", pair);
      return true;
    } catch { return false; }
  }
  const stored = jsonGet("pair_meetings", pair);
  let pm; try { pm = stored ? JSON.parse(stored) : { meetCount: 0, creditSeconds: 0 }; } catch { return false; }
  if ((pm.creditSeconds || 0) < seconds) return false;
  pm.creditSeconds -= seconds;
  jsonSet("pair_meetings", pair, JSON.stringify(pm));
  return true;
}

async function dbAddPairCredit(nameA, nameB, seconds) {
  const pair = [nameA, nameB].map(n => n.toLowerCase().trim()).sort().join(":");
  if (supabase) {
    try {
      const { data } = await supabase.from("pair_meetings").select("credit_seconds").eq("pair", pair).single();
      if (data) {
        await supabase.from("pair_meetings").update({ credit_seconds: (data.credit_seconds || 0) + seconds }).eq("pair", pair);
      } else {
        await supabase.from("pair_meetings").insert({ pair, meet_count: 0, credit_seconds: seconds, last_met: new Date().toISOString() });
      }
    } catch (e) { console.warn("Pair credit add error:", e.message); }
    return;
  }
  const stored = jsonGet("pair_meetings", pair);
  let pm; try { pm = stored ? JSON.parse(stored) : { meetCount: 0, creditSeconds: 0 }; } catch { pm = { meetCount: 0, creditSeconds: 0 }; }
  pm.creditSeconds += seconds;
  jsonSet("pair_meetings", pair, JSON.stringify(pm));
}

async function dbGetPairMeetings(nameA, nameB) {
  const pair = [nameA, nameB].map(n => n.toLowerCase().trim()).sort().join(":");
  if (supabase) {
    try {
      const { data } = await supabase.from("pair_meetings").select("*").eq("pair", pair).single();
      if (data) return { meetCount: data.meet_count || 0, creditSeconds: data.credit_seconds || 0, lastMet: data.last_met ? new Date(data.last_met).getTime() : null };
    } catch {}
    return { meetCount: 0, creditSeconds: 0, lastMet: null };
  }
  const stored = jsonGet("pair_meetings", pair);
  try { return stored ? JSON.parse(stored) : { meetCount: 0, creditSeconds: 0, lastMet: null }; } catch { return { meetCount: 0, creditSeconds: 0, lastMet: null }; }
}

async function dbGetSocialScore(name) {
  const key = name.toLowerCase().trim();
  const stats = await dbGetStats(key);
  const onlineSeconds = Math.floor((stats.totalOnlineMs || 0) / 1000);
  // Sum all pair credits this user has earned
  let totalPairCredits = 0;
  if (supabase) {
    try {
      const safeKey = key.replace(/[%_\\]/g, "\\$&");
      const [{ data: d1 }, { data: d2 }] = await Promise.all([
        supabase.from("pair_meetings").select("credit_seconds").like("pair", `${safeKey}:%`),
        supabase.from("pair_meetings").select("credit_seconds").like("pair", `%:${safeKey}`),
      ]);
      // Dedup by pair key to avoid double-counting self-pairs (e.g. alice:alice)
      const seen = new Set();
      const data = [...(d1 || []), ...(d2 || [])].filter(r => { if (seen.has(r.pair)) return false; seen.add(r.pair); return true; });
      if (data) totalPairCredits = data.reduce((sum, r) => sum + (r.credit_seconds || 0), 0);
    } catch {}
  } else {
    const store = jsonStores["pair_meetings"] || {};
    for (const [pair, val] of Object.entries(store)) {
      if (!pair.split(":").includes(key)) continue;
      try { totalPairCredits += JSON.parse(val).creditSeconds || 0; } catch {}
    }
  }
  return { score: onlineSeconds + totalPairCredits, onlineSeconds, pairCredits: totalPairCredits, totalMeets: stats.totalMeets };
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

async function dbGetWalletOwner(walletAddress) {
  const addr = walletAddress.toLowerCase();
  if (supabase) {
    try {
      const { data } = await supabase.from("wallet_addresses").select("name").eq("wallet_address", addr).single();
      if (data) return data.name;
    } catch {}
    return null;
  }
  // JSON fallback: scan all entries
  if (!jsonStores["wallet_addresses"]) jsonGet("wallet_addresses", "_probe");
  const store = jsonStores["wallet_addresses"] || {};
  for (const [name, wa] of Object.entries(store)) {
    if (wa === addr) return name;
  }
  return null;
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

// ─── Visitor & user counters ─────────────────────────────────────────────────

let totalVisitors = 0;

async function dbGetCounter(key) {
  if (supabase) {
    try {
      const { data } = await supabase.from("counters").select("value").eq("key", key).single();
      if (data) return data.value;
    } catch {}
    return 0;
  }
  const stored = jsonGet("counters", key);
  return stored ? parseInt(stored, 10) : 0;
}

async function dbIncrCounter(key) {
  if (supabase) {
    try {
      await supabase.rpc("increment_counter", { counter_key: key });
    } catch {
      // Fallback: read-increment-write
      try {
        const val = await dbGetCounter(key);
        await supabase.from("counters").upsert({ key, value: val + 1 });
      } catch (e) { console.warn("Counter increment error:", e.message); }
    }
    return;
  }
  const val = await dbGetCounter(key);
  jsonSet("counters", key, String(val + 1));
}

// ─── User directory (verified users) ────────────────────────────────────────

async function dbAddToDirectory(name, profile) {
  const key = name.toLowerCase().trim();
  if (supabase) {
    try {
      await supabase.from("user_directory").upsert({
        name: key,
        display_name: profile.displayName || name,
        x_username: profile.xUsername || null,
        wallet_address: profile.walletAddress || null,
        avatar: profile.avatar || null,
        last_seen: new Date().toISOString(),
      });
    } catch (e) { console.warn("Directory write error:", e.message); }
    return;
  }
  const stored = jsonGet("user_directory", "_all");
  let dir; try { dir = stored ? JSON.parse(stored) : {}; } catch { dir = {}; }
  dir[key] = { displayName: profile.displayName || name, xUsername: profile.xUsername || null, walletAddress: profile.walletAddress || null, avatar: profile.avatar || null, lastSeen: Date.now() };
  jsonSet("user_directory", "_all", JSON.stringify(dir));
}

async function dbGetDirectory() {
  if (supabase) {
    try {
      const { data } = await supabase.from("user_directory").select("*").order("last_seen", { ascending: false }).limit(500);
      if (data) return data.map(d => ({
        name: d.display_name, xUsername: d.x_username || null,
        walletAddress: d.wallet_address || null, avatar: d.avatar || null,
        lastSeen: new Date(d.last_seen).getTime(),
      }));
    } catch (e) { console.warn("Directory read error:", e.message); }
    return [];
  }
  const stored = jsonGet("user_directory", "_all");
  let dir; try { dir = stored ? JSON.parse(stored) : {}; } catch { dir = {}; }
  return Object.values(dir).sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0));
}

async function dbGetDirectoryEntry(name) {
  const key = name.toLowerCase().trim();
  if (supabase) {
    try {
      const { data } = await supabase.from("user_directory").select("x_username, wallet_address, display_name, avatar").eq("name", key).single();
      if (data) return { xUsername: data.x_username || null, walletAddress: data.wallet_address || null, displayName: data.display_name || null, avatar: data.avatar || null };
    } catch {}
    return null;
  }
  const stored = jsonGet("user_directory", "_all");
  try { const dir = stored ? JSON.parse(stored) : {}; return dir[key] || null; } catch { return null; }
}

async function countFollowers(name, xUsername) {
  let followers = 0;
  const self = name.toLowerCase().trim();
  if (supabase) {
    try {
      const { count: c1 } = await supabase.from("contacts").select("owner", { count: "exact", head: true }).eq("contact_name", name).neq("owner", self);
      followers = c1 || 0;
      if (xUsername) {
        const { count: c2 } = await supabase.from("contacts").select("owner", { count: "exact", head: true }).eq("contact_name", "@" + xUsername.toLowerCase()).neq("owner", self);
        followers += c2 || 0;
      }
    } catch {}
  } else {
    const store = jsonStores["contacts"] || {};
    for (const [owner, val] of Object.entries(store)) {
      if (owner === self) continue;
      try {
        const contacts = JSON.parse(val);
        if (contacts.includes(name) || (xUsername && contacts.includes("@" + xUsername.toLowerCase()))) followers++;
      } catch {}
    }
  }
  return followers;
}

async function getFollowerNames(name, xUsername) {
  const followers = [];
  const self = name.toLowerCase().trim();
  if (supabase) {
    try {
      const { data: d1 } = await supabase.from("contacts").select("owner").eq("contact_name", name).neq("owner", self);
      if (d1) for (const r of d1) followers.push(r.owner);
      if (xUsername) {
        const { data: d2 } = await supabase.from("contacts").select("owner").eq("contact_name", "@" + xUsername.toLowerCase()).neq("owner", self);
        if (d2) for (const r of d2) if (!followers.includes(r.owner)) followers.push(r.owner);
      }
    } catch {}
  } else {
    const store = jsonStores["contacts"] || {};
    for (const [owner, val] of Object.entries(store)) {
      if (owner === self) continue;
      try {
        const contacts = JSON.parse(val);
        if (contacts.includes(name) || (xUsername && contacts.includes("@" + xUsername.toLowerCase()))) {
          if (!followers.includes(owner)) followers.push(owner);
        }
      } catch {}
    }
  }
  return followers;
}

const MAX_NAME_LENGTH = 30;
const MAX_AVATAR_BYTES = 200_000; // ~200KB for a 128x128 JPEG

// ─── State ──────────────────────────────────────────────────────────────────

const onlineUsers = new Map();
const activeCalls = new Map();
const activeStreams = new Map(); // streamId -> { streamerId, streamerName, streamerAvatar, streamerXUsername, title, startedAt, viewers: Set<userId> }
const privateRooms = new Map(); // roomId -> { creatorId, creatorName, createdAt, guestId?, guestName? }
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

// Debounced broadcast — coalesces rapid-fire calls, always uses latest state
let _broadcastTimer = null;
function broadcastUserList() {
  if (_broadcastTimer) clearTimeout(_broadcastTimer);
  _broadcastTimer = setTimeout(() => {
    _broadcastTimer = null;
    const users = [];
    const seenNames = new Set();
    for (const [userId, data] of onlineUsers) {
      if (!data.disconnectedAt && !data.privateRoom && data.status !== "invisible" && !seenNames.has(data.name.toLowerCase())) {
        seenNames.add(data.name.toLowerCase());
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
          xUsername: data.xUsername || null, walletAddress: data.walletAddress || null, appWalletAddress: data.appWalletAddress || null,
          customStatus: data.customStatus || null, publicKey: data.publicKey || null,
          autoMeet: data.autoMeet || false,
          streaming, inCallWith,
        });
      }
    }
    io.emit("user-list", users);
    io.emit("online-count", users.length);
  }, 50);
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
  // Clean up private room state
  if (call.privateRoom) {
    privateRooms.delete(call.privateRoom);
    if (callerData) delete callerData.privateRoom;
    if (calleeData) delete calleeData.privateRoom;
    broadcastUserList(); // Re-add users to online list
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

// Check if a name is permanently claimed by a verified user (survives server restart)
async function isNameClaimed(name, requestingXUsername, requestingWallet) {
  const lower = name.toLowerCase().trim();
  // Check directory for a verified user with this name
  if (supabase) {
    try {
      const { data } = await supabase.from("user_directory").select("x_username, wallet_address").eq("name", lower).single();
      if (data && (data.x_username || data.wallet_address)) {
        // Name belongs to a verified user — only they can use it
        if (data.x_username && requestingXUsername && data.x_username.toLowerCase() === requestingXUsername.toLowerCase()) return false; // same X user
        if (data.wallet_address && requestingWallet && data.wallet_address.toLowerCase() === requestingWallet.toLowerCase()) return false; // same wallet
        return true; // different person trying to take a verified name
      }
    } catch {}
  } else {
    const stored = jsonGet("user_directory", "_all");
    try {
      const dir = stored ? JSON.parse(stored) : {};
      const entry = dir[lower];
      if (entry && (entry.xUsername || entry.walletAddress)) {
        if (entry.xUsername && requestingXUsername && entry.xUsername.toLowerCase() === requestingXUsername.toLowerCase()) return false;
        if (entry.walletAddress && requestingWallet && entry.walletAddress.toLowerCase() === requestingWallet.toLowerCase()) return false;
        return true;
      }
    } catch {}
  }
  return false; // not claimed by anyone verified
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
  // Count every socket connection as a visit
  totalVisitors++;
  dbIncrCounter("total_visitors");

  socket.on("register", async ({ name, reconnectUserId, avatar, xUsername, walletAddress, walletSignature, walletNonce, sessionToken }) => {
    if (!name || typeof name !== "string") return;
    const trimmedName = name.trim().slice(0, MAX_NAME_LENGTH);
    if (!trimmedName) { socket.emit("register-error", { message: "Name cannot be empty" }); return; }
    const safeAvatar = (avatar && typeof avatar === "string" && avatar.length <= MAX_AVATAR_BYTES) ? avatar : null;
    let safeWallet = (walletAddress && typeof walletAddress === "string" && /^0x[0-9a-fA-F]{40}$/.test(walletAddress)) ? walletAddress.toLowerCase() : null;

    // Verify X username: only trust it if the directory confirms this name owns it,
    // or if there's an x_profile entry matching the claimed username.
    // This prevents a malicious client from claiming any @handle on socket register.
    let verifiedXUsername = null;
    if (xUsername && typeof xUsername === "string") {
      const safeX = xUsername.toLowerCase().trim();
      // Check if x_profiles has this username (meaning they completed OAuth at some point)
      const xp = await dbGetXProfile(safeX);
      if (xp) {
        // Verify the registering name matches what was stored during OAuth
        const dirEntry = await dbGetDirectoryEntry(trimmedName);
        if (dirEntry && dirEntry.xUsername && dirEntry.xUsername.toLowerCase() === safeX) {
          verifiedXUsername = safeX;
        } else if (!dirEntry || !dirEntry.xUsername) {
          // Name not in directory yet or has no X link — allow if X profile exists (first login after OAuth)
          verifiedXUsername = safeX;
        }
        // If dirEntry has a DIFFERENT xUsername, reject the claim (someone else owns this name)
      }
    }

    // Verify wallet signature if wallet is being used for first-time login (not reconnect)
    if (safeWallet && walletSignature && walletNonce) {
      if (!verifyWalletSignature(safeWallet, walletSignature, walletNonce)) {
        socket.emit("register-error", { message: "Wallet signature verification failed" });
        return;
      }
    } else if (safeWallet && !reconnectUserId && !sessionToken && !verifiedXUsername) {
      // First-time wallet-only login without signature — reject
      // Skip if X-authenticated (X OAuth already verified identity)
      socket.emit("register-error", { message: "Wallet signature required" });
      return;
    }

    if (reconnectUserId && onlineUsers.has(reconnectUserId)) {
      const eu = onlineUsers.get(reconnectUserId);
      if (eu.name.toLowerCase() !== trimmedName.toLowerCase()) { socket.emit("register-error", { message: "Name mismatch on reconnect" }); return; }
      if (disconnectTimers.has(reconnectUserId)) { clearTimeout(disconnectTimers.get(reconnectUserId)); disconnectTimers.delete(reconnectUserId); }
      eu.socketId = socket.id; eu.disconnectedAt = null; eu.status = "online"; eu.connectedAt = Date.now();
      if (safeAvatar) { eu.avatar = safeAvatar; await dbSetAvatar(eu.name, safeAvatar); }
      // On reconnect, only accept wallet if it matches what's already stored (no unsigned updates)
      if (safeWallet && eu.walletAddress && safeWallet !== eu.walletAddress) safeWallet = null;
      socket.userId = reconnectUserId;
      let resolvedAvatar = eu.avatar || await dbGetAvatar(eu.name);
      if (!resolvedAvatar && eu.xUsername) {
        const xp = await dbGetXProfile(eu.xUsername);
        if (xp?.avatar) { resolvedAvatar = xp.avatar; await dbSetAvatar(eu.name, resolvedAvatar); }
      }
      eu.avatar = resolvedAvatar;
      eu.stats = await dbGetStats(eu.name);
      const prefs = await dbGetPrefs(eu.name);
      eu.autoMeet = prefs.autoMeet;
      eu.cooldownHours = prefs.cooldownHours;
      if (!eu.customStatus) { const p = await dbGetProfile(eu.name); eu.customStatus = p.customStatus || null; }
      socket.emit("registered", { userId: reconnectUserId, name: eu.name, reconnected: true, avatar: resolvedAvatar, stats: eu.stats, xUsername: eu.xUsername || null, walletAddress: eu.walletAddress || null, customStatus: eu.customStatus || null, autoMeet: eu.autoMeet, cooldownHours: eu.cooldownHours });
      // Backfill directory for verified users
      dbAddToDirectory(eu.name, { displayName: eu.name, xUsername: eu.xUsername, walletAddress: eu.walletAddress, avatar: resolvedAvatar });
      broadcastUserList();
      return;
    }

    if (isNameTaken(trimmedName)) {
      // Check if the user can reclaim this name via matching X username or session token
      const existingUserId = takenNames.get(trimmedName.toLowerCase());
      const existingUser = existingUserId ? onlineUsers.get(existingUserId) : null;
      let canReclaim = false;
      if (existingUser) {
        // Same X username → same person
        if (verifiedXUsername && existingUser.xUsername && verifiedXUsername.toLowerCase() === existingUser.xUsername.toLowerCase()) canReclaim = true;
        // Same wallet → same person
        if (safeWallet && existingUser.walletAddress && safeWallet === existingUser.walletAddress) canReclaim = true;
        // Existing user is disconnected (in grace period) and session token matches
        if (existingUser.disconnectedAt && sessionToken) {
          const storedHash = await dbGetSessionToken(trimmedName);
          if (storedHash && hashToken(sessionToken) === storedHash) canReclaim = true;
        }
      }
      if (canReclaim && existingUser) {
        // Take over the old connection
        if (disconnectTimers.has(existingUserId)) { clearTimeout(disconnectTimers.get(existingUserId)); disconnectTimers.delete(existingUserId); }
        onlineUsers.delete(existingUserId);
        takenNames.delete(trimmedName.toLowerCase());
      } else {
        socket.emit("register-error", { message: `"${trimmedName}" is already taken. Try a different name.` });
        return;
      }
    }

    // Check if name is permanently claimed by a verified user (survives server restart)
    if (await isNameClaimed(trimmedName, verifiedXUsername, safeWallet)) {
      socket.emit("register-error", { message: `"${trimmedName}" belongs to a verified account. Sign in with the original method.` });
      return;
    }

    // Wallet-authenticated: verify wallet ownership
    if (safeWallet) {
      const existingWallet = await dbGetWallet(trimmedName);
      if (existingWallet && existingWallet !== safeWallet) {
        socket.emit("register-error", { message: `"${trimmedName}" is claimed by a different wallet.` });
        return;
      }
      // Reverse check: ensure this wallet isn't already used by a different user
      const existingOwner = await dbGetWalletOwner(safeWallet);
      if (existingOwner && existingOwner !== trimmedName.toLowerCase().trim()) {
        socket.emit("register-error", { message: "This wallet is already linked to another account." });
        return;
      }
    }

    // Guest session token: if this name has a stored token, verify it
    // Skip for X-authenticated or wallet-authenticated users
    if (!verifiedXUsername && !safeWallet) {
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
    let storedAvatar = await dbGetAvatar(trimmedName);
    // Fallback: try x_profiles for avatar if not in avatars table
    if (!storedAvatar && verifiedXUsername) {
      const xp = await dbGetXProfile(verifiedXUsername);
      if (xp?.avatar) { storedAvatar = xp.avatar; await dbSetAvatar(trimmedName, storedAvatar); }
    }
    const resolvedAvatar = safeAvatar || storedAvatar || null;
    if (safeAvatar && safeAvatar !== storedAvatar) await dbSetAvatar(trimmedName, safeAvatar);
    const stats = await dbGetStats(trimmedName);
    const prefs = await dbGetPrefs(trimmedName);

    const storedWallet = safeWallet || await dbGetWallet(trimmedName);
    if (safeWallet && safeWallet !== storedWallet) await dbSetWallet(trimmedName, safeWallet);
    const storedProfile = await dbGetProfile(trimmedName);

    onlineUsers.set(userId, {
      socketId: socket.id, name: trimmedName, status: "online",
      avatar: resolvedAvatar, stats, disconnectedAt: null, connectedAt: Date.now(),
      xUsername: verifiedXUsername || null, walletAddress: storedWallet || null,
      customStatus: storedProfile.customStatus || null,
      publicKey: null, // loaded via register-pubkey
      autoMeet: prefs.autoMeet, cooldownHours: prefs.cooldownHours,
    });

    // Load stored public key for E2E encryption
    const storedPubKey = await dbGetPublicKey(trimmedName);
    if (storedPubKey) onlineUsers.get(userId).publicKey = storedPubKey;
    takenNames.set(trimmedName.toLowerCase(), userId);

    // Issue session token for all users (needed for reconnection after server restart)
    // Always generate server-side — never reuse a client-supplied token
    const newSessionToken = base64url(crypto.randomBytes(24));
    await dbSetSessionToken(trimmedName, hashToken(newSessionToken));

    socket.emit("registered", { userId, name: trimmedName, reconnected: false, avatar: resolvedAvatar, stats, xUsername: verifiedXUsername || null, walletAddress: storedWallet || null, customStatus: storedProfile.customStatus || null, autoMeet: prefs.autoMeet, cooldownHours: prefs.cooldownHours, sessionToken: newSessionToken });
    broadcastUserList();
    console.log(`✅ ${trimmedName}${verifiedXUsername ? " (@" + verifiedXUsername + ")" : ""}${storedWallet ? " [" + storedWallet.slice(0,6) + "...]" : ""} registered as ${userId}`);

    // Add all users to directory (verified and guests)
    dbAddToDirectory(trimmedName, { displayName: trimmedName, xUsername: verifiedXUsername || null, walletAddress: storedWallet || null, avatar: resolvedAvatar });

    // Claim wallet inbox: migrate DMs sent to the raw wallet address to this user's name
    if (storedWallet) {
      claimWalletInbox(storedWallet, trimmedName, socket);
    }
  });

  socket.on("update-avatar", async ({ avatar }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (avatar && (typeof avatar !== "string" || avatar.length > MAX_AVATAR_BYTES)) return;
    userData.avatar = avatar || null;
    await dbSetAvatar(userData.name, avatar);
    broadcastUserList();
  });

  socket.on("set-status", async ({ status, customStatus }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    // Update presence status
    if (status === "online" || status === "idle" || status === "invisible") {
      const prevStatus = userData.status;
      userData.status = status;
      // Flush online time when leaving "online" status (no credit for idle/invisible)
      if (prevStatus === "online" && status !== "online" && userData.connectedAt) {
        const sessionMs = Date.now() - userData.connectedAt;
        if (sessionMs > 0) {
          const stats = await dbGetStats(userData.name);
          stats.totalOnlineMs = (stats.totalOnlineMs || 0) + sessionMs;
          await dbSetStats(userData.name, stats);
        }
        userData.connectedAt = null; // stop accumulating
      }
      // Resume tracking when returning to online
      if (status === "online" && prevStatus !== "online") {
        userData.connectedAt = Date.now();
      }
    }
    // Broadcast immediately after status change — don't wait for DB operations
    broadcastUserList();
    // Persist online time in background (non-blocking for the broadcast)
    if (status !== undefined && userData.status !== "online") {
      // Already flushed above if needed
    }
    // Update custom status text (persisted like bio)
    if (customStatus !== undefined) {
      userData.customStatus = (typeof customStatus === "string") ? customStatus.trim().slice(0, 50) : null;
      broadcastUserList(); // broadcast again with updated custom status
      const profile = await dbGetProfile(userData.name);
      profile.customStatus = userData.customStatus;
      await dbSetProfile(userData.name, profile);
    }
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
    // Check wallet isn't already used by another user
    const existingOwner = await dbGetWalletOwner(safeWallet);
    if (existingOwner && existingOwner !== userData.name.toLowerCase().trim()) {
      socket.emit("wallet-link-error", { message: "This wallet is already linked to another account." });
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
    // Don't allow saving yourself
    const targetKey = (contactName || "").toLowerCase().trim();
    const selfName = userData.name.toLowerCase().trim();
    const selfX = userData.xUsername ? "@" + userData.xUsername.toLowerCase() : null;
    if (targetKey === selfName || targetKey === selfX) return;
    await dbAddContact(userData.name, contactName);
    const contacts = await dbGetContacts(userData.name);
    socket.emit("contacts-list", contacts);
    // Notify the person being followed
    const targetName = contactName.startsWith("@") ? contactName.slice(1) : contactName;
    // Resolve @handle to registered name
    let resolvedName = targetName;
    if (contactName.startsWith("@")) {
      for (const [, d] of onlineUsers) { if (d.xUsername && d.xUsername.toLowerCase() === targetName.toLowerCase()) { resolvedName = d.name; break; } }
    }
    const notif = await dbCreateNotification(resolvedName, "follow", userData.name, null, null);
    emitNotification(resolvedName, notif);
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
  socket.on("start-stream", async ({ title, groupId }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (isUserInCall(userId) || isUserStreaming(userId)) { socket.emit("stream-error", { message: "You're already in a call or stream" }); return; }

    const streamId = uuidv4().slice(0, 12);
    activeStreams.set(streamId, {
      streamerId: userId, streamerName: userData.name,
      streamerAvatar: userData.avatar || null, streamerXUsername: userData.xUsername || null,
      title: title || `${userData.name}'s stream`, startedAt: Date.now(),
      viewers: new Set(), groupId: groupId || null,
    });
    socket.emit("stream-started", { streamId });
    broadcastUserList();
    // If group stream, notify all group members
    if (groupId) {
      const members = await dbGetGroupMembers(groupId);
      const group = await dbGetGroup(groupId);
      const groupName = group?.name || "a group";
      for (const m of members) {
        if (m.userName === userData.name.toLowerCase().trim() || m.role === "pending") continue;
        const notif = await dbCreateNotification(m.userName, "group_stream", userData.name, null, `Live in ${groupName}`);
        emitNotification(m.userName, notif);
        // Also emit a direct event so online members get an immediate prompt
        for (const [uid, d] of onlineUsers) {
          if (d.name.toLowerCase() === m.userName && !d.disconnectedAt) {
            const s = getSocketByUserId(uid);
            if (s) s.emit("group-stream-started", { groupId, streamId, streamerName: userData.name, groupName });
            break;
          }
        }
      }
    }
    console.log(`📺 ${userData.name} started streaming: ${title || userData.name + "'s stream"}${groupId ? " (group: " + groupId + ")" : ""}`);
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
    if (stream.streamerId !== socket.userId) return; // only streamer can send offers
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
  socket.on("chat-public", async ({ text, image }) => {
    if (!rateLimit(socket, "chat", 10, 10_000)) return;
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const trimmed = (text || "").trim().slice(0, 500);
    const safeImage = (image && typeof image === "string" && image.startsWith("data:image/") && image.length <= 500_000) ? image : null;
    if (!trimmed && !safeImage) return;
    const msg = { id: uuidv4().slice(0, 10), userId, name: userData.name, avatar: userData.avatar || null, xUsername: userData.xUsername || null, walletAddress: userData.walletAddress || null, text: trimmed, image: safeImage, ts: Date.now() };
    publicChat.push(msg);
    if (publicChat.length > MAX_CHAT_HISTORY) publicChat.shift();
    io.emit("chat-public", msg);
    dbSavePublicMsg(msg); // persist (non-blocking)
  });

  socket.on("chat-react", async ({ msgId, emoji }) => {
    if (!rateLimit(socket, "react", 20, 10_000)) return;
    const userId = socket.userId; if (!userId) return;
    if (!msgId || !emoji || typeof emoji !== "string" || emoji.length > 4) return;
    // Find the message in publicChat
    const msg = publicChat.find(m => m.id === msgId);
    if (!msg) return;
    if (!msg.reactions) msg.reactions = {};
    // Toggle: if user already reacted with this emoji, remove it; otherwise set it
    if (msg.reactions[userId] === emoji) {
      delete msg.reactions[userId];
    } else {
      msg.reactions[userId] = emoji;
    }
    io.emit("chat-react", { msgId, reactions: msg.reactions });
    // Persist reactions
    dbSaveReaction(msgId, msg.reactions);
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

  // P2P direct messages (persisted)
  socket.on("chat-dm", async ({ toUserId, toName, text, image, encrypted }) => {
    if (!rateLimit(socket, "chat", 10, 10_000)) return;
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const trimmed = (text || "").trim().slice(0, 2000); // larger limit for encrypted base64
    const safeImage = (!encrypted && image && typeof image === "string" && image.startsWith("data:image/") && image.length <= 500_000) ? image : null;
    if (!trimmed && !safeImage) return;
    const isEncrypted = !!encrypted;

    // Resolve target: userId → online user, or name/wallet → resolved name
    let targetName = null;
    let targetUserId = null;
    if (toUserId && onlineUsers.has(toUserId)) {
      const target = onlineUsers.get(toUserId);
      targetName = target.name;
      targetUserId = toUserId;
    } else if (toName && typeof toName === "string") {
      targetName = toName.trim().slice(0, 60);
      // Resolve wallet address to registered user
      if (/^0x[0-9a-f]{40}$/i.test(targetName)) {
        const owner = await dbGetWalletOwner(targetName.toLowerCase());
        if (owner) targetName = owner;
      }
      // Check if resolved target is online
      const onlineTarget = [...onlineUsers.entries()].find(([, d]) => d.name.toLowerCase() === targetName.toLowerCase() && !d.disconnectedAt);
      if (onlineTarget) targetUserId = onlineTarget[0];
    }
    if (!targetName) return;

    // Build message, deliver, persist, notify
    const msg = { id: uuidv4().slice(0, 10), fromUserId: userId, fromName: userData.name, fromAvatar: userData.avatar || null, text: trimmed, image: safeImage, encrypted: isEncrypted, ts: Date.now() };
    if (targetUserId) {
      const ts = getSocketByUserId(targetUserId);
      if (ts) ts.emit("chat-dm", msg);
    }
    socket.emit("chat-dm-sent", { toUserId: targetUserId, toName: targetName, ...msg });
    dbSaveDM(userData.name, targetName, msg);
    const dmNotif = await dbCreateNotification(targetName, "dm", userData.name, null, isEncrypted ? "[encrypted message]" : trimmed);
    emitNotification(targetName, dmNotif);
    // Notify both sides to refresh conversation list
    socket.emit("dm-conversations-update", { peerName: targetName, lastMessage: isEncrypted ? "[encrypted]" : trimmed.slice(0, 50), lastTime: msg.ts });
    if (targetUserId) {
      const ts = getSocketByUserId(targetUserId);
      if (ts) ts.emit("dm-conversations-update", { peerName: userData.name, lastMessage: isEncrypted ? "[encrypted]" : trimmed.slice(0, 50), lastTime: msg.ts });
    }
  });

  // DM typing indicator (relay only, no persistence)
  socket.on("dm-typing", ({ toName }) => {
    if (!rateLimit(socket, "dm-typing", 5, 5_000)) return;
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (!toName || typeof toName !== "string") return;
    const targetKey = toName.toLowerCase().trim();
    for (const [tId, tData] of onlineUsers) {
      if (tData.name.toLowerCase() === targetKey && !tData.disconnectedAt) {
        const ts = getSocketByUserId(tId);
        if (ts) ts.emit("dm-typing", { fromName: userData.name });
        break;
      }
    }
  });

  // DM read receipts
  socket.on("dm-read", async ({ peerName, readAt }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (!peerName || typeof peerName !== "string" || typeof readAt !== "number") return;
    const myName = userData.name.toLowerCase().trim();
    const peerKey = peerName.toLowerCase().trim();
    // Persist read cursor
    await dbSetReadCursor(myName, peerKey, readAt);
    // Relay to peer if online
    for (const [tId, tData] of onlineUsers) {
      if (tData.name.toLowerCase() === peerKey && !tData.disconnectedAt) {
        const ts = getSocketByUserId(tId);
        if (ts) ts.emit("dm-read-receipt", { fromName: myName, readAt });
        break;
      }
    }
  });

  // DM history
  socket.on("dm-history", async ({ peerName, limit, before }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (!peerName || typeof peerName !== "string") return;
    let resolvedPeer = peerName;
    // If peerName is a wallet address, resolve to the registered user's name
    if (/^0x[0-9a-f]{40}$/i.test(peerName)) {
      const owner = await dbGetWalletOwner(peerName.toLowerCase());
      if (owner) resolvedPeer = owner;
    }
    const safeLimit = Math.min(Math.max(parseInt(limit) || 50, 1), 100);
    const safeBefore = typeof before === "number" ? before : null;
    const peerKey = resolvedPeer.toLowerCase().trim();
    const myKey = userData.name.toLowerCase().trim();
    const [messages, peerReadAt] = await Promise.all([
      dbLoadDMs(myKey, peerKey, safeLimit, safeBefore),
      safeBefore ? Promise.resolve(0) : dbGetReadCursor(peerKey, myKey), // only load on initial fetch
    ]);
    socket.emit("dm-history", { peerName, messages, hasMore: messages.length === safeLimit, peerReadAt: peerReadAt || 0 });
  });

  // ── Posts & Profiles ──────────────────────────────────────────────────────

  socket.on("create-post", async ({ text, parentId, image }) => {
    if (!rateLimit(socket, "post", 5, 60_000)) return;
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (!userData.xUsername && !userData.walletAddress) { socket.emit("post-error", { message: "Verified account required to post" }); return; }
    const trimmed = (text || "").trim().slice(0, 500);
    if (!trimmed && !image) return;
    const safeImage = (image && typeof image === "string" && image.startsWith("data:image/") && image.length <= 500_000) ? image : null;
    const post = await dbCreatePost(userData.name, trimmed || "", parentId || null, safeImage);
    post.authorName = userData.name;
    post.authorAvatar = userData.avatar || null;
    post.authorXUsername = userData.xUsername || null;
    socket.emit("post-created", post);
    // Broadcast new top-level posts to all connected users so feeds update in real time
    if (!parentId) {
      socket.broadcast.emit("feed-new-post", post);
    }
    // Broadcast reply count update and notify parent author on reply
    if (parentId) {
      const parent = await dbGetPost(parentId);
      if (parent) {
        io.emit("post-reply-count", { postId: parentId, replyCount: parent.replyCount || 0 });
        if (parent.author !== userData.name.toLowerCase()) {
          const notif = await dbCreateNotification(parent.author, "reply", userData.name, parent.rootId || parentId, trimmed);
          emitNotification(parent.author, notif);
        }
      }
    }
    // Notify users who have saved this author as a contact (top-level posts only)
    if (!parentId) {
      const authorKey = userData.name.toLowerCase().trim();
      const authorXKey = userData.xUsername ? "@" + userData.xUsername.toLowerCase() : null;
      // Check all online users' contacts
      for (const [uid, udata] of onlineUsers) {
        if (uid === userId || udata.disconnectedAt) continue;
        const contacts = contactsCache.get(udata.name.toLowerCase().trim());
        if (contacts && (contacts.has(authorKey) || (authorXKey && contacts.has(authorXKey)))) {
          const notif = await dbCreateNotification(udata.name, "post", userData.name, post.id, (trimmed || "").slice(0, 60));
          emitNotification(udata.name, notif);
        }
      }
    }
    // Notify @mentioned users
    const mentions = (trimmed || "").match(/@([a-zA-Z0-9._-]{1,30})/g);
    if (mentions) {
      const notifiedSet = new Set(); // avoid duplicate notifications
      for (const mention of mentions) {
        const mentionedName = mention.slice(1).toLowerCase();
        if (mentionedName === userData.name.toLowerCase()) continue; // don't notify self
        if (notifiedSet.has(mentionedName)) continue;
        notifiedSet.add(mentionedName);
        // Check if this is an X handle — resolve to registered name
        let resolvedName = mentionedName;
        const dirEntry = await dbGetDirectoryEntry(mentionedName);
        if (!dirEntry) {
          // Try as X username
          for (const [, d] of onlineUsers) {
            if (d.xUsername && d.xUsername.toLowerCase() === mentionedName) { resolvedName = d.name.toLowerCase(); break; }
          }
        }
        const notif = await dbCreateNotification(resolvedName, "mention", userData.name, post.rootId || post.id, (trimmed || "").slice(0, 60));
        emitNotification(resolvedName, notif);
      }
    }
  });

  socket.on("delete-post", async ({ postId }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const post = await dbGetPost(postId);
    const parentId = post ? post.parentId : null;
    const ok = await dbDeletePost(postId, userData.name);
    if (ok) {
      socket.emit("post-deleted", { postId });
      // Update parent's reply count if this was a reply
      if (parentId) {
        const parent = await dbGetPost(parentId);
        if (parent) io.emit("post-reply-count", { postId: parentId, replyCount: parent.replyCount || 0 });
      }
    }
  });

  socket.on("toggle-like", async ({ postId }) => {
    if (!rateLimit(socket, "like", 20, 10_000)) return;
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const result = await dbToggleLike(postId, userData.name);
    const post = await dbGetPost(postId);
    const likers = await dbGetPostLikes(postId);
    const likeCount = post ? post.likeCount : 0;
    // Send liked state to the user who clicked
    socket.emit("post-liked", { postId, likeCount, liked: result.liked, likers });
    // Broadcast updated count to all other users (no chime — just silent count update)
    socket.broadcast.emit("post-like-count", { postId, likeCount, likers });
    // Notify post author on like
    if (result.liked && post && post.author !== userData.name.toLowerCase()) {
      const notif = await dbCreateNotification(post.author, "like", userData.name, postId, null);
      emitNotification(post.author, notif);
    }
  });

  socket.on("toggle-repost", async ({ postId }) => {
    if (!rateLimit(socket, "repost", 10, 10_000)) return;
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const post = await dbGetPost(postId);
    if (!post) return;
    // Can't repost own posts
    if (post.author === userData.name.toLowerCase()) {
      socket.emit("post-error", { message: "Can't repost your own post" });
      return;
    }
    const result = await dbToggleRepost(postId, userData.name);
    const reposters = await dbGetPostReposters(postId);
    socket.emit("post-reposted", { postId, reposted: result.reposted, reposters });
    // Notify original poster on repost
    if (result.reposted) {
      const notif = await dbCreateNotification(post.author, "repost", userData.name, postId, null);
      emitNotification(post.author, notif);
    }
  });

  socket.on("get-user-posts", async ({ username, limit, offset }) => {
    if (!username || typeof username !== "string") return;
    const result = await dbGetUserPosts(username, limit || 20, offset || 0);
    const userData = socket.userId ? onlineUsers.get(socket.userId) : null;
    const myNameLower = userData ? userData.name.toLowerCase() : "";
    // Get author avatar + reposts in parallel with post enrichment
    const [authorAvatar, reposts] = await Promise.all([
      dbGetAvatar(username), dbGetUserReposts(username, limit || 20),
    ]);
    // Enrich own posts in parallel (likers + reposters per post)
    await Promise.all(result.posts.map(async (post) => {
      post.authorName = username;
      post.authorAvatar = authorAvatar || null;
      const [likers, reposters] = await Promise.all([dbGetPostLikes(post.id), dbGetPostReposters(post.id)]);
      post.likers = likers;
      post.liked = myNameLower ? likers.includes(myNameLower) : false;
      post.reposters = reposters;
    }));
    // Enrich reposts in parallel
    const avatarCacheLocal = { [username.toLowerCase()]: authorAvatar || null };
    // Pre-fetch unique repost author avatars in parallel
    const uniqueAuthors = [...new Set(reposts.map(rp => rp.author).filter(a => !avatarCacheLocal[a]))];
    const authorAvatars = await Promise.all(uniqueAuthors.map(a => dbGetAvatar(a)));
    uniqueAuthors.forEach((a, i) => { avatarCacheLocal[a] = authorAvatars[i] || null; });
    await Promise.all(reposts.map(async (rp) => {
      rp.authorName = rp.author;
      rp.authorAvatar = avatarCacheLocal[rp.author] || null;
      const [likers, reposters] = await Promise.all([dbGetPostLikes(rp.id), dbGetPostReposters(rp.id)]);
      rp.likers = likers;
      rp.liked = myNameLower ? likers.includes(myNameLower) : false;
      rp.reposters = reposters;
    }));
    // Merge and sort by time, dedup by post ID (own posts take priority over reposts)
    const ownIds = new Set(result.posts.map(p => p.id));
    const dedupedReposts = reposts.filter(rp => !ownIds.has(rp.id));
    const merged = [...result.posts, ...dedupedReposts].sort((a, b) => (b.repostedAt || b.createdAt) - (a.repostedAt || a.createdAt));
    socket.emit("user-posts", { username, posts: merged, total: merged.length });
  });

  socket.on("get-user-replies", async ({ username, limit, offset }) => {
    if (!username || typeof username !== "string") return;
    const result = await dbGetUserReplies(username, limit || 20, offset || 0);
    const userData = socket.userId ? onlineUsers.get(socket.userId) : null;
    const myNameLower = userData ? userData.name.toLowerCase() : "";
    const avatarCacheLocal = {};
    await Promise.all(result.posts.map(async (post) => {
      post.authorName = post.author;
      if (!avatarCacheLocal[post.author]) avatarCacheLocal[post.author] = await dbGetAvatar(post.author) || null;
      post.authorAvatar = avatarCacheLocal[post.author];
      const [likers, reposters] = await Promise.all([dbGetPostLikes(post.id), dbGetPostReposters(post.id)]);
      post.likers = likers;
      post.liked = myNameLower ? likers.includes(myNameLower) : false;
      post.reposters = reposters;
    }));
    socket.emit("user-replies", { username, posts: result.posts, total: result.total });
  });

  socket.on("get-thread", async ({ postId }) => {
    if (!postId) return;
    const thread = await dbGetThread(postId);
    const avatarCache = {};
    for (const post of thread) {
      post.authorName = post.author;
      if (!avatarCache[post.author]) avatarCache[post.author] = await dbGetAvatar(post.author) || null;
      post.authorAvatar = avatarCache[post.author];
      post.likers = await dbGetPostLikes(post.id);
      post.reposters = await dbGetPostReposters(post.id);
    }
    socket.emit("thread", { postId, posts: thread });
  });

  socket.on("get-global-feed", async ({ limit }) => {
    const posts = await dbGetGlobalFeed(limit || 30);
    const userData = socket.userId ? onlineUsers.get(socket.userId) : null;
    const myNameLower = userData ? userData.name.toLowerCase() : "";
    for (const post of posts) {
      const likers = await dbGetPostLikes(post.id);
      post.likers = likers;
      post.liked = myNameLower ? likers.includes(myNameLower) : false;
      const reposters = await dbGetPostReposters(post.id);
      post.reposters = reposters;
      // Enrich with author avatar/name from directory
      post.authorAvatar = await dbGetAvatar(post.author) || null;
      post.authorName = post.author;
    }
    socket.emit("global-feed", { posts });
  });

  socket.on("get-profile", async ({ username }) => {
    if (!username || typeof username !== "string") return;
    let key = username.toLowerCase().trim();

    // Resolve @handle to registered name
    if (key.startsWith("@") && key.length > 1) {
      const handle = key.slice(1);
      for (const [, d] of onlineUsers) {
        if (d.xUsername && d.xUsername.toLowerCase() === handle) { key = d.name.toLowerCase(); break; }
      }
      // If still @handle, check x_profiles
      if (key.startsWith("@")) {
        const xp = await dbGetXProfile(key.slice(1));
        if (xp?.display_name) key = xp.display_name.toLowerCase().trim();
        else if (xp?.displayName) key = xp.displayName.toLowerCase().trim();
      }
    }

    // Resolve 0x address to registered name
    if (/^0x[0-9a-f]{40}$/.test(key)) {
      const owner = await dbGetWalletOwner(key);
      if (owner) key = owner;
    }
    // Parallelize independent DB queries for faster profile loading
    const [profile, stats, wallet, socialScore] = await Promise.all([
      dbGetProfile(key), dbGetStats(key), dbGetWallet(key), dbGetSocialScore(key),
    ]);
    let avatar = await dbGetAvatar(key);

    // Find xUsername + avatar from online users (instant, in-memory)
    let xUsername = null;
    let displayName = username;
    for (const [, d] of onlineUsers) {
      if (d.name.toLowerCase() === key) {
        xUsername = d.xUsername; if (d.avatar && !avatar) avatar = d.avatar;
        displayName = d.name; break;
      }
    }
    // Fallback: check directory for offline users
    if (!xUsername || !avatar) {
      const dirEntry = await dbGetDirectoryEntry(key);
      if (dirEntry) {
        if (!xUsername) xUsername = dirEntry.xUsername || null;
        if (!avatar && dirEntry.avatar) avatar = dirEntry.avatar;
        if (dirEntry.displayName) displayName = dirEntry.displayName;
      }
    }
    // Final fallback: check x_profiles for avatar + xUsername
    if (!xUsername && supabase) {
      try {
        const { data } = await supabase.from("x_profiles").select("username, avatar").eq("display_name", displayName).single();
        if (data) { xUsername = data.username; if (!avatar) avatar = data.avatar; }
      } catch {}
    }
    if (!avatar && xUsername) {
      const xProfile = await dbGetXProfile(xUsername);
      if (xProfile?.avatar) { avatar = xProfile.avatar; dbSetAvatar(key, avatar); }
    }

    // Parallelize pair info + follower count (both depend on xUsername being resolved)
    const viewerData = socket.userId ? onlineUsers.get(socket.userId) : null;
    const [pairInfo, followers] = await Promise.all([
      (viewerData && viewerData.name.toLowerCase() !== key) ? dbGetPairMeetings(viewerData.name, key) : null,
      countFollowers(key, xUsername),
    ]);

    socket.emit("profile", { username: key, displayName, bio: profile.bio, banner: profile.banner, avatar, xUsername, walletAddress: wallet, appWalletAddress: profile.appWalletAddress || null, stats, postCount: 0, followers, customStatus: profile.customStatus || null, socialScore, pairInfo, callRate: profile.callRate || null });
  });

  socket.on("update-profile", async ({ bio, banner }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const profile = await dbGetProfile(userData.name);
    if (bio !== undefined) profile.bio = typeof bio === "string" ? bio.trim().slice(0, 200) : null;
    if (banner !== undefined) profile.banner = (typeof banner === "string" && banner.length <= 500_000) ? banner : null;
    await dbSetProfile(userData.name, profile);
    socket.emit("profile-updated", { bio: profile.bio, banner: profile.banner });
  });

  socket.on("get-social-score", async () => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const score = await dbGetSocialScore(userData.name);
    socket.emit("social-score", score);
  });

  socket.on("get-followers", async ({ username }) => {
    if (!socket.userId || !onlineUsers.has(socket.userId)) return;
    if (!username || typeof username !== "string") return;
    const key = username.toLowerCase().trim();
    // Resolve xUsername from directory
    const dirEntry = await dbGetDirectoryEntry(key);
    const xUsername = dirEntry?.xUsername || null;
    const followerNames = await getFollowerNames(key, xUsername);
    // Enrich with avatars
    const followers = await Promise.all(followerNames.map(async (name) => {
      const avatar = await dbGetAvatar(name);
      const entry = await dbGetDirectoryEntry(name);
      return { name: entry?.displayName || name, avatar: avatar || entry?.avatar || null, xUsername: entry?.xUsername || null };
    }));
    socket.emit("followers-list", { username: key, followers });
  });

  socket.on("get-my-pairs", async () => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const key = userData.name.toLowerCase().trim();
    const pairs = {};
    if (supabase) {
      try {
        const safeKey = key.replace(/[%_\\]/g, "\\$&");
        const [{ data: d1 }, { data: d2 }] = await Promise.all([
          supabase.from("pair_meetings").select("pair, meet_count, credit_seconds").like("pair", `${safeKey}:%`),
          supabase.from("pair_meetings").select("pair, meet_count, credit_seconds").like("pair", `%:${safeKey}`),
        ]);
        const data = [...(d1 || []), ...(d2 || [])];
        if (data) for (const r of data) {
          const parts = r.pair.split(":");
          const peer = parts.find(p => p !== key) || parts[0];
          pairs[peer] = { meetCount: r.meet_count || 0, creditSeconds: r.credit_seconds || 0 };
        }
      } catch {}
    } else {
      const store = jsonStores["pair_meetings"] || {};
      for (const [pair, val] of Object.entries(store)) {
        const parts = pair.split(":");
        if (!parts.includes(key)) continue;
        try {
          const pm = JSON.parse(val);
          const peer = parts.find(p => p !== key) || parts[0];
          pairs[peer] = { meetCount: pm.meetCount || 0, creditSeconds: pm.creditSeconds || 0 };
        } catch {}
      }
    }
    socket.emit("my-pairs", pairs);
  });

  // Bundled init — returns contacts, chat history, notifications, social score, pairs, feed in one response
  socket.on("init-data", async () => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const key = userData.name.toLowerCase().trim();
    const [contacts, notifications, unreadCount, socialScore, feed] = await Promise.all([
      dbGetContacts(key),
      dbGetNotifications(key),
      dbGetUnreadCount(key),
      dbGetSocialScore(key),
      (async () => {
        const posts = await dbGetGlobalFeed(30);
        const myNameLower = key;
        for (const post of posts) {
          const likers = await dbGetPostLikes(post.id);
          post.likers = likers;
          post.liked = myNameLower ? likers.includes(myNameLower) : false;
          post.authorAvatar = await dbGetAvatar(post.author) || null;
          post.authorName = post.author;
        }
        return posts;
      })(),
    ]);
    // Pair meetings
    const pairs = {};
    const safeKey = key.replace(/[%_\\]/g, "\\$&");
    if (supabase) {
      try {
        const [{ data: d1 }, { data: d2 }] = await Promise.all([
          supabase.from("pair_meetings").select("pair, meet_count, credit_seconds").like("pair", `${safeKey}:%`),
          supabase.from("pair_meetings").select("pair, meet_count, credit_seconds").like("pair", `%:${safeKey}`),
        ]);
        const data = [...(d1 || []), ...(d2 || [])];
        if (data) for (const r of data) {
          const parts = r.pair.split(":");
          const peer = parts.find(p => p !== key) || parts[0];
          pairs[peer] = { meetCount: r.meet_count || 0, creditSeconds: r.credit_seconds || 0 };
        }
      } catch {}
    } else {
      const store = jsonStores["pair_meetings"] || {};
      for (const [pair, val] of Object.entries(store)) {
        const parts = pair.split(":");
        if (!parts.includes(key)) continue;
        try {
          const pm = JSON.parse(val);
          const peer = parts.find(p => p !== key) || parts[0];
          pairs[peer] = { meetCount: pm.meetCount || 0, creditSeconds: pm.creditSeconds || 0 };
        } catch {}
      }
    }
    socket.emit("init-data", {
      contacts,
      chatHistory: publicChat.slice(-50),
      notifications, unreadCount,
      socialScore,
      pairs,
      globalFeed: feed,
    });
  });

  socket.on("get-notifications", async () => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const notifications = await dbGetNotifications(userData.name);
    const unreadCount = await dbGetUnreadCount(userData.name);
    socket.emit("notifications", { notifications, unreadCount });
  });

  socket.on("mark-notifications-read", async () => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    await dbMarkNotificationsRead(userData.name);
  });

  // E2E encryption key exchange
  socket.on("register-pubkey", async ({ publicKey }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    // Validate P-256 ECDH public key format
    if (!publicKey || typeof publicKey !== "object" || publicKey.kty !== "EC" || publicKey.crv !== "P-256" || !publicKey.x || !publicKey.y) return;
    // Strip any private key fields if accidentally included
    const safePubKey = { kty: publicKey.kty, crv: publicKey.crv, x: publicKey.x, y: publicKey.y };
    userData.publicKey = safePubKey;
    await dbSetPublicKey(userData.name, safePubKey);
    broadcastUserList();
  });

  // E2E key backup for X/guest users (cross-device recovery)
  socket.on("backup-e2e-key", async ({ e2eKey }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (!e2eKey || typeof e2eKey !== "string" || e2eKey.length > 5000) return;
    const profile = await dbGetProfile(userData.name);
    profile.e2eKey = e2eKey;
    await dbSetProfile(userData.name, profile);
  });

  socket.on("get-e2e-backup", async () => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const profile = await dbGetProfile(userData.name);
    socket.emit("e2e-backup", { e2eKey: profile.e2eKey || null });
  });

  // App wallet backup/restore
  socket.on("backup-app-wallet", async ({ wallet }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (!wallet || typeof wallet !== "string" || wallet.length > 5000) return;
    const profile = await dbGetProfile(userData.name);
    profile.appWallet = wallet;
    await dbSetProfile(userData.name, profile);
  });

  socket.on("get-app-wallet", async () => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const profile = await dbGetProfile(userData.name);
    socket.emit("app-wallet", { wallet: profile.appWallet || null });
  });

  // Register app wallet address (so others can tip)
  socket.on("register-app-wallet", async ({ address }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (!address || !/^0x[0-9a-fA-F]{40}$/.test(address)) return;
    userData.appWalletAddress = address.toLowerCase();
    // Store in directory for discoverability
    const profile = await dbGetProfile(userData.name);
    profile.appWalletAddress = address.toLowerCase();
    await dbSetProfile(userData.name, profile);
    broadcastUserList();
  });

  socket.on("get-pubkey", async ({ peerName }) => {
    if (!socket.userId || !onlineUsers.has(socket.userId)) return;
    if (!peerName) return;
    const key = peerName.toLowerCase().trim();
    // Check online users first
    for (const [, d] of onlineUsers) {
      if (d.name.toLowerCase() === key && d.publicKey) {
        socket.emit("peer-pubkey", { peerName, publicKey: d.publicKey });
        return;
      }
    }
    // Fallback to DB
    const pubKey = await dbGetPublicKey(key);
    socket.emit("peer-pubkey", { peerName, publicKey: pubKey });
  });

  // Poke — lightweight nudge
  // ── Group chats ──────────────────────────────────────────────────────────
  socket.on("create-group", async ({ name, inviteNames, avatar }) => {
    if (!rateLimit(socket, "create-group", 3, 60_000)) return;
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (!name || typeof name !== "string") return;
    const groupName = name.trim().slice(0, 50);
    if (!groupName) return;
    const safeAvatar = (avatar && typeof avatar === "string" && avatar.length <= MAX_AVATAR_BYTES) ? avatar : null;
    const groupId = uuidv4().slice(0, 12);
    await dbCreateGroup(groupId, groupName, userData.name.toLowerCase().trim(), safeAvatar);
    // Send invites
    if (Array.isArray(inviteNames)) {
      for (const invName of inviteNames.slice(0, 100)) {
        if (typeof invName !== "string") continue;
        const targetKey = invName.toLowerCase().trim();
        if (targetKey === userData.name.toLowerCase().trim()) continue;
        await dbAddGroupMember(groupId, targetKey, "pending"); // track invite
        await dbCreateNotification(targetKey, "group_invite", userData.name, groupId, groupName);
        emitNotification(targetKey, { type: "group_invite", fromUser: userData.name, groupId, groupName, preview: groupName });
      }
    }
    socket.emit("group-created", { groupId, name: groupName });
  });

  socket.on("accept-group-invite", async ({ groupId }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const group = await dbGetGroup(groupId);
    if (!group) { socket.emit("group-error", { message: "Group not found" }); return; }
    const members = await dbGetGroupMembers(groupId);
    const myKey = userData.name.toLowerCase().trim();
    const existing = members.find(m => m.userName === myKey);
    if (existing && existing.role !== "pending") { socket.emit("group-error", { message: "Already a member" }); return; }
    if (!existing) { socket.emit("group-error", { message: "No invite found" }); return; }
    if (members.filter(m => m.role !== "pending").length >= 100) { socket.emit("group-error", { message: "Group is full" }); return; }
    // Upgrade from pending to member
    await dbAddGroupMember(groupId, userData.name, "member");
    // Notify all members
    for (const m of members) {
      for (const [uid, d] of onlineUsers) {
        if (d.name.toLowerCase() === m.userName && !d.disconnectedAt) {
          const s = getSocketByUserId(uid);
          if (s) s.emit("group-member-joined", { groupId, userName: userData.name });
          break;
        }
      }
    }
    socket.emit("group-joined", { groupId, name: group.name });
  });

  socket.on("leave-group", async ({ groupId }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    await dbRemoveGroupMember(groupId, userData.name);
    socket.emit("group-left", { groupId });
    // Notify members
    const members = await dbGetGroupMembers(groupId);
    for (const m of members) {
      for (const [uid, d] of onlineUsers) {
        if (d.name.toLowerCase() === m.userName && !d.disconnectedAt) {
          const s = getSocketByUserId(uid);
          if (s) s.emit("group-member-left", { groupId, userName: userData.name });
          break;
        }
      }
    }
  });

  socket.on("group-invite", async ({ groupId, userName }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const group = await dbGetGroup(groupId);
    if (!group) return;
    const members = await dbGetGroupMembers(groupId);
    const me = members.find(m => m.userName === userData.name.toLowerCase().trim());
    if (!me || me.role !== "admin") { socket.emit("group-error", { message: "Only admin can invite" }); return; }
    if (members.length >= 100) { socket.emit("group-error", { message: "Group is full" }); return; }
    const targetKey = (userName || "").toLowerCase().trim();
    const existingMember = members.find(m => m.userName === targetKey);
    if (existingMember && existingMember.role !== "pending") return; // already member
    await dbAddGroupMember(groupId, targetKey, "pending"); // track invite
    await dbCreateNotification(targetKey, "group_invite", userData.name, groupId, group.name);
    emitNotification(targetKey, { type: "group_invite", fromUser: userData.name, groupId, groupName: group.name, preview: group.name });
  });

  socket.on("group-remove-member", async ({ groupId, userName }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const members = await dbGetGroupMembers(groupId);
    const me = members.find(m => m.userName === userData.name.toLowerCase().trim());
    if (!me || me.role !== "admin") { socket.emit("group-error", { message: "Only admin can remove members" }); return; }
    const targetKey = (userName || "").toLowerCase().trim();
    if (targetKey === userData.name.toLowerCase().trim()) return; // can't remove self
    await dbRemoveGroupMember(groupId, targetKey);
    // Notify removed user
    for (const [uid, d] of onlineUsers) {
      if (d.name.toLowerCase() === targetKey && !d.disconnectedAt) {
        const s = getSocketByUserId(uid);
        if (s) s.emit("group-removed", { groupId });
        break;
      }
    }
  });

  socket.on("delete-group", async ({ groupId }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const group = await dbGetGroup(groupId);
    if (!group || group.creator !== userData.name.toLowerCase().trim()) { socket.emit("group-error", { message: "Only creator can delete" }); return; }
    const members = await dbGetGroupMembers(groupId);
    await dbDeleteGroup(groupId);
    // Notify all members
    for (const m of members) {
      for (const [uid, d] of onlineUsers) {
        if (d.name.toLowerCase() === m.userName && !d.disconnectedAt) {
          const s = getSocketByUserId(uid);
          if (s) s.emit("group-deleted", { groupId });
          break;
        }
      }
    }
  });

  socket.on("get-my-groups", async () => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const groups = await dbGetUserGroups(userData.name);
    // Enrich with last message and member count
    const enriched = await Promise.all(groups.map(async (g) => {
      const [members, lastMsg] = await Promise.all([dbGetGroupMembers(g.id), dbGetGroupLastMsg(g.id)]);
      return { ...g, memberCount: members.length, lastMessage: lastMsg?.text?.slice(0, 50) || null, lastSender: lastMsg?.senderName || null, lastTime: lastMsg?.ts || g.createdAt };
    }));
    socket.emit("my-groups", enriched.sort((a, b) => (b.lastTime || 0) - (a.lastTime || 0)));
  });

  socket.on("get-group-info", async ({ groupId }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const members = await dbGetGroupMembers(groupId);
    if (!members.find(m => m.userName === userData.name.toLowerCase().trim() && m.role !== "pending")) { socket.emit("group-error", { message: "Not a member" }); return; }
    const group = await dbGetGroup(groupId);
    if (!group) return;
    // Enrich members with avatars
    const enrichedMembers = await Promise.all(members.map(async (m) => {
      const avatar = await dbGetAvatar(m.userName);
      return { ...m, avatar: avatar || null };
    }));
    socket.emit("group-info", { ...group, members: enrichedMembers });
  });

  socket.on("group-chat", async ({ groupId, text, image }) => {
    if (!rateLimit(socket, "group-chat", 10, 10_000)) return;
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const members = await dbGetGroupMembers(groupId);
    if (!members.find(m => m.userName === userData.name.toLowerCase().trim() && m.role !== "pending")) return;
    const trimmed = (text || "").trim().slice(0, 500);
    const safeImage = (image && typeof image === "string" && image.startsWith("data:image/") && image.length <= 500_000) ? image : null;
    if (!trimmed && !safeImage) return;
    const msg = { id: uuidv4().slice(0, 10), sender: userData.name.toLowerCase().trim(), senderName: userData.name, text: trimmed, image: safeImage, ts: Date.now() };
    dbSaveGroupMsg(groupId, msg);
    // Broadcast to all online members
    for (const m of members) {
      for (const [uid, d] of onlineUsers) {
        if (d.name.toLowerCase() === m.userName && !d.disconnectedAt) {
          const s = getSocketByUserId(uid);
          if (s) s.emit("group-chat", { groupId, ...msg, avatar: userData.avatar || null });
          break;
        }
      }
    }
  });

  socket.on("group-history", async ({ groupId, limit, before }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const members = await dbGetGroupMembers(groupId);
    if (!members.find(m => m.userName === userData.name.toLowerCase().trim() && m.role !== "pending")) return;
    const safeLimit = Math.min(Math.max(parseInt(limit) || 50, 1), 100);
    const safeBefore = typeof before === "number" ? before : null;
    const messages = await dbLoadGroupMsgs(groupId, safeLimit, safeBefore);
    socket.emit("group-history", { groupId, messages, hasMore: messages.length === safeLimit });
  });

  socket.on("rename-group", async ({ groupId, name }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const group = await dbGetGroup(groupId);
    if (!group) return;
    const members = await dbGetGroupMembers(groupId);
    const me = members.find(m => m.userName === userData.name.toLowerCase().trim());
    if (!me || me.role !== "admin") { socket.emit("group-error", { message: "Only admin can rename" }); return; }
    const newName = (name || "").trim().slice(0, 50);
    if (!newName) return;
    if (supabase) {
      try { await supabase.from("group_chats").update({ name: newName }).eq("id", groupId); } catch {}
    } else {
      const groups = jsonGet("group_chats", "_all");
      let list; try { list = groups ? JSON.parse(groups) : []; } catch { list = []; }
      const g = list.find(g => g.id === groupId);
      if (g) { g.name = newName; jsonSet("group_chats", "_all", JSON.stringify(list)); }
    }
    // Notify all members
    for (const m of members) {
      for (const [uid, d] of onlineUsers) {
        if (d.name.toLowerCase() === m.userName && !d.disconnectedAt) {
          const s = getSocketByUserId(uid);
          if (s) s.emit("group-renamed", { groupId, name: newName });
          break;
        }
      }
    }
  });

  // ── Token-gated rooms ────────────────────────────────────────────────────
  socket.on("create-gated-room", async ({ name, tokenAddress, tokenType, minBalance, avatar }) => {
    if (!rateLimit(socket, "create-gated-room", 3, 60_000)) return;
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (!name || typeof name !== "string" || !tokenAddress || !/^0x[0-9a-fA-F]{40}$/.test(tokenAddress)) return;
    const roomName = name.trim().slice(0, 50);
    const type = tokenType === "NFT" ? "NFT" : "ERC20";
    const minBal = (minBalance && /^\d+$/.test(minBalance) && BigInt(minBalance) > 0n) ? minBalance : "1";
    const safeAvatar = (avatar && typeof avatar === "string" && avatar.length <= MAX_AVATAR_BYTES) ? avatar : null;
    const roomId = uuidv4().slice(0, 12);
    const creatorWallet = userData.walletAddress || userData.appWalletAddress || "creator";
    await dbCreateGatedRoom(roomId, roomName, userData.name.toLowerCase().trim(), tokenAddress.toLowerCase(), type, minBal, safeAvatar, creatorWallet);
    socket.emit("gated-room-created", { roomId, name: roomName });
  });

  socket.on("get-gated-room-info", async ({ roomId }) => {
    if (!roomId) return;
    const room = await dbGetGatedRoom(roomId);
    if (!room) { socket.emit("gated-room-error", { message: "Room not found" }); return; }
    const members = await dbGetGatedRoomMembers(roomId);
    socket.emit("gated-room-info", { ...room, memberCount: members.length });
  });

  socket.on("join-gated-room", async ({ roomId, walletAddress, walletSignature, walletNonce }) => {
    if (!rateLimit(socket, "join-gated-room", 5, 30_000)) return;
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (!roomId || !walletAddress || !/^0x[0-9a-fA-F]{40}$/.test(walletAddress)) return;
    const addr = walletAddress.toLowerCase();
    const room = await dbGetGatedRoom(roomId);
    if (!room) { socket.emit("gated-room-error", { message: "Room not found" }); return; }
    const members = await dbGetGatedRoomMembers(roomId);
    const myKey = userData.name.toLowerCase().trim();
    if (members.find(m => m.userName === myKey)) {
      socket.emit("gated-room-joined", { roomId, name: room.name });
      return;
    }
    // Verify wallet ownership: must be linked wallet, app wallet, or signed proof
    const isLinkedWallet = userData.walletAddress && userData.walletAddress === addr;
    const isAppWallet = userData.appWalletAddress && userData.appWalletAddress === addr;
    const isDbWallet = !isLinkedWallet && !isAppWallet && (await dbGetWallet(myKey)) === addr;
    let isSignedProof = false;
    if (!isLinkedWallet && !isAppWallet && !isDbWallet) {
      // Require signature verification
      if (walletSignature && walletNonce) {
        isSignedProof = verifyWalletSignature(addr, walletSignature, walletNonce);
      }
      if (!isSignedProof) {
        socket.emit("gated-room-error", { message: "Wallet ownership not verified. Link your wallet or sign to prove ownership." });
        return;
      }
    }
    // Server-side token balance check
    const balance = await checkTokenBalance(room.tokenAddress, room.tokenType, addr);
    if (balance === null) {
      socket.emit("gated-room-error", { message: "Token check failed — try again in a moment" });
      return;
    }
    const minRequired = BigInt(room.minBalance);
    if (balance < minRequired) {
      const needed = room.tokenType === "NFT" ? `${minRequired} NFT(s)` : `${minRequired} tokens`;
      socket.emit("gated-room-error", { message: `Insufficient balance. Need ${needed}.` });
      return;
    }
    await dbAddGatedRoomMember(roomId, userData.name, addr);
    socket.emit("gated-room-joined", { roomId, name: room.name });
    // Notify existing members
    for (const m of members) {
      for (const [uid, d] of onlineUsers) {
        if (d.name.toLowerCase() === m.userName && !d.disconnectedAt) {
          const s = getSocketByUserId(uid);
          if (s) s.emit("gated-room-member-joined", { roomId, userName: userData.name });
          break;
        }
      }
    }
  });

  socket.on("leave-gated-room", async ({ roomId }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    await dbRemoveGatedRoomMember(roomId, userData.name);
    socket.emit("gated-room-left", { roomId });
  });

  socket.on("delete-gated-room", async ({ roomId }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const room = await dbGetGatedRoom(roomId);
    if (!room || room.creator !== userData.name.toLowerCase().trim()) { socket.emit("gated-room-error", { message: "Only creator can delete" }); return; }
    const members = await dbGetGatedRoomMembers(roomId);
    await dbDeleteGatedRoom(roomId);
    for (const m of members) {
      for (const [uid, d] of onlineUsers) {
        if (d.name.toLowerCase() === m.userName && !d.disconnectedAt) {
          const s = getSocketByUserId(uid);
          if (s) s.emit("gated-room-deleted", { roomId });
          break;
        }
      }
    }
  });

  socket.on("gated-room-kick", async ({ roomId, userName }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const room = await dbGetGatedRoom(roomId);
    if (!room || room.creator !== userData.name.toLowerCase().trim()) return;
    const targetKey = (userName || "").toLowerCase().trim();
    if (targetKey === room.creator) return;
    await dbRemoveGatedRoomMember(roomId, targetKey);
    for (const [uid, d] of onlineUsers) {
      if (d.name.toLowerCase() === targetKey && !d.disconnectedAt) {
        const s = getSocketByUserId(uid);
        if (s) s.emit("gated-room-kicked", { roomId });
        break;
      }
    }
  });

  socket.on("get-my-gated-rooms", async () => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const rooms = await dbGetUserGatedRooms(userData.name);
    const enriched = await Promise.all(rooms.map(async (r) => {
      const [members, lastMsg] = await Promise.all([dbGetGatedRoomMembers(r.id), dbGetGatedRoomLastMsg(r.id)]);
      return { ...r, memberCount: members.length, lastMessage: lastMsg?.text?.slice(0, 50) || null, lastSender: lastMsg?.senderName || null, lastTime: lastMsg?.ts || r.createdAt };
    }));
    socket.emit("my-gated-rooms", enriched.sort((a, b) => (b.lastTime || 0) - (a.lastTime || 0)));
  });

  socket.on("gated-room-chat", async ({ roomId, text, image }) => {
    if (!rateLimit(socket, "gated-room-chat", 10, 10_000)) return;
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const members = await dbGetGatedRoomMembers(roomId);
    if (!members.find(m => m.userName === userData.name.toLowerCase().trim())) return;
    const trimmed = (text || "").trim().slice(0, 500);
    const safeImage = (image && typeof image === "string" && image.startsWith("data:image/") && image.length <= 500_000) ? image : null;
    if (!trimmed && !safeImage) return;
    const msg = { id: uuidv4().slice(0, 10), sender: userData.name.toLowerCase().trim(), senderName: userData.name, text: trimmed, image: safeImage, ts: Date.now() };
    dbSaveGatedRoomMsg(roomId, msg);
    for (const m of members) {
      for (const [uid, d] of onlineUsers) {
        if (d.name.toLowerCase() === m.userName && !d.disconnectedAt) {
          const s = getSocketByUserId(uid);
          if (s) s.emit("gated-room-chat", { roomId, ...msg, avatar: userData.avatar || null });
          break;
        }
      }
    }
  });

  socket.on("gated-room-history", async ({ roomId, limit, before }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const members = await dbGetGatedRoomMembers(roomId);
    if (!members.find(m => m.userName === userData.name.toLowerCase().trim())) return;
    const safeLimit = Math.min(Math.max(parseInt(limit) || 50, 1), 100);
    const safeBefore = typeof before === "number" ? before : null;
    const messages = await dbLoadGatedRoomMsgs(roomId, safeLimit, safeBefore);
    socket.emit("gated-room-history", { roomId, messages, hasMore: messages.length === safeLimit });
  });

  socket.on("poke", async ({ toUserId }) => {
    if (!rateLimit(socket, "poke", 3, 30_000)) return; // 3 pokes per 30s
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const target = onlineUsers.get(toUserId); if (!target || target.disconnectedAt) return;
    const ts = getSocketByUserId(toUserId);
    if (ts) ts.emit("poke", { fromUserId: userId, fromName: userData.name, fromAvatar: userData.avatar || null });
    // Poke notification
    const notif = await dbCreateNotification(target.name, "poke", userData.name, null, null);
    emitNotification(target.name, notif);
  });

  // Tip notification (unverified — no on-chain check)
  socket.on("tip-sent", async ({ toName, amount, txHash }) => {
    if (!rateLimit(socket, "tip", 3, 60_000)) return; // 3 tips per minute
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (!toName || !amount || !txHash || typeof txHash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(txHash)) return;
    const preview = `${amount} ETH`;
    const notif = await dbCreateNotification(toName, "tip", userData.name, null, preview);
    emitNotification(toName, notif);
  });

  // ── Call rate (sell your time) ──────────────────────────────────────────
  socket.on("set-call-rate", async ({ rate }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    // rate is wei per second as a string, or null to clear
    const safeRate = (rate && /^\d+$/.test(rate) && BigInt(rate) > 0n) ? rate : null;
    const profile = await dbGetProfile(userData.name);
    profile.callRate = safeRate;
    await dbSetProfile(userData.name, profile);
    socket.emit("call-rate-set", { callRate: safeRate });
    broadcastUserList();
  });

  socket.on("buy-time", async ({ toName, seconds, amount, txHash }) => {
    if (!rateLimit(socket, "buy-time", 3, 60_000)) return;
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (!toName || typeof toName !== "string") return;
    const targetKey = toName.toLowerCase().trim().slice(0, 60);
    // Can't buy time with yourself
    if (targetKey === userData.name.toLowerCase().trim()) return;
    if (!seconds || typeof seconds !== "number" || seconds < 1 || seconds > 36000) return;
    if (!amount || !txHash || typeof txHash !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(txHash)) return;
    // Verify the target exists and has a call rate
    const targetProfile = await dbGetProfile(targetKey);
    if (!targetProfile.callRate) { socket.emit("buy-time-error", { message: "This user hasn't set a call rate" }); return; }
    // Sanity check: verify amount ≈ seconds × rate
    const secs = Math.floor(seconds);
    try {
      const rateWei = BigInt(targetProfile.callRate);
      const expectedWei = rateWei * BigInt(secs);
      const claimedWei = ethers.parseEther(amount);
      // Allow 1% tolerance for rounding
      const diff = claimedWei > expectedWei ? claimedWei - expectedWei : expectedWei - claimedWei;
      if (diff > expectedWei / 100n && diff > ethers.parseEther("0.0001")) {
        socket.emit("buy-time-error", { message: "Amount doesn't match the rate" }); return;
      }
    } catch { socket.emit("buy-time-error", { message: "Invalid amount" }); return; }
    // Add credits to the pair
    await dbAddPairCredit(userData.name, targetKey, secs);
    const pairInfo = await dbGetPairMeetings(userData.name, targetKey);
    // Notify the seller
    const preview = `${amount} ETH for ${secs}s call time`;
    const notif = await dbCreateNotification(targetKey, "tip", userData.name, null, preview);
    emitNotification(targetKey, notif);
    socket.emit("time-purchased", { toName: targetKey, seconds: secs, creditSeconds: pairInfo.creditSeconds || 0 });
  });

  // Stream/call tip — broadcast to all participants
  socket.on("stream-tip", async ({ streamId, amount, txHash, message }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (!streamId || !amount || !txHash || isNaN(parseFloat(amount)) || parseFloat(amount) <= 0) return;
    const stream = activeStreams.get(streamId); if (!stream) return;
    const tipMsg = { type: "tip", sender: userData.name, avatar: userData.avatar || null, amount, message: (message || "").slice(0, 100), txHash };
    // Broadcast to streamer + all viewers
    const ss = getSocketByUserId(stream.streamerId);
    if (ss) ss.emit("stream-tip-event", { streamId, ...tipMsg });
    for (const vid of stream.viewers) {
      const vs = getSocketByUserId(vid);
      if (vs) vs.emit("stream-tip-event", { streamId, ...tipMsg });
    }
    // Also create notification for streamer
    const streamerData = onlineUsers.get(stream.streamerId);
    if (streamerData) {
      const notif = await dbCreateNotification(streamerData.name, "tip", userData.name, null, `${amount} ETH`);
      emitNotification(streamerData.name, notif);
    }
  });

  // Call tip — notify the other participant
  socket.on("call-tip", async ({ callId, amount, txHash, message }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (!callId || !amount || !txHash || isNaN(parseFloat(amount)) || parseFloat(amount) <= 0) return;
    const call = activeCalls.get(callId); if (!call) return;
    const otherId = call.callerId === userId ? call.calleeId : call.callerId;
    const otherData = onlineUsers.get(otherId);
    const tipMsg = { type: "tip", sender: userData.name, avatar: userData.avatar || null, amount, message: (message || "").slice(0, 100), txHash };
    const os = getSocketByUserId(otherId);
    if (os) os.emit("call-tip-event", { callId, ...tipMsg });
    // Echo to sender
    socket.emit("call-tip-event", { callId, ...tipMsg });
    // Notification
    if (otherData) {
      const notif = await dbCreateNotification(otherData.name, "tip", userData.name, null, `${amount} ETH`);
      emitNotification(otherData.name, notif);
    }
  });

  socket.on("call-request", async ({ targetName }) => {
    if (!rateLimit(socket, "call-request", 3, 60_000)) return;
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (!targetName || typeof targetName !== "string") return;
    const key = targetName.toLowerCase().trim();
    // Check if target is actually online
    for (const [tId, tData] of onlineUsers) {
      if (tData.name.toLowerCase() === key && !tData.disconnectedAt) {
        // They're online — tell the client to call normally
        socket.emit("call-request-online", { userId: tId, name: tData.name, avatar: tData.avatar || null });
        return;
      }
    }
    // Offline — create notification
    const notif = await dbCreateNotification(key, "call_request", userData.name, null, null);
    emitNotification(key, notif);
    socket.emit("call-request-sent", { targetName });
  });

  socket.on("call-user", async ({ calleeId, prepaidSeconds }) => {
    if (!rateLimit(socket, "call-user", 3, 10_000)) return; // 3 calls per 10s
    const callerId = socket.userId; if (!callerId) return;
    const caller = onlineUsers.get(callerId); if (!caller) return;
    const callee = onlineUsers.get(calleeId);
    if (!callee || callee.disconnectedAt || callee.status === "invisible") {
      const calleeName = callee?.name || [...takenNames.entries()].find(([, uid]) => uid === calleeId)?.[0] || null;
      if (calleeName) {
        const notif = await dbCreateNotification(calleeName, "call_request", caller.name, null, null);
        emitNotification(calleeName, notif);
        socket.emit("call-error", { message: `${calleeName} is offline — they'll get a notification to call you back` });
      } else {
        socket.emit("call-error", { message: "User is offline" });
      }
      return;
    }
    if (isUserInCall(calleeId) || isUserStreaming(calleeId)) { socket.emit("call-error", { message: `${callee.name} is busy` }); return; }
    if (isUserInCall(callerId) || isUserStreaming(callerId)) { socket.emit("call-error", { message: "You're already in a call or stream" }); return; }

    // Validate prepaid seconds against pair credit
    let validPrepaid = 0;
    if (prepaidSeconds && typeof prepaidSeconds === "number" && prepaidSeconds > 0) {
      const pairInfo = await dbGetPairMeetings(caller.name, callee.name);
      validPrepaid = Math.min(Math.floor(prepaidSeconds), pairInfo.creditSeconds || 0, 3600); // cap at 1hr
    }

    const callId = uuidv4().slice(0, 12);
    const calleeName = callee.name;
    const ringTimerId = setTimeout(async () => {
      const call = activeCalls.get(callId);
      if (call && !call.startedAt) {
        await recordCallOutcome(calleeName, "missed");
        await refreshUserStats(calleeId);
        socket.emit("call-not-answered", { callId });
        const cs = getSocketByUserId(calleeId); if (cs) cs.emit("call-cancelled", { callId });
        cleanupCall(callId);
      }
    }, RING_TIMEOUT_MS);

    const totalDuration = CALL_DURATION_MS + (validPrepaid * 1000);
    activeCalls.set(callId, { callerId, calleeId, startedAt: null, timerId: null, ringTimerId, prepaidSeconds: validPrepaid, totalDurationMs: totalDuration });
    const cs = getSocketByUserId(calleeId);
    const callDurationLabel = Math.round(totalDuration / 1000);
    if (cs) cs.emit("incoming-call", { callId, callerId, callerName: caller.name, callerAvatar: caller.avatar || null, callerXUsername: caller.xUsername || null, callerWalletAddress: caller.walletAddress || null, duration: callDurationLabel });
    socket.emit("call-ringing", { callId, calleeId, calleeName: callee.name, calleeAvatar: callee.avatar || null, duration: callDurationLabel });
  });

  socket.on("accept-call", async ({ callId }) => {
    const call = activeCalls.get(callId); if (!call) return;
    clearTimeout(call.ringTimerId); call.startedAt = Date.now();
    const callee = onlineUsers.get(call.calleeId);
    const caller = onlineUsers.get(call.callerId);
    const isPrivate = !!call.privateRoom;

    if (isPrivate) {
      if (callee) { const cs = await dbGetStats(callee.name); cs.totalMeets++; await dbSetStats(callee.name, cs); await refreshUserStats(call.calleeId); }
      if (caller) { const cs = await dbGetStats(caller.name); cs.totalMeets++; await dbSetStats(caller.name, cs); await refreshUserStats(call.callerId); }
    } else {
      if (callee) { await recordCallOutcome(callee.name, "accepted"); await refreshUserStats(call.calleeId); }
      if (caller) { const cs = await dbGetStats(caller.name); cs.totalMeets++; await dbSetStats(caller.name, cs); await refreshUserStats(call.callerId); }
      if (caller && callee) await dbSetLastCall(caller.name, callee.name);
    }

    // Deduct prepaid credits on accept (not on ring — refunded if missed/declined)
    if (call.prepaidSeconds > 0 && caller && callee && !isPrivate) {
      const spent = await dbSpendPairCredit(caller.name, callee.name, call.prepaidSeconds);
      if (!spent) { call.prepaidSeconds = 0; call.totalDurationMs = CALL_DURATION_MS; } // fallback to 1 min if credit vanished
    }

    const callDuration = call.totalDurationMs || CALL_DURATION_MS;
    call.timerId = setTimeout(async () => {
      const callerData = onlineUsers.get(call.callerId);
      const calleeData = onlineUsers.get(call.calleeId);
      if (!isPrivate) {
        // Award 30 seconds credit to both users for completing the meeting
        if (callerData) { const cs = await dbGetStats(callerData.name); cs.creditSeconds = (cs.creditSeconds || 0) + 30; await dbSetStats(callerData.name, cs); }
        if (calleeData) { const cs = await dbGetStats(calleeData.name); cs.creditSeconds = (cs.creditSeconds || 0) + 30; await dbSetStats(calleeData.name, cs); }
        // Record pair meeting (earns pair credit)
        if (callerData && calleeData) dbRecordPairMeeting(callerData.name, calleeData.name);
      }
      // Private calls: NO pair meeting record — no trace of who met whom
      const s1 = getSocketByUserId(call.callerId); const s2 = getSocketByUserId(call.calleeId);
      const earned = isPrivate ? 0 : 30;
      if (s1) s1.emit("call-timeout", { callId, creditEarned: earned }); if (s2) s2.emit("call-timeout", { callId, creditEarned: earned });
      cleanupCall(callId);
    }, callDuration);
    // Notify both participants of accepted call + duration
    const durationSecs = Math.round(callDuration / 1000);
    const s1 = getSocketByUserId(call.callerId); if (s1 && s1.id !== socket.id) s1.emit("call-accepted", { callId, duration: durationSecs });
    const s2a = getSocketByUserId(call.calleeId); if (s2a && s2a.id !== socket.id) s2a.emit("call-accepted", { callId, duration: durationSecs });
    socket.emit("call-accepted", { callId, duration: durationSecs });
  });

  socket.on("decline-call", async ({ callId }) => {
    const call = activeCalls.get(callId); if (!call) return;
    const callee = onlineUsers.get(call.calleeId);
    // Skip stats for private calls (no DB footprint)
    if (callee && !call.privateRoom) { await recordCallOutcome(callee.name, "declined"); await refreshUserStats(call.calleeId); }
    const s = getSocketByUserId(call.callerId); if (s) s.emit("call-declined", { callId });
    cleanupCall(callId);
  });

  socket.on("extend-call", async ({ callId, seconds }) => {
    if (!rateLimit(socket, "extend", 2, 5_000)) return; // max 2 extends per 5s
    const userId = socket.userId; if (!userId) return;
    const call = activeCalls.get(callId); if (!call || !call.startedAt) return;
    if (call.privateRoom) { socket.emit("extend-error", { message: "Private calls cannot be extended" }); return; }
    const userData = onlineUsers.get(userId); if (!userData) return;
    const secs = Math.min(Math.max(parseInt(seconds) || 30, 10), 300); // 10-300 seconds
    // Find the other user in this call
    const otherUserId = call.callerId === userId ? call.calleeId : call.callerId;
    const otherData = onlineUsers.get(otherUserId);
    if (!otherData) { socket.emit("extend-error", { message: "Other user disconnected" }); return; }
    // Check pair credit
    const pairInfo = await dbGetPairMeetings(userData.name, otherData.name);
    if ((pairInfo.creditSeconds || 0) < secs) {
      socket.emit("extend-error", { message: `Not enough pair credit (${pairInfo.creditSeconds || 0}s available with ${otherData.name})` });
      return;
    }
    // Deduct from pair credit
    const spent = await dbSpendPairCredit(userData.name, otherData.name, secs);
    if (!spent) { socket.emit("extend-error", { message: "Credit deduction failed" }); return; }
    // Extend the timer — track total allowed duration
    if (call.timerId) clearTimeout(call.timerId);
    if (!call.totalDurationMs) call.totalDurationMs = CALL_DURATION_MS;
    call.totalDurationMs += secs * 1000;
    const elapsed = Date.now() - call.startedAt;
    const remaining = call.totalDurationMs - elapsed;
    call.timerId = setTimeout(async () => {
      const callerData = onlineUsers.get(call.callerId);
      const calleeData = onlineUsers.get(call.calleeId);
      // Award 30s pair credit (not per-user — prevents farming with fake accounts)
      if (callerData && calleeData) await dbRecordPairMeeting(callerData.name, calleeData.name, 30);
      const s1 = getSocketByUserId(call.callerId); const s2 = getSocketByUserId(call.calleeId);
      if (s1) s1.emit("call-timeout", { callId, creditEarned: 30 }); if (s2) s2.emit("call-timeout", { callId, creditEarned: 30 });
      cleanupCall(callId);
    }, Math.max(remaining, 0));
    // Notify both users
    const s1 = getSocketByUserId(call.callerId); const s2 = getSocketByUserId(call.calleeId);
    const remainingCredit = (pairInfo.creditSeconds || 0) - secs;
    if (s1) s1.emit("call-extended", { callId, addedSeconds: secs, byUser: userData.name, pairCreditRemaining: remainingCredit });
    if (s2) s2.emit("call-extended", { callId, addedSeconds: secs, byUser: userData.name, pairCreditRemaining: remainingCredit });
  });

  socket.on("end-call", ({ callId }) => {
    const call = activeCalls.get(callId); if (!call) return;
    const dur = call.startedAt ? Math.floor((Date.now() - call.startedAt) / 1000) : 0;
    const oid = call.callerId === socket.userId ? call.calleeId : call.callerId;
    const os = getSocketByUserId(oid); if (os) os.emit("call-ended", { callId, duration: dur });
    socket.emit("call-ended", { callId, duration: dur });
    cleanupCall(callId);
  });

  socket.on("webrtc-offer", ({ callId, sdp }) => { const c = activeCalls.get(callId); if (!c) return; if (c.callerId !== socket.userId && c.calleeId !== socket.userId) return; const t = c.callerId === socket.userId ? c.calleeId : c.callerId; const s = getSocketByUserId(t); if (s) s.emit("webrtc-offer", { callId, sdp }); });
  socket.on("webrtc-answer", ({ callId, sdp }) => { const c = activeCalls.get(callId); if (!c) return; if (c.callerId !== socket.userId && c.calleeId !== socket.userId) return; const t = c.callerId === socket.userId ? c.calleeId : c.callerId; const s = getSocketByUserId(t); if (s) s.emit("webrtc-answer", { callId, sdp }); });
  socket.on("webrtc-ice-candidate", ({ callId, candidate }) => { const c = activeCalls.get(callId); if (!c) return; if (c.callerId !== socket.userId && c.calleeId !== socket.userId) return; const t = c.callerId === socket.userId ? c.calleeId : c.callerId; const s = getSocketByUserId(t); if (s) s.emit("webrtc-ice-candidate", { callId, candidate }); });

  // Video toggle relay
  socket.on("video-toggle", ({ callId, videoOff }) => { const c = activeCalls.get(callId); if (!c) return; if (c.callerId !== socket.userId && c.calleeId !== socket.userId) return; const t = c.callerId === socket.userId ? c.calleeId : c.callerId; const s = getSocketByUserId(t); if (s) s.emit("video-toggle", { callId, videoOff }); });

  // ── Private Rooms ──────────────────────────────────────────────────────
  socket.on("create-private-room", () => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const roomId = crypto.randomBytes(16).toString("hex"); // 32-char hex
    privateRooms.set(roomId, { creatorId: userId, creatorName: userData.name, createdAt: Date.now() });
    socket.emit("private-room-created", { roomId });
    console.log(`🔒 Private room ${roomId} created by ${userData.name}`);
  });

  socket.on("join-private-room", async ({ roomId, name, avatar }) => {
    if (!roomId || !privateRooms.has(roomId)) { socket.emit("private-room-error", { message: "Room not found or expired" }); return; }
    const room = privateRooms.get(roomId);
    const userId = socket.userId;
    if (!userId) { socket.emit("private-room-error", { message: "Please register first" }); return; }
    const userData = onlineUsers.get(userId);
    if (!userData) { socket.emit("private-room-error", { message: "Not connected" }); return; }

    // Mark user as in a private room (hides from online list, skips online-time/credit accrual)
    userData.privateRoom = roomId;

    if (userId === room.creatorId) {
      // Creator joining their own room — just wait
      socket.emit("private-room-waiting", { roomId, role: "creator" });
      return;
    }

    // Guest joining — store and notify both
    room.guestId = userId;
    room.guestName = userData.name;

    // Mark creator as private too (in case they weren't already)
    const creatorData = onlineUsers.get(room.creatorId);
    if (creatorData) creatorData.privateRoom = roomId;

    // Auto-initiate call between creator and guest
    const callId = uuidv4().slice(0, 12);
    const ringTimerId = setTimeout(() => {
      const call = activeCalls.get(callId);
      if (call && !call.startedAt) {
        const s1 = getSocketByUserId(room.creatorId); if (s1) s1.emit("call-not-answered", { callId });
        socket.emit("call-not-answered", { callId });
        cleanupCall(callId);
      }
    }, RING_TIMEOUT_MS);

    activeCalls.set(callId, { callerId: room.creatorId, calleeId: userId, startedAt: null, timerId: null, ringTimerId, privateRoom: roomId, prepaidSeconds: 0, totalDurationMs: CALL_DURATION_MS });

    // Notify creator of incoming guest
    const creatorSocket = getSocketByUserId(room.creatorId);
    if (creatorSocket) {
      creatorSocket.emit("private-room-guest-joined", { roomId, callId, guestId: userId, guestName: userData.name, guestAvatar: userData.avatar || null });
      creatorSocket.emit("incoming-call", { callId, callerId: userId, callerName: userData.name, callerAvatar: userData.avatar || null, privateRoom: true });
    }
    // Tell guest to wait for accept
    socket.emit("private-room-calling", { roomId, callId, creatorId: room.creatorId, creatorName: room.creatorName, creatorAvatar: creatorData?.avatar || null });

    // Remove from broadcast since they're private
    broadcastUserList();
  });

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

    userData.disconnectedAt = Date.now();
    // Update last-seen in directory for all users
    dbAddToDirectory(userData.name, { displayName: userData.name, xUsername: userData.xUsername, walletAddress: userData.walletAddress, avatar: userData.avatar });
    broadcastUserList();
    const timer = setTimeout(async () => {
      for (const [callId, call] of activeCalls) {
        if (call.callerId === userId || call.calleeId === userId) {
          const oid = call.callerId === userId ? call.calleeId : call.callerId;
          const os = getSocketByUserId(oid);
          if (os) os.emit("call-ended", { callId, duration: call.startedAt ? Math.floor((Date.now() - call.startedAt) / 1000) : 0 });
          cleanupCall(callId);
        }
      }
      // Flush accumulated online time (only for "online" status, skip private rooms)
      if (userData.connectedAt && userData.status === "online" && !userData.privateRoom) {
        const sessionMs = Date.now() - userData.connectedAt;
        const stats = await dbGetStats(userData.name);
        stats.totalOnlineMs = (stats.totalOnlineMs || 0) + sessionMs;
        await dbSetStats(userData.name, stats);
      }
      // Clean up private room if this user was in one
      if (userData.privateRoom) {
        const room = privateRooms.get(userData.privateRoom);
        if (room) {
          // Notify other participant
          const otherId = room.creatorId === userId ? room.guestId : room.creatorId;
          if (otherId) { const os = getSocketByUserId(otherId); if (os) os.emit("private-room-ended", { roomId: userData.privateRoom }); }
          privateRooms.delete(userData.privateRoom);
        }
      }
      takenNames.delete(userData.name.toLowerCase());
      onlineUsers.delete(userId); disconnectTimers.delete(userId);
      broadcastUserList();
    }, RECONNECT_GRACE_MS);
    disconnectTimers.set(userId, timer);
  });
});

// ─── Directory & stats API ────────────────────────────────────────────────────

async function getFullDirectory() {
  const dir = await dbGetDirectory();
  const dirNames = new Set(dir.map(d => (d.name || "").toLowerCase()));
  // Merge online verified users
  for (const [, data] of onlineUsers) {
    if (data.disconnectedAt) continue;
    // Include all users (verified and guests)
    if (dirNames.has(data.name.toLowerCase())) continue;
    dir.push({ name: data.name, xUsername: data.xUsername || null, walletAddress: data.walletAddress || null, avatar: data.avatar || null, lastSeen: Date.now() });
    dirNames.add(data.name.toLowerCase());
    dbAddToDirectory(data.name, { displayName: data.name, xUsername: data.xUsername, walletAddress: data.walletAddress, avatar: data.avatar });
  }
  // Backfill from x_profiles (users who authenticated before directory existed)
  if (supabase) {
    try {
      const { data: xProfiles } = await supabase.from("x_profiles").select("username, display_name, avatar");
      if (xProfiles) {
        for (const xp of xProfiles) {
          const name = xp.display_name || xp.username;
          if (dirNames.has(name.toLowerCase())) continue;
          const wallet = await dbGetWallet(name);
          dir.push({ name, xUsername: xp.username, walletAddress: wallet || null, avatar: xp.avatar || null, lastSeen: null });
          dirNames.add(name.toLowerCase());
          dbAddToDirectory(name, { displayName: name, xUsername: xp.username, walletAddress: wallet, avatar: xp.avatar });
        }
      }
    } catch {}
  }
  return dir;
}

app.get("/api/directory", async (req, res) => {
  res.json(await getFullDirectory());
});

// Public gated room info (no auth — for gate screen)
app.get("/api/gated-room/:id", async (req, res) => {
  const roomId = (req.params.id || "").replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 20);
  if (!roomId) return res.status(400).json({ error: "Room ID required" });
  const room = await dbGetGatedRoom(roomId);
  if (!room) return res.status(404).json({ error: "Room not found" });
  const members = await dbGetGatedRoomMembers(roomId);
  res.json({ id: room.id, name: room.name, avatar: room.avatar, tokenAddress: room.tokenAddress, tokenType: room.tokenType, minBalance: room.minBalance, memberCount: members.length, creator: room.creator });
});

// Public profile preview (no auth required — for shared profile links)
app.get("/api/profile/:name", async (req, res) => {
  const key = (req.params.name || "").toLowerCase().trim();
  if (!key) return res.status(400).json({ error: "Name required" });
  const [profile, stats, avatar, dirEntry, followers] = await Promise.all([
    dbGetProfile(key), dbGetStats(key), dbGetAvatar(key),
    dbGetDirectoryEntry(key), countFollowers(key, null),
  ]);
  const xUsername = dirEntry?.xUsername || null;
  // Count followers again with xUsername if found
  const totalFollowers = xUsername ? await countFollowers(key, xUsername) : followers;
  const resolvedAvatar = avatar || dirEntry?.avatar || null;
  if (!resolvedAvatar && !profile.bio && !stats.totalMeets && !dirEntry) return res.status(404).json({ error: "User not found" });
  res.json({
    name: dirEntry?.displayName || key,
    avatar: resolvedAvatar,
    bio: profile.bio || null,
    xUsername,
    customStatus: profile.customStatus || null,
    followers: totalFollowers,
    stats: { totalMeets: stats.totalMeets || 0, totalOnlineMs: stats.totalOnlineMs || 0 },
  });
});

app.get("/api/stats", async (req, res) => {
  const dirSize = (await getFullDirectory()).length;
  // Aggregate total meets and posts
  let totalMeets = 0, totalPosts = 0;
  if (supabase) {
    try {
      const { data: meetsData } = await supabase.from("call_stats").select("total_meets");
      if (meetsData) totalMeets = meetsData.reduce((sum, r) => sum + (r.total_meets || 0), 0);
    } catch {}
    try {
      const { count } = await supabase.from("posts").select("id", { count: "exact", head: true }).is("parent_id", null);
      totalPosts = count || 0;
    } catch {}
  } else {
    // JSON fallback
    jsonGet("stats", "_probe"); // trigger load
    const store = jsonStores["stats"] || {};
    for (const val of Object.values(store)) {
      try { const s = JSON.parse(val); totalMeets += s.totalMeets || 0; } catch {}
    }
    const postsStored = jsonGet("posts", "_all");
    try { const posts = postsStored ? JSON.parse(postsStored) : []; totalPosts = posts.filter(p => !p.parentId).length; } catch {}
  }
  const visitors = await dbGetCounter("total_visitors");
  res.json({ totalVisitors: visitors, onlineUsers: onlineUsers.size, registeredUsers: dirSize, totalMeets, totalPosts });
});

// ─── DM conversations list ────────────────────────────────────────────────────

app.get("/api/dm-conversations", async (req, res) => {
  const name = (req.query.name || "").toLowerCase().trim();
  if (!name || name.length < 2) return res.json([]);
  // Auth: require a valid session token matching the requested name
  const token = req.query.token || req.headers["x-session-token"];
  if (!token) return res.status(401).json({ error: "Authentication required" });
  const storedHash = await dbGetSessionToken(name);
  if (!storedHash || hashToken(token) !== storedHash) {
    return res.status(403).json({ error: "Invalid session" });
  }
  if (supabase) {
    try {
      // Use parameterized .like() queries instead of .or() with string interpolation
      // to avoid PostgREST filter injection via special chars in names
      const safeName = name.replace(/[%_\\]/g, "\\$&"); // escape LIKE wildcards only
      const [{ data: d1 }, { data: d2 }] = await Promise.all([
        supabase.from("direct_messages").select("pair, text, encrypted, created_at").like("pair", `${safeName}:%`).order("created_at", { ascending: false }).limit(100),
        supabase.from("direct_messages").select("pair, text, encrypted, created_at").like("pair", `%:${safeName}`).order("created_at", { ascending: false }).limit(100),
      ]);
      const data = [...(d1 || []), ...(d2 || [])];
      if (data) {
        // Group by pair, take latest message per conversation
        const convos = new Map();
        for (const d of data) {
          if (!convos.has(d.pair)) {
            const parts = d.pair.split(":");
            const peerName = parts.find(p => p !== name) || parts[0];
            convos.set(d.pair, { peerName, lastMessage: d.encrypted ? "[encrypted]" : d.text?.slice(0, 50), lastTime: new Date(d.created_at).getTime() });
          }
        }
        return res.json([...convos.values()].sort((a, b) => b.lastTime - a.lastTime));
      }
    } catch (e) { console.warn("dm-conversations query error:", e.message); }
  } else {
    const store = jsonStores["direct_messages"] || {};
    const convos = [];
    for (const [pair, val] of Object.entries(store)) {
      const parts = pair.split(":");
      if (!parts.includes(name)) continue;
      try {
        const msgs = JSON.parse(val);
        if (msgs.length === 0) continue;
        const last = msgs[msgs.length - 1];
        const peerName = parts.find(p => p !== name) || parts[0];
        convos.push({ peerName, lastMessage: last.encrypted ? "[encrypted]" : (last.text || "").slice(0, 50), lastTime: last.ts });
      } catch {}
    }
    return res.json(convos.sort((a, b) => b.lastTime - a.lastTime));
  }
  res.json([]);
});

// ─── Dynamic OG meta tags for link previews ─────────────────────────────────

const OG_IMAGE = "https://minimeet.cc/og-image.png";
const SITE_NAME = "minimeet.cc";
const SITE_DESC = "minute meetings and socials";

function escOgHtml(s) {
  return String(s).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/'/g, "&#39;");
}

app.get("/", async (req, res, next) => {
  const ua = (req.headers["user-agent"] || "").toLowerCase();
  const isCrawler = /bot|crawl|spider|preview|slack|discord|telegram|whatsapp|twitter|facebook|linkedin|og-image/i.test(ua);
  if (!isCrawler) return next();

  const { profile, call, stream, post } = req.query;
  let title = SITE_NAME;
  let description = SITE_DESC;
  let url = `https://${SITE_NAME}/`;

  if (post) {
    const postId = String(post).replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 20);
    const postData = await dbGetPost(postId);
    if (postData) {
      const authorName = postData.author || "someone";
      const preview = (postData.text || "").slice(0, 100);
      title = `${authorName} on ${SITE_NAME}`;
      description = preview || `A post on ${SITE_NAME}`;
      url += `?post=${postId}`;
    }
  } else if (profile) {
    const name = decodeURIComponent(profile).replace(/[<>"'&]/g, "").slice(0, 60);
    title = `${name} on ${SITE_NAME}`;
    description = `View ${name}'s profile on ${SITE_NAME} — ${SITE_DESC}`;
    url += `?profile=${encodeURIComponent(name)}`;
  } else if (call) {
    const name = decodeURIComponent(call).replace(/[<>"'&]/g, "").slice(0, 60);
    title = `Call ${name} on ${SITE_NAME}`;
    description = `Join a 1-minute video call with ${name} on ${SITE_NAME}`;
    url += `?call=${encodeURIComponent(name)}`;
  } else if (stream) {
    title = `Live stream on ${SITE_NAME}`;
    description = `Watch a live stream on ${SITE_NAME} — ${SITE_DESC}`;
    url += `?stream=${encodeURIComponent(String(stream).slice(0, 60))}`;
  } else if (req.query.gate) {
    const gateId = String(req.query.gate).replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 20);
    const room = await dbGetGatedRoom(gateId);
    if (room) {
      title = `${room.name} on ${SITE_NAME}`;
      description = `Token-gated room — ${room.tokenType} required to join`;
      url += `?gate=${gateId}`;
    }
  }

  // Read the HTML and inject meta tags
  const htmlPath = path.join(__dirname, "public", "index.html");
  let html = fs.readFileSync(htmlPath, "utf-8");
  const safeTitle = escOgHtml(title);
  const safeDesc = escOgHtml(description);
  const safeUrl = escOgHtml(url);
  const metaTags = `
    <meta property="og:type" content="website" />
    <meta property="og:site_name" content="${SITE_NAME}" />
    <meta property="og:title" content="${safeTitle}" />
    <meta property="og:description" content="${safeDesc}" />
    <meta property="og:url" content="${safeUrl}" />
    <meta property="og:image" content="${OG_IMAGE}" />
    <meta name="twitter:card" content="summary" />
    <meta name="twitter:title" content="${safeTitle}" />
    <meta name="twitter:description" content="${safeDesc}" />
    <meta name="twitter:image" content="${OG_IMAGE}" />
    <meta name="description" content="${safeDesc}" />
  `;
  html = html.replace("</head>", metaTags + "</head>");
  html = html.replace("<title>minimeet.cc</title>", `<title>${safeTitle}</title>`);
  res.send(html);
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
    if (data.autoMeet && !data.disconnectedAt && !data.privateRoom && data.status === "online" && !isUserInCall(userId) && !isUserStreaming(userId)) {
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
      const autoCalleeName = calleeData.name; // capture before timeout
      const ringTimerId = setTimeout(async () => {
        const call = activeCalls.get(callId);
        if (call && !call.startedAt) {
          await recordCallOutcome(autoCalleeName, "missed");
          await refreshUserStats(callee.userId);
          const s1 = getSocketByUserId(caller.userId); if (s1) s1.emit("call-not-answered", { callId });
          const s2 = getSocketByUserId(callee.userId); if (s2) s2.emit("call-cancelled", { callId });
          cleanupCall(callId);
        }
        autoMeetPending.delete(pairKey);
      }, RING_TIMEOUT_MS);

      activeCalls.set(callId, { callerId: caller.userId, calleeId: callee.userId, startedAt: null, timerId: null, ringTimerId, prepaidSeconds: 0, totalDurationMs: CALL_DURATION_MS });

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
  totalVisitors = await dbGetCounter("total_visitors");
  const savedMsgs = await dbLoadPublicMsgs(MAX_CHAT_HISTORY);
  // Load reactions for all saved messages
  if (savedMsgs.length > 0) {
    const reactions = await dbLoadReactions(savedMsgs.map(m => m.id));
    for (const msg of savedMsgs) {
      if (reactions[msg.id]) msg.reactions = reactions[msg.id];
    }
  }
  publicChat.push(...savedMsgs);
  while (publicChat.length > MAX_CHAT_HISTORY) publicChat.shift();
  console.log(`\n  📞 minimeet.cc on http://localhost:${PORT} | DB: ${supabase ? "Supabase" : "JSON"} | X OAuth: ${X_CLIENT_ID ? "✅" : "❌"} | Chat: ${savedMsgs.length} msgs loaded\n`);
});
