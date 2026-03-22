const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { verifyMessage, Wallet: EthersWallet } = require("ethers");

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
  const wallet = new EthersWallet("0x" + privateKeyBytes.toString("hex"));
  return { address: wallet.address.toLowerCase() };
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
app.get("/auth/wallet/nonce", (req, res) => {
  // Rate limit: max 10 nonce requests per IP per minute
  const ip = req.ip || req.connection.remoteAddress;
  const rl = nonceRateLimit.get(ip) || { count: 0, resetAt: Date.now() + 60000 };
  if (Date.now() > rl.resetAt) { rl.count = 0; rl.resetAt = Date.now() + 60000; }
  rl.count++;
  nonceRateLimit.set(ip, rl);
  if (rl.count > 10) return res.status(429).json({ error: "Too many requests" });
  // Cap nonce map size to prevent memory exhaustion
  if (walletNonces.size > 10000) walletNonces.clear();

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
      await supabase.from("direct_messages").insert(row);
    } catch (e) { console.warn("DM write error:", e.message); }
    return;
  }
  const stored = jsonGet("direct_messages", pair);
  let msgs; try { msgs = stored ? JSON.parse(stored) : []; } catch { msgs = []; }
  msgs.push({ id: msg.id, sender: senderName.toLowerCase().trim(), senderName: msg.fromName, text: msg.text, encrypted: msg.encrypted || false, ts: msg.ts });
  if (msgs.length > 100) msgs.splice(0, msgs.length - 100);
  jsonSet("direct_messages", pair, JSON.stringify(msgs));
}

async function dbLoadDMs(nameA, nameB, limit = 50) {
  const pair = [nameA, nameB].map(n => n.toLowerCase().trim()).sort().join(":");
  if (supabase) {
    try {
      const { data } = await supabase.from("direct_messages")
        .select("*").eq("pair", pair)
        .order("created_at", { ascending: false }).limit(limit);
      if (data) return data.reverse().map(d => ({
        id: d.id, sender: d.sender, senderName: d.sender_name, text: d.text, encrypted: d.encrypted || false, ts: new Date(d.created_at).getTime(),
      }));
    } catch (e) { console.warn("DM read error:", e.message); }
    return [];
  }
  const stored = jsonGet("direct_messages", pair);
  let msgs; try { msgs = stored ? JSON.parse(stored) : []; } catch { msgs = []; }
  return msgs.slice(-limit);
}

// ─── User profiles (bio + banner) ────────────────────────────────────────────

const profileCache = new Map();

async function dbGetProfile(name) {
  const key = name.toLowerCase().trim();
  if (profileCache.has(key)) return profileCache.get(key);
  if (supabase) {
    try {
      const { data } = await supabase.from("user_profiles").select("*").eq("name", key).single();
      if (data) { const p = { bio: data.bio || null, banner: data.banner || null, customStatus: data.custom_status || null, e2eKey: data.e2e_key || null, appWallet: data.app_wallet || null, appWalletAddress: data.app_wallet_address || null }; profileCache.set(key, p); return p; }
    } catch {}
    return { bio: null, banner: null, customStatus: null, e2eKey: null, appWallet: null, appWalletAddress: null };
  }
  const stored = jsonGet("user_profiles", key);
  const defaultProfile = { bio: null, banner: null, customStatus: null, e2eKey: null, appWallet: null, appWalletAddress: null };
  let p; try { p = stored ? { ...defaultProfile, ...JSON.parse(stored) } : { ...defaultProfile }; } catch { p = { ...defaultProfile }; }
  profileCache.set(key, p);
  return p;
}

async function dbSetProfile(name, profile) {
  const key = name.toLowerCase().trim();
  profileCache.set(key, profile);
  if (supabase) {
    try {
      const row = { name: key, bio: profile.bio, banner: profile.banner, custom_status: profile.customStatus || null, updated_at: new Date().toISOString() };
      if (profile.appWallet !== undefined) row.app_wallet = profile.appWallet;
      if (profile.appWalletAddress !== undefined) row.app_wallet_address = profile.appWalletAddress;
      if (profile.e2eKey !== undefined) row.e2e_key = profile.e2eKey;
      await supabase.from("user_profiles").upsert(row);
    } catch (e) { console.warn("Profile write error:", e.message); }
    return;
  }
  jsonSet("user_profiles", key, JSON.stringify(profile));
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
        await supabase.rpc("increment_post_reply_count", { pid: parentId }).catch(() => {
          supabase.from("posts").update({ reply_count: supabase.raw ? undefined : 1 }).eq("id", parentId); // fallback
        });
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
        try { await supabase.rpc("decrement_post_reply_count", { pid: post.parentId }); } catch {}
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
        .like("pair", `%${addr.replace(/[%_\\]/g, "")}%`).order("created_at", { ascending: true });
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
      const { data } = await supabase.from("pair_meetings").select("credit_seconds").like("pair", `%${key.replace(/[%_\\]/g, "")}%`);
      if (data) totalPairCredits = data.reduce((sum, r) => sum + (r.credit_seconds || 0), 0);
    } catch {}
  } else {
    const store = jsonStores["pair_meetings"] || {};
    for (const [pair, val] of Object.entries(store)) {
      if (pair.includes(key)) { try { totalPairCredits += JSON.parse(val).creditSeconds || 0; } catch {} }
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
  const seenNames = new Set();
  for (const [userId, data] of onlineUsers) {
    if (!data.disconnectedAt && !seenNames.has(data.name.toLowerCase())) {
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

    // Verify wallet signature if wallet is being used for first-time login (not reconnect)
    if (safeWallet && walletSignature && walletNonce) {
      if (!verifyWalletSignature(safeWallet, walletSignature, walletNonce)) {
        socket.emit("register-error", { message: "Wallet signature verification failed" });
        return;
      }
    } else if (safeWallet && !reconnectUserId && !sessionToken && !xUsername) {
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
        if (xUsername && existingUser.xUsername && xUsername.toLowerCase() === existingUser.xUsername.toLowerCase()) canReclaim = true;
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
    if (await isNameClaimed(trimmedName, xUsername, safeWallet)) {
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
    let storedAvatar = await dbGetAvatar(trimmedName);
    // Fallback: try x_profiles for avatar if not in avatars table
    if (!storedAvatar && xUsername) {
      const xp = await dbGetXProfile(xUsername);
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
      xUsername: xUsername || null, walletAddress: storedWallet || null,
      customStatus: storedProfile.customStatus || null,
      publicKey: null, // loaded via register-pubkey
      autoMeet: prefs.autoMeet, cooldownHours: prefs.cooldownHours,
    });

    // Load stored public key for E2E encryption
    const storedPubKey = await dbGetPublicKey(trimmedName);
    if (storedPubKey) onlineUsers.get(userId).publicKey = storedPubKey;
    takenNames.set(trimmedName.toLowerCase(), userId);

    // Issue session token for all users (needed for reconnection after server restart)
    let newSessionToken = sessionToken || base64url(crypto.randomBytes(24));
    await dbSetSessionToken(trimmedName, hashToken(newSessionToken));

    socket.emit("registered", { userId, name: trimmedName, reconnected: false, avatar: resolvedAvatar, stats, xUsername: xUsername || null, walletAddress: storedWallet || null, customStatus: storedProfile.customStatus || null, autoMeet: prefs.autoMeet, cooldownHours: prefs.cooldownHours, sessionToken: newSessionToken });
    broadcastUserList();
    console.log(`✅ ${trimmedName}${xUsername ? " (@" + xUsername + ")" : ""}${storedWallet ? " [" + storedWallet.slice(0,6) + "...]" : ""} registered as ${userId}`);

    // Add verified users (X or wallet) to the directory
    // Add all users to directory (verified and guests)
    dbAddToDirectory(trimmedName, { displayName: trimmedName, xUsername: xUsername || null, walletAddress: storedWallet || null, avatar: resolvedAvatar });

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
    if (status === "online" || status === "idle") {
      userData.status = status;
    }
    // Update custom status text (persisted like bio)
    if (customStatus !== undefined) {
      userData.customStatus = (typeof customStatus === "string") ? customStatus.trim().slice(0, 50) : null;
      // Persist to profile
      const profile = await dbGetProfile(userData.name);
      profile.customStatus = userData.customStatus;
      await dbSetProfile(userData.name, profile);
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

    let targetName = null;
    let targetUserId = toUserId || null;

    if (toUserId && onlineUsers.has(toUserId)) {
      // Online target by userId
      const target = onlineUsers.get(toUserId);
      targetName = target.name;
      const msg = { id: uuidv4().slice(0, 10), fromUserId: userId, fromName: userData.name, fromAvatar: userData.avatar || null, text: trimmed, image: safeImage, encrypted: isEncrypted, ts: Date.now() };
      if (!target.disconnectedAt) {
        const ts = getSocketByUserId(toUserId);
        if (ts) ts.emit("chat-dm", msg);
      }
      socket.emit("chat-dm-sent", { toUserId, toName: targetName, ...msg });
      dbSaveDM(userData.name, targetName, msg);
      // DM notification
      const dmNotif = await dbCreateNotification(targetName, "dm", userData.name, null, isEncrypted ? "[encrypted message]" : trimmed);
      emitNotification(targetName, dmNotif);
    } else if (toName && typeof toName === "string") {
      // Offline target by name or wallet address
      targetName = toName.trim().slice(0, 60);
      // If it's a wallet address, check if a registered user owns it
      if (/^0x[0-9a-f]{40}$/i.test(targetName)) {
        const owner = await dbGetWalletOwner(targetName.toLowerCase());
        if (owner) {
          // Resolve to registered user — check if they're online
          const onlineOwner = [...onlineUsers.entries()].find(([, d]) => d.name.toLowerCase() === owner);
          if (onlineOwner && !onlineOwner[1].disconnectedAt) {
            const ts = getSocketByUserId(onlineOwner[0]);
            const msg = { id: uuidv4().slice(0, 10), fromUserId: userId, fromName: userData.name, fromAvatar: userData.avatar || null, text: trimmed, image: safeImage, encrypted: isEncrypted, ts: Date.now() };
            if (ts) ts.emit("chat-dm", msg);
            socket.emit("chat-dm-sent", { toUserId: onlineOwner[0], toName: owner, ...msg });
            dbSaveDM(userData.name, owner, msg);
            const dmNotif = await dbCreateNotification(owner, "dm", userData.name, null, isEncrypted ? "[encrypted message]" : trimmed);
            emitNotification(owner, dmNotif);
            return;
          }
          targetName = owner; // use registered name for storage
        }
      }
      const msg = { id: uuidv4().slice(0, 10), fromUserId: userId, fromName: userData.name, fromAvatar: userData.avatar || null, text: trimmed, image: safeImage, encrypted: isEncrypted, ts: Date.now() };
      // Check if they happen to be online under a different lookup
      const onlineTarget = [...onlineUsers.entries()].find(([, d]) => d.name.toLowerCase() === targetName.toLowerCase());
      if (onlineTarget) {
        const [tId, tData] = onlineTarget;
        if (!tData.disconnectedAt) {
          const ts = getSocketByUserId(tId);
          if (ts) ts.emit("chat-dm", msg);
        }
        targetUserId = tId;
      }
      socket.emit("chat-dm-sent", { toUserId: targetUserId, toName: targetName, ...msg });
      dbSaveDM(userData.name, targetName, msg);
      const dmNotif2 = await dbCreateNotification(targetName, "dm", userData.name, null, isEncrypted ? "[encrypted message]" : trimmed);
      emitNotification(targetName, dmNotif2);
    }
  });

  // DM history
  socket.on("dm-history", async ({ peerName }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (!peerName || typeof peerName !== "string") return;
    let resolvedPeer = peerName;
    // If peerName is a wallet address, resolve to the registered user's name
    if (/^0x[0-9a-f]{40}$/i.test(peerName)) {
      const owner = await dbGetWalletOwner(peerName.toLowerCase());
      if (owner) resolvedPeer = owner;
    }
    const messages = await dbLoadDMs(userData.name, resolvedPeer);
    socket.emit("dm-history", { peerName, messages });
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
          const notif = await dbCreateNotification(parent.author, "reply", userData.name, parentId, trimmed);
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
  });

  socket.on("delete-post", async ({ postId }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const ok = await dbDeletePost(postId, userData.name);
    if (ok) socket.emit("post-deleted", { postId });
  });

  socket.on("toggle-like", async ({ postId }) => {
    if (!rateLimit(socket, "like", 20, 10_000)) return;
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const result = await dbToggleLike(postId, userData.name);
    const post = await dbGetPost(postId);
    const likers = await dbGetPostLikes(postId);
    socket.emit("post-liked", { postId, likeCount: post ? post.likeCount : 0, liked: result.liked, likers });
    // Notify post author on like
    if (result.liked && post && post.author !== userData.name.toLowerCase()) {
      const notif = await dbCreateNotification(post.author, "like", userData.name, postId, null);
      emitNotification(post.author, notif);
    }
  });

  socket.on("get-user-posts", async ({ username, limit, offset }) => {
    if (!username || typeof username !== "string") return;
    const result = await dbGetUserPosts(username, limit || 20, offset || 0);
    const userData = socket.userId ? onlineUsers.get(socket.userId) : null;
    const myNameLower = userData ? userData.name.toLowerCase() : "";
    // Get author avatar once for all posts (same author)
    const authorAvatar = await dbGetAvatar(username) || null;
    for (const post of result.posts) {
      post.authorName = username;
      post.authorAvatar = authorAvatar;
      const likers = await dbGetPostLikes(post.id);
      post.likers = likers;
      post.liked = myNameLower ? likers.includes(myNameLower) : false;
    }
    socket.emit("user-posts", { username, ...result });
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
    const profile = await dbGetProfile(key);
    const stats = await dbGetStats(key);
    let avatar = await dbGetAvatar(key);
    const wallet = await dbGetWallet(key);
    const { total: postCount } = await dbGetUserPosts(key, 0, 0);
    // Find xUsername + avatar from online users, then directory, then x_profiles
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
      if (supabase) {
        try {
          const { data } = await supabase.from("user_directory").select("*").eq("name", key).single();
          if (data) {
            if (!xUsername) xUsername = data.x_username || null;
            if (!avatar) avatar = data.avatar || null;
            displayName = data.display_name || username;
          }
        } catch {}
      } else {
        const stored = jsonGet("user_directory", "_all");
        try {
          const dir = stored ? JSON.parse(stored) : {};
          const entry = dir[key];
          if (entry) {
            if (!xUsername) xUsername = entry.xUsername || null;
            if (!avatar) avatar = entry.avatar || null;
            displayName = entry.displayName || username;
          }
        } catch {}
      }
    }
    // Final fallback: check x_profiles for avatar + xUsername
    if (!xUsername) {
      // Try to find xUsername by scanning x_profiles for this display name
      if (supabase) {
        try {
          const { data } = await supabase.from("x_profiles").select("username, avatar").eq("display_name", displayName).single();
          if (data) { xUsername = data.username; if (!avatar) avatar = data.avatar; }
        } catch {}
      }
    }
    if (!avatar && xUsername) {
      const xProfile = await dbGetXProfile(xUsername);
      if (xProfile?.avatar) { avatar = xProfile.avatar; dbSetAvatar(key, avatar); }
    }
    const socialScore = await dbGetSocialScore(key);
    // Include pair meeting info if viewer has a relationship with this user
    const viewerData = socket.userId ? onlineUsers.get(socket.userId) : null;
    let pairInfo = null;
    if (viewerData && viewerData.name.toLowerCase() !== key) {
      pairInfo = await dbGetPairMeetings(viewerData.name, key);
    }
    // Count followers (how many users have saved this person as a contact)
    let followers = 0;
    if (supabase) {
      try {
        const xKey = xUsername ? "@" + xUsername.toLowerCase() : null;
        let query = supabase.from("contacts").select("owner", { count: "exact", head: true }).eq("contact_name", key);
        const { count: c1 } = await query;
        followers = c1 || 0;
        if (xKey) {
          const { count: c2 } = await supabase.from("contacts").select("owner", { count: "exact", head: true }).eq("contact_name", xKey);
          followers += c2 || 0;
        }
      } catch {}
    } else {
      const store = jsonStores["contacts"] || {};
      for (const val of Object.values(store)) {
        try {
          const contacts = JSON.parse(val);
          if (contacts.includes(key) || (xUsername && contacts.includes("@" + xUsername.toLowerCase()))) followers++;
        } catch {}
      }
    }
    socket.emit("profile", { username: key, displayName, bio: profile.bio, banner: profile.banner, avatar, xUsername, walletAddress: wallet, appWalletAddress: profile.appWalletAddress || null, stats, postCount, followers, customStatus: profile.customStatus || null, socialScore, pairInfo });
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

  socket.on("get-my-pairs", async () => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const key = userData.name.toLowerCase().trim().replace(/[%_\\]/g, "");
    const pairs = {};
    if (supabase) {
      try {
        const { data } = await supabase.from("pair_meetings").select("pair, meet_count, credit_seconds").like("pair", `%${key}%`);
        if (data) for (const r of data) {
          const parts = r.pair.split(":");
          const peer = parts.find(p => p !== key) || parts[0];
          pairs[peer] = { meetCount: r.meet_count || 0, creditSeconds: r.credit_seconds || 0 };
        }
      } catch {}
    } else {
      const store = jsonStores["pair_meetings"] || {};
      for (const [pair, val] of Object.entries(store)) {
        if (!pair.includes(key)) continue;
        try {
          const pm = JSON.parse(val);
          const parts = pair.split(":");
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
    const safeKey = key.replace(/[%_\\]/g, "");
    if (supabase) {
      try {
        const { data } = await supabase.from("pair_meetings").select("pair, meet_count, credit_seconds").like("pair", `%${safeKey}%`);
        if (data) for (const r of data) {
          const parts = r.pair.split(":");
          const peer = parts.find(p => p !== key) || parts[0];
          pairs[peer] = { meetCount: r.meet_count || 0, creditSeconds: r.credit_seconds || 0 };
        }
      } catch {}
    } else {
      const store = jsonStores["pair_meetings"] || {};
      for (const [pair, val] of Object.entries(store)) {
        if (!pair.includes(key)) continue;
        try {
          const pm = JSON.parse(val);
          const parts = pair.split(":");
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

  // Call request for offline users (by name)
  socket.on("tip-sent", async ({ toName, amount, txHash }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (!toName || !amount || !txHash) return;
    const preview = `${amount} ETH`;
    const notif = await dbCreateNotification(toName, "tip", userData.name, null, preview);
    emitNotification(toName, notif);
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
    const tipMsg = { type: "tip", sender: userData.name, avatar: userData.avatar || null, amount, message: (message || "").slice(0, 100) };
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

  socket.on("call-user", async ({ calleeId }) => {
    if (!rateLimit(socket, "call-user", 3, 10_000)) return; // 3 calls per 10s
    const callerId = socket.userId; if (!callerId) return;
    const caller = onlineUsers.get(callerId); if (!caller) return;
    const callee = onlineUsers.get(calleeId);
    if (!callee || callee.disconnectedAt) {
      // User is offline — send a call request notification instead
      let calleeName = null;
      // Find name by userId in takenNames reverse lookup
      for (const [name, uid] of takenNames) { if (uid === calleeId) { calleeName = name; break; } }
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

    const callId = uuidv4().slice(0, 12);
    const calleeName = callee.name; // capture name before timeout fires
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
    call.timerId = setTimeout(async () => {
      // Award 30 seconds credit to both users for completing the meeting
      const callerData = onlineUsers.get(call.callerId);
      const calleeData = onlineUsers.get(call.calleeId);
      if (callerData) { const cs = await dbGetStats(callerData.name); cs.creditSeconds = (cs.creditSeconds || 0) + 30; await dbSetStats(callerData.name, cs); }
      if (calleeData) { const cs = await dbGetStats(calleeData.name); cs.creditSeconds = (cs.creditSeconds || 0) + 30; await dbSetStats(calleeData.name, cs); }
      // Record pair meeting
      if (callerData && calleeData) dbRecordPairMeeting(callerData.name, calleeData.name);
      const s1 = getSocketByUserId(call.callerId); const s2 = getSocketByUserId(call.calleeId);
      if (s1) s1.emit("call-timeout", { callId, creditEarned: 30 }); if (s2) s2.emit("call-timeout", { callId, creditEarned: 30 });
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

  socket.on("extend-call", async ({ callId, seconds }) => {
    if (!rateLimit(socket, "extend", 2, 5_000)) return; // max 2 extends per 5s
    const userId = socket.userId; if (!userId) return;
    const call = activeCalls.get(callId); if (!call || !call.startedAt) return;
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
  res.json({ totalVisitors: totalVisitors, onlineUsers: onlineUsers.size, registeredUsers: dirSize, totalMeets, totalPosts });
});

// ─── DM conversations list ────────────────────────────────────────────────────

app.get("/api/dm-conversations", async (req, res) => {
  const name = (req.query.name || "").toLowerCase().trim().replace(/[%_\\]/g, ""); // sanitize LIKE wildcards
  if (!name || name.length < 2) return res.json([]);
  if (supabase) {
    try {
      const { data } = await supabase.from("direct_messages")
        .select("pair, text, encrypted, created_at")
        .like("pair", `%${name}%`)
        .order("created_at", { ascending: false })
        .limit(100);
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
    } catch {}
  } else {
    const store = jsonStores["direct_messages"] || {};
    const convos = [];
    for (const [pair, val] of Object.entries(store)) {
      if (!pair.includes(name)) continue;
      try {
        const msgs = JSON.parse(val);
        if (msgs.length === 0) continue;
        const last = msgs[msgs.length - 1];
        const parts = pair.split(":");
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

app.get("/", async (req, res, next) => {
  const ua = (req.headers["user-agent"] || "").toLowerCase();
  const isCrawler = /bot|crawl|spider|preview|slack|discord|telegram|whatsapp|twitter|facebook|linkedin|og-image/i.test(ua);
  if (!isCrawler) return next();

  const { profile, call, stream } = req.query;
  let title = SITE_NAME;
  let description = SITE_DESC;
  let url = `https://${SITE_NAME}/`;

  if (profile) {
    const name = decodeURIComponent(profile);
    title = `${name} on ${SITE_NAME}`;
    description = `View ${name}'s profile on ${SITE_NAME} — ${SITE_DESC}`;
    url += `?profile=${encodeURIComponent(name)}`;
  } else if (call) {
    const name = decodeURIComponent(call);
    title = `Call ${name} on ${SITE_NAME}`;
    description = `Join a 1-minute video call with ${name} on ${SITE_NAME}`;
    url += `?call=${encodeURIComponent(name)}`;
  } else if (stream) {
    title = `Live stream on ${SITE_NAME}`;
    description = `Watch a live stream on ${SITE_NAME} — ${SITE_DESC}`;
    url += `?stream=${encodeURIComponent(stream)}`;
  }

  // Read the HTML and inject meta tags
  const htmlPath = path.join(__dirname, "public", "index.html");
  let html = fs.readFileSync(htmlPath, "utf-8");
  const metaTags = `
    <meta property="og:type" content="website" />
    <meta property="og:site_name" content="${SITE_NAME}" />
    <meta property="og:title" content="${title}" />
    <meta property="og:description" content="${description}" />
    <meta property="og:url" content="${url}" />
    <meta property="og:image" content="${OG_IMAGE}" />
    <meta name="twitter:card" content="summary" />
    <meta name="twitter:title" content="${title}" />
    <meta name="twitter:description" content="${description}" />
    <meta name="twitter:image" content="${OG_IMAGE}" />
    <meta name="description" content="${description}" />
  `;
  html = html.replace("</head>", metaTags + "</head>");
  // Also update the <title>
  html = html.replace("<title>minimeet.cc</title>", `<title>${title}</title>`);
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
  console.log(`\n  📞 minimeet.cc on http://localhost:${PORT} | DB: ${supabase ? "Supabase" : "JSON"} | X OAuth: ${X_CLIENT_ID ? "✅" : "❌"} | Chat: ${savedMsgs.length} msgs loaded\n`);
});
