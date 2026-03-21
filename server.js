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
      await supabase.from("direct_messages").insert({
        id: msg.id, pair, sender: senderName.toLowerCase().trim(),
        sender_name: msg.fromName, text: msg.text,
        created_at: new Date(msg.ts).toISOString(),
      });
    } catch (e) { console.warn("DM write error:", e.message); }
    return;
  }
  const stored = jsonGet("direct_messages", pair);
  let msgs; try { msgs = stored ? JSON.parse(stored) : []; } catch { msgs = []; }
  msgs.push({ id: msg.id, sender: senderName.toLowerCase().trim(), senderName: msg.fromName, text: msg.text, ts: msg.ts });
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
        id: d.id, sender: d.sender, senderName: d.sender_name, text: d.text, ts: new Date(d.created_at).getTime(),
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
      if (data) { const p = { bio: data.bio || null, banner: data.banner || null, customStatus: data.custom_status || null }; profileCache.set(key, p); return p; }
    } catch {}
    return { bio: null, banner: null, customStatus: null };
  }
  const stored = jsonGet("user_profiles", key);
  let p; try { p = stored ? JSON.parse(stored) : { bio: null, banner: null, customStatus: null }; } catch { p = { bio: null, banner: null, customStatus: null }; }
  profileCache.set(key, p);
  return p;
}

async function dbSetProfile(name, profile) {
  const key = name.toLowerCase().trim();
  profileCache.set(key, profile);
  if (supabase) {
    try {
      await supabase.from("user_profiles").upsert({ name: key, bio: profile.bio, banner: profile.banner, custom_status: profile.customStatus || null, updated_at: new Date().toISOString() });
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
      const { data: existing } = await supabase.from("post_likes").select("post_id").eq("post_id", postId).eq("user_name", user).single();
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
      const resolvedAvatar = eu.avatar || await dbGetAvatar(eu.name);
      eu.avatar = resolvedAvatar;
      eu.stats = await dbGetStats(eu.name);
      const prefs = await dbGetPrefs(eu.name);
      eu.autoMeet = prefs.autoMeet;
      eu.cooldownHours = prefs.cooldownHours;
      if (!eu.customStatus) { const p = await dbGetProfile(eu.name); eu.customStatus = p.customStatus || null; }
      socket.emit("registered", { userId: reconnectUserId, name: eu.name, reconnected: true, avatar: resolvedAvatar, stats: eu.stats, xUsername: eu.xUsername || null, walletAddress: eu.walletAddress || null, customStatus: eu.customStatus || null, autoMeet: eu.autoMeet, cooldownHours: eu.cooldownHours });
      // Backfill directory for verified users
      if (eu.xUsername || eu.walletAddress) dbAddToDirectory(eu.name, { displayName: eu.name, xUsername: eu.xUsername, walletAddress: eu.walletAddress, avatar: resolvedAvatar });
      broadcastUserList();
      return;
    }

    if (isNameTaken(trimmedName)) {
      socket.emit("register-error", { message: `"${trimmedName}" is already taken. Try a different name.` });
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
    const storedAvatar = await dbGetAvatar(trimmedName);
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
      autoMeet: prefs.autoMeet, cooldownHours: prefs.cooldownHours,
    });
    takenNames.set(trimmedName.toLowerCase(), userId);

    // Issue session token for all users (needed for reconnection after server restart)
    let newSessionToken = sessionToken || base64url(crypto.randomBytes(24));
    await dbSetSessionToken(trimmedName, hashToken(newSessionToken));

    socket.emit("registered", { userId, name: trimmedName, reconnected: false, avatar: resolvedAvatar, stats, xUsername: xUsername || null, walletAddress: storedWallet || null, customStatus: storedProfile.customStatus || null, autoMeet: prefs.autoMeet, cooldownHours: prefs.cooldownHours, sessionToken: newSessionToken });
    broadcastUserList();
    console.log(`✅ ${trimmedName}${xUsername ? " (@" + xUsername + ")" : ""}${storedWallet ? " [" + storedWallet.slice(0,6) + "...]" : ""} registered as ${userId}`);

    // Add verified users (X or wallet) to the directory
    if (xUsername || storedWallet) {
      dbAddToDirectory(trimmedName, { displayName: trimmedName, xUsername: xUsername || null, walletAddress: storedWallet || null, avatar: resolvedAvatar });
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
  socket.on("chat-dm", async ({ toUserId, toName, text }) => {
    if (!rateLimit(socket, "chat", 10, 10_000)) return;
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    const trimmed = (text || "").trim().slice(0, 500);
    if (!trimmed) return;

    let targetName = null;
    let targetUserId = toUserId || null;

    if (toUserId && onlineUsers.has(toUserId)) {
      // Online target by userId
      const target = onlineUsers.get(toUserId);
      targetName = target.name;
      const msg = { id: uuidv4().slice(0, 10), fromUserId: userId, fromName: userData.name, fromAvatar: userData.avatar || null, text: trimmed, ts: Date.now() };
      if (!target.disconnectedAt) {
        const ts = getSocketByUserId(toUserId);
        if (ts) ts.emit("chat-dm", msg);
      }
      socket.emit("chat-dm-sent", { toUserId, toName: targetName, ...msg });
      dbSaveDM(userData.name, targetName, msg);
      // DM notification
      const dmNotif = await dbCreateNotification(targetName, "dm", userData.name, null, trimmed);
      emitNotification(targetName, dmNotif);
    } else if (toName && typeof toName === "string") {
      // Offline target by name — persist for when they come online
      targetName = toName.trim().slice(0, 60);
      const msg = { id: uuidv4().slice(0, 10), fromUserId: userId, fromName: userData.name, fromAvatar: userData.avatar || null, text: trimmed, ts: Date.now() };
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
      const dmNotif2 = await dbCreateNotification(targetName, "dm", userData.name, null, trimmed);
      emitNotification(targetName, dmNotif2);
    }
  });

  // DM history
  socket.on("dm-history", async ({ peerName }) => {
    const userId = socket.userId; if (!userId) return;
    const userData = onlineUsers.get(userId); if (!userData) return;
    if (!peerName || typeof peerName !== "string") return;
    const messages = await dbLoadDMs(userData.name, peerName);
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
    // Notify parent post author on reply
    if (parentId) {
      const parent = await dbGetPost(parentId);
      if (parent && parent.author !== userData.name.toLowerCase()) {
        const notif = await dbCreateNotification(parent.author, "reply", userData.name, parentId, trimmed);
        emitNotification(parent.author, notif);
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
    const key = username.toLowerCase().trim();
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
    // Final fallback: check x_profiles for avatar
    if (!avatar && xUsername) {
      const xProfile = await dbGetXProfile(xUsername);
      if (xProfile?.avatar) avatar = xProfile.avatar;
    }
    socket.emit("profile", { username: key, displayName, bio: profile.bio, banner: profile.banner, avatar, xUsername, walletAddress: wallet, stats, postCount });
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

    userData.disconnectedAt = Date.now();
    // Update last-seen in directory for verified users
    if (userData.xUsername || userData.walletAddress) {
      dbAddToDirectory(userData.name, { displayName: userData.name, xUsername: userData.xUsername, walletAddress: userData.walletAddress, avatar: userData.avatar });
    }
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
    if (!data.xUsername && !data.walletAddress) continue;
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
