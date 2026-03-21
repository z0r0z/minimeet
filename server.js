const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const fs = require("fs");

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
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

// Stats shape: { received: 0, accepted: 0, declined: 0, missed: 0, streak: 0, best_streak: 0 }
const statsCache = new Map();

function defaultStats() {
  return { received: 0, accepted: 0, declined: 0, missed: 0, streak: 0, best_streak: 0 };
}

async function dbGetStats(name) {
  const key = name.toLowerCase().trim();
  if (statsCache.has(key)) return statsCache.get(key);
  if (supabase) {
    try {
      const { data } = await supabase.from("call_stats").select("*").eq("name", key).single();
      if (data) {
        const stats = {
          received: data.received || 0,
          accepted: data.accepted || 0,
          declined: data.declined || 0,
          missed: data.missed || 0,
          streak: data.streak || 0,
          best_streak: data.best_streak || 0,
        };
        statsCache.set(key, stats);
        return stats;
      }
    } catch {}
    const fresh = defaultStats();
    statsCache.set(key, fresh);
    return fresh;
  }
  const stored = jsonGet("stats", key);
  const stats = stored ? JSON.parse(stored) : defaultStats();
  statsCache.set(key, stats);
  return stats;
}

async function dbSetStats(name, stats) {
  const key = name.toLowerCase().trim();
  statsCache.set(key, stats);
  if (supabase) {
    try {
      await supabase.from("call_stats").upsert({
        name: key,
        received: stats.received,
        accepted: stats.accepted,
        declined: stats.declined,
        missed: stats.missed,
        streak: stats.streak,
        best_streak: stats.best_streak,
        updated_at: new Date().toISOString(),
      });
    } catch (e) { console.warn("Stats write error:", e.message); }
    return;
  }
  jsonSet("stats", key, JSON.stringify(stats));
}

// Helper: record an outcome for callee
async function recordCallOutcome(calleeName, outcome) {
  const stats = await dbGetStats(calleeName);
  stats.received++;

  if (outcome === "accepted") {
    stats.accepted++;
    stats.streak++;
    if (stats.streak > stats.best_streak) stats.best_streak = stats.streak;
  } else if (outcome === "declined") {
    stats.declined++;
    stats.streak = 0;
  } else if (outcome === "missed") {
    stats.missed++;
    stats.streak = 0;
  }

  await dbSetStats(calleeName, stats);
  return stats;
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
  return jsonStores[store][key] || null;
}

function jsonSet(store, key, value) {
  if (!jsonStores[store]) jsonStores[store] = {};
  if (value) jsonStores[store][key] = value;
  else delete jsonStores[store][key];
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(path.join(DATA_DIR, `${store}.json`), JSON.stringify(jsonStores[store]), "utf-8");
  } catch (e) { console.warn(`JSON write error (${store}):`, e.message); }
}

// ─── State ──────────────────────────────────────────────────────────────────

const onlineUsers = new Map();
const activeCalls = new Map();
const takenNames = new Map();
const disconnectTimers = new Map();

const CALL_DURATION_MS = 60_000;
const RING_TIMEOUT_MS = 20_000;
const RECONNECT_GRACE_MS = 15_000;

// ─── Helpers ────────────────────────────────────────────────────────────────

function broadcastUserList() {
  const users = [];
  for (const [userId, data] of onlineUsers) {
    if (!data.disconnectedAt) {
      users.push({
        userId,
        name: data.name,
        status: data.status,
        avatar: data.avatar || null,
        stats: data.stats || null,
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

// Refresh a user's stats in the online map and broadcast
async function refreshUserStats(userId) {
  const userData = onlineUsers.get(userId);
  if (!userData) return;
  userData.stats = await dbGetStats(userData.name);
  broadcastUserList();
}

// ─── Socket.IO Events ──────────────────────────────────────────────────────

io.on("connection", (socket) => {
  console.log(`⚡ Socket connected: ${socket.id}`);

  // ── Register ──────────────────────────────────────────────────────────
  socket.on("register", async ({ name, reconnectUserId, avatar }) => {
    const trimmedName = name.trim();

    if (reconnectUserId && onlineUsers.has(reconnectUserId)) {
      const existingUser = onlineUsers.get(reconnectUserId);
      if (disconnectTimers.has(reconnectUserId)) {
        clearTimeout(disconnectTimers.get(reconnectUserId));
        disconnectTimers.delete(reconnectUserId);
      }
      existingUser.socketId = socket.id;
      existingUser.disconnectedAt = null;
      existingUser.status = "online";
      if (avatar) { existingUser.avatar = avatar; await dbSetAvatar(existingUser.name, avatar); }
      socket.userId = reconnectUserId;
      const resolvedAvatar = existingUser.avatar || await dbGetAvatar(existingUser.name);
      existingUser.avatar = resolvedAvatar;
      existingUser.stats = await dbGetStats(existingUser.name);

      socket.emit("registered", {
        userId: reconnectUserId, name: existingUser.name, reconnected: true,
        avatar: resolvedAvatar, stats: existingUser.stats,
      });
      broadcastUserList();
      return;
    }

    if (isNameTaken(trimmedName)) {
      socket.emit("register-error", { message: `"${trimmedName}" is already taken. Try a different name.` });
      return;
    }

    const userId = uuidv4().slice(0, 8);
    socket.userId = userId;
    const storedAvatar = await dbGetAvatar(trimmedName);
    const resolvedAvatar = avatar || storedAvatar || null;
    if (avatar && avatar !== storedAvatar) await dbSetAvatar(trimmedName, avatar);

    const stats = await dbGetStats(trimmedName);

    onlineUsers.set(userId, {
      socketId: socket.id, name: trimmedName, status: "online",
      avatar: resolvedAvatar, stats, disconnectedAt: null,
    });
    takenNames.set(trimmedName.toLowerCase(), userId);

    socket.emit("registered", { userId, name: trimmedName, reconnected: false, avatar: resolvedAvatar, stats });
    broadcastUserList();
    console.log(`✅ ${trimmedName} registered as ${userId}`);
  });

  // ── Update Avatar ─────────────────────────────────────────────────────
  socket.on("update-avatar", async ({ avatar }) => {
    const userId = socket.userId;
    if (!userId) return;
    const userData = onlineUsers.get(userId);
    if (!userData) return;
    userData.avatar = avatar || null;
    await dbSetAvatar(userData.name, avatar);
    broadcastUserList();
  });

  // ── Initiate Call ─────────────────────────────────────────────────────
  socket.on("call-user", ({ calleeId }) => {
    const callerId = socket.userId;
    const caller = onlineUsers.get(callerId);
    const callee = onlineUsers.get(calleeId);

    if (!callee || callee.disconnectedAt) { socket.emit("call-error", { message: "User is offline" }); return; }
    if (isUserInCall(calleeId)) { socket.emit("call-error", { message: `${callee.name} is already in a call` }); return; }
    if (isUserInCall(callerId)) { socket.emit("call-error", { message: "You are already in a call" }); return; }

    const callId = uuidv4().slice(0, 12);

    const ringTimerId = setTimeout(async () => {
      const call = activeCalls.get(callId);
      if (call && !call.startedAt) {
        // Missed call
        await recordCallOutcome(callee.name, "missed");
        await refreshUserStats(calleeId);

        socket.emit("call-not-answered", { callId });
        const calleeSocket = getSocketByUserId(calleeId);
        if (calleeSocket) calleeSocket.emit("call-cancelled", { callId });
        cleanupCall(callId);
      }
    }, RING_TIMEOUT_MS);

    activeCalls.set(callId, {
      callerId, calleeId, startedAt: null, timerId: null, ringTimerId,
    });

    const calleeSocket = getSocketByUserId(calleeId);
    if (calleeSocket) {
      calleeSocket.emit("incoming-call", {
        callId, callerId, callerName: caller.name, callerAvatar: caller.avatar || null,
      });
    }

    socket.emit("call-ringing", {
      callId, calleeId, calleeName: callee.name, calleeAvatar: callee.avatar || null,
    });
    console.log(`📞 ${caller.name} calling ${callee.name} [${callId}]`);
  });

  // ── Accept Call ───────────────────────────────────────────────────────
  socket.on("accept-call", async ({ callId }) => {
    const call = activeCalls.get(callId);
    if (!call) return;

    clearTimeout(call.ringTimerId);
    call.startedAt = Date.now();

    // Record accepted
    const callee = onlineUsers.get(call.calleeId);
    if (callee) {
      await recordCallOutcome(callee.name, "accepted");
      await refreshUserStats(call.calleeId);
    }

    call.timerId = setTimeout(() => {
      const callerSocket = getSocketByUserId(call.callerId);
      const calleeSocket = getSocketByUserId(call.calleeId);
      if (callerSocket) callerSocket.emit("call-timeout", { callId });
      if (calleeSocket) calleeSocket.emit("call-timeout", { callId });
      cleanupCall(callId);
    }, CALL_DURATION_MS);

    const callerSocket = getSocketByUserId(call.callerId);
    if (callerSocket) callerSocket.emit("call-accepted", { callId });
    socket.emit("call-accepted", { callId });
    console.log(`✅ Call ${callId} accepted`);
  });

  // ── Decline Call ──────────────────────────────────────────────────────
  socket.on("decline-call", async ({ callId }) => {
    const call = activeCalls.get(callId);
    if (!call) return;

    // Record declined
    const callee = onlineUsers.get(call.calleeId);
    if (callee) {
      await recordCallOutcome(callee.name, "declined");
      await refreshUserStats(call.calleeId);
    }

    const callerSocket = getSocketByUserId(call.callerId);
    if (callerSocket) callerSocket.emit("call-declined", { callId });
    cleanupCall(callId);
    console.log(`❌ Call ${callId} declined`);
  });

  // ── End Call ──────────────────────────────────────────────────────────
  socket.on("end-call", ({ callId }) => {
    const call = activeCalls.get(callId);
    if (!call) return;
    const duration = call.startedAt ? Math.floor((Date.now() - call.startedAt) / 1000) : 0;
    const otherUserId = call.callerId === socket.userId ? call.calleeId : call.callerId;
    const otherSocket = getSocketByUserId(otherUserId);
    if (otherSocket) otherSocket.emit("call-ended", { callId, duration });
    socket.emit("call-ended", { callId, duration });
    cleanupCall(callId);
  });

  // ── WebRTC Signaling ──────────────────────────────────────────────────
  socket.on("webrtc-offer", ({ callId, sdp }) => {
    const call = activeCalls.get(callId); if (!call) return;
    const t = call.callerId === socket.userId ? call.calleeId : call.callerId;
    const s = getSocketByUserId(t); if (s) s.emit("webrtc-offer", { callId, sdp });
  });
  socket.on("webrtc-answer", ({ callId, sdp }) => {
    const call = activeCalls.get(callId); if (!call) return;
    const t = call.callerId === socket.userId ? call.calleeId : call.callerId;
    const s = getSocketByUserId(t); if (s) s.emit("webrtc-answer", { callId, sdp });
  });
  socket.on("webrtc-ice-candidate", ({ callId, candidate }) => {
    const call = activeCalls.get(callId); if (!call) return;
    const t = call.callerId === socket.userId ? call.calleeId : call.callerId;
    const s = getSocketByUserId(t); if (s) s.emit("webrtc-ice-candidate", { callId, candidate });
  });

  // ── Disconnect ────────────────────────────────────────────────────────
  socket.on("disconnect", () => {
    const userId = socket.userId;
    if (!userId) return;
    const userData = onlineUsers.get(userId);
    if (!userData) return;
    userData.disconnectedAt = Date.now();
    broadcastUserList();

    const timer = setTimeout(() => {
      for (const [callId, call] of activeCalls) {
        if (call.callerId === userId || call.calleeId === userId) {
          const otherUserId = call.callerId === userId ? call.calleeId : call.callerId;
          const otherSocket = getSocketByUserId(otherUserId);
          if (otherSocket) {
            otherSocket.emit("call-ended", {
              callId, duration: call.startedAt ? Math.floor((Date.now() - call.startedAt) / 1000) : 0,
            });
          }
          cleanupCall(callId);
        }
      }
      takenNames.delete(userData.name.toLowerCase());
      onlineUsers.delete(userId);
      disconnectTimers.delete(userId);
      broadcastUserList();
      console.log(`👋 ${userData.name} (${userId}) fully removed`);
    }, RECONNECT_GRACE_MS);
    disconnectTimers.set(userId, timer);
  });
});

app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`\n  🕐 OneMinute Server on http://localhost:${PORT} | Storage: ${supabase ? "Supabase" : "Local JSON"}\n`);
});
