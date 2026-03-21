const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const fs = require("fs");

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
  pingTimeout: 30000,
  pingInterval: 10000,
  maxHttpBufferSize: 1e6,
});

// ─── Avatar Persistence (Supabase with JSON fallback) ───────────────────────

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
let supabase = null;

if (SUPABASE_URL && SUPABASE_KEY) {
  const { createClient } = require("@supabase/supabase-js");
  supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
  console.log("✅ Supabase connected for avatar storage");
} else {
  console.log("⚠️ No SUPABASE_URL/SUPABASE_KEY — falling back to local JSON file");
}

// In-memory cache so we don't hit the DB on every user-list broadcast
const avatarCache = new Map(); // lowercase name → data URL

// ── Supabase methods ────────────────────────────────────────────────────────

async function dbGetAvatar(name) {
  const key = name.toLowerCase().trim();

  // Check cache first
  if (avatarCache.has(key)) return avatarCache.get(key);

  if (supabase) {
    try {
      const { data, error } = await supabase
        .from("avatars")
        .select("data")
        .eq("name", key)
        .single();

      if (!error && data) {
        avatarCache.set(key, data.data);
        return data.data;
      }
    } catch (e) {
      console.warn("Supabase read error:", e.message);
    }
    return null;
  }

  // JSON fallback
  return jsonGetAvatar(key);
}

async function dbSetAvatar(name, dataUrl) {
  const key = name.toLowerCase().trim();

  if (dataUrl) {
    avatarCache.set(key, dataUrl);
  } else {
    avatarCache.delete(key);
  }

  if (supabase) {
    try {
      if (dataUrl) {
        await supabase
          .from("avatars")
          .upsert({ name: key, data: dataUrl, updated_at: new Date().toISOString() });
      } else {
        await supabase
          .from("avatars")
          .delete()
          .eq("name", key);
      }
    } catch (e) {
      console.warn("Supabase write error:", e.message);
    }
    return;
  }

  // JSON fallback
  jsonSetAvatar(key, dataUrl);
}

// ── JSON file fallback (for local dev without Supabase) ─────────────────────

const AVATAR_FILE = path.join(__dirname, "data", "avatars.json");
let jsonAvatars = null;

function loadJsonAvatars() {
  if (jsonAvatars !== null) return jsonAvatars;
  try {
    const dir = path.dirname(AVATAR_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    if (fs.existsSync(AVATAR_FILE)) {
      jsonAvatars = JSON.parse(fs.readFileSync(AVATAR_FILE, "utf-8"));
    } else {
      jsonAvatars = {};
    }
  } catch {
    jsonAvatars = {};
  }
  return jsonAvatars;
}

function saveJsonAvatars() {
  try {
    const dir = path.dirname(AVATAR_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(AVATAR_FILE, JSON.stringify(jsonAvatars), "utf-8");
  } catch (e) {
    console.warn("JSON file write error:", e.message);
  }
}

function jsonGetAvatar(key) {
  const store = loadJsonAvatars();
  return store[key] || null;
}

function jsonSetAvatar(key, dataUrl) {
  const store = loadJsonAvatars();
  if (dataUrl) {
    store[key] = dataUrl;
  } else {
    delete store[key];
  }
  saveJsonAvatars();
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
  if (!onlineUsers.has(existingUserId)) {
    takenNames.delete(lower);
    return false;
  }
  return true;
}

function isUserInCall(userId) {
  for (const [, call] of activeCalls) {
    if (call.callerId === userId || call.calleeId === userId) return true;
  }
  return false;
}

// ─── Socket.IO Events ──────────────────────────────────────────────────────

io.on("connection", (socket) => {
  console.log(`⚡ Socket connected: ${socket.id}`);

  // ── Register ──────────────────────────────────────────────────────────
  socket.on("register", async ({ name, reconnectUserId, avatar }) => {
    const trimmedName = name.trim();

    // Attempt reconnection
    if (reconnectUserId && onlineUsers.has(reconnectUserId)) {
      const existingUser = onlineUsers.get(reconnectUserId);

      if (disconnectTimers.has(reconnectUserId)) {
        clearTimeout(disconnectTimers.get(reconnectUserId));
        disconnectTimers.delete(reconnectUserId);
      }

      existingUser.socketId = socket.id;
      existingUser.disconnectedAt = null;
      existingUser.status = "online";

      if (avatar) {
        existingUser.avatar = avatar;
        await dbSetAvatar(existingUser.name, avatar);
      }

      socket.userId = reconnectUserId;

      const resolvedAvatar = existingUser.avatar || await dbGetAvatar(existingUser.name);
      existingUser.avatar = resolvedAvatar;

      socket.emit("registered", {
        userId: reconnectUserId,
        name: existingUser.name,
        reconnected: true,
        avatar: resolvedAvatar,
      });

      broadcastUserList();
      console.log(`🔄 ${existingUser.name} reconnected as ${reconnectUserId}`);
      return;
    }

    // Check for duplicate name
    if (isNameTaken(trimmedName)) {
      socket.emit("register-error", {
        message: `"${trimmedName}" is already taken. Try a different name.`,
      });
      return;
    }

    const userId = uuidv4().slice(0, 8);
    socket.userId = userId;

    // Resolve avatar: client-sent > database-stored > null
    const storedAvatar = await dbGetAvatar(trimmedName);
    const resolvedAvatar = avatar || storedAvatar || null;

    if (avatar && avatar !== storedAvatar) {
      await dbSetAvatar(trimmedName, avatar);
    }

    onlineUsers.set(userId, {
      socketId: socket.id,
      name: trimmedName,
      status: "online",
      avatar: resolvedAvatar,
      disconnectedAt: null,
    });

    takenNames.set(trimmedName.toLowerCase(), userId);

    socket.emit("registered", {
      userId,
      name: trimmedName,
      reconnected: false,
      avatar: resolvedAvatar,
    });
    broadcastUserList();
    console.log(`✅ ${trimmedName} registered as ${userId}${resolvedAvatar ? " (with avatar)" : ""}`);
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
    console.log(`🖼️ ${userData.name} updated avatar`);
  });

  // ── Initiate Call ─────────────────────────────────────────────────────
  socket.on("call-user", ({ calleeId }) => {
    const callerId = socket.userId;
    const caller = onlineUsers.get(callerId);
    const callee = onlineUsers.get(calleeId);

    if (!callee || callee.disconnectedAt) {
      socket.emit("call-error", { message: "User is offline" });
      return;
    }

    if (isUserInCall(calleeId)) {
      socket.emit("call-error", { message: `${callee.name} is already in a call` });
      return;
    }

    if (isUserInCall(callerId)) {
      socket.emit("call-error", { message: "You are already in a call" });
      return;
    }

    const callId = uuidv4().slice(0, 12);

    const ringTimerId = setTimeout(() => {
      const call = activeCalls.get(callId);
      if (call && !call.startedAt) {
        socket.emit("call-not-answered", { callId });
        const calleeSocket = getSocketByUserId(calleeId);
        if (calleeSocket) calleeSocket.emit("call-cancelled", { callId });
        cleanupCall(callId);
      }
    }, RING_TIMEOUT_MS);

    activeCalls.set(callId, {
      callerId,
      calleeId,
      startedAt: null,
      timerId: null,
      ringTimerId,
    });

    const calleeSocket = getSocketByUserId(calleeId);
    if (calleeSocket) {
      calleeSocket.emit("incoming-call", {
        callId,
        callerId,
        callerName: caller.name,
        callerAvatar: caller.avatar || null,
      });
    }

    socket.emit("call-ringing", {
      callId,
      calleeId,
      calleeName: callee.name,
      calleeAvatar: callee.avatar || null,
    });
    console.log(`📞 ${caller.name} calling ${callee.name} [${callId}]`);
  });

  // ── Accept Call ───────────────────────────────────────────────────────
  socket.on("accept-call", ({ callId }) => {
    const call = activeCalls.get(callId);
    if (!call) return;

    clearTimeout(call.ringTimerId);
    call.startedAt = Date.now();

    call.timerId = setTimeout(() => {
      const callerSocket = getSocketByUserId(call.callerId);
      const calleeSocket = getSocketByUserId(call.calleeId);
      if (callerSocket) callerSocket.emit("call-timeout", { callId });
      if (calleeSocket) calleeSocket.emit("call-timeout", { callId });
      cleanupCall(callId);
      console.log(`⏰ Call ${callId} auto-ended (60s limit)`);
    }, CALL_DURATION_MS);

    const callerSocket = getSocketByUserId(call.callerId);
    if (callerSocket) callerSocket.emit("call-accepted", { callId });
    socket.emit("call-accepted", { callId });
    console.log(`✅ Call ${callId} accepted — 60s timer started`);
  });

  // ── Decline Call ──────────────────────────────────────────────────────
  socket.on("decline-call", ({ callId }) => {
    const call = activeCalls.get(callId);
    if (!call) return;
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
    console.log(`🔚 Call ${callId} ended by user (${duration}s)`);
  });

  // ── WebRTC Signaling ──────────────────────────────────────────────────
  socket.on("webrtc-offer", ({ callId, sdp }) => {
    const call = activeCalls.get(callId);
    if (!call) return;
    const targetId = call.callerId === socket.userId ? call.calleeId : call.callerId;
    const targetSocket = getSocketByUserId(targetId);
    if (targetSocket) targetSocket.emit("webrtc-offer", { callId, sdp });
  });

  socket.on("webrtc-answer", ({ callId, sdp }) => {
    const call = activeCalls.get(callId);
    if (!call) return;
    const targetId = call.callerId === socket.userId ? call.calleeId : call.callerId;
    const targetSocket = getSocketByUserId(targetId);
    if (targetSocket) targetSocket.emit("webrtc-answer", { callId, sdp });
  });

  socket.on("webrtc-ice-candidate", ({ callId, candidate }) => {
    const call = activeCalls.get(callId);
    if (!call) return;
    const targetId = call.callerId === socket.userId ? call.calleeId : call.callerId;
    const targetSocket = getSocketByUserId(targetId);
    if (targetSocket) targetSocket.emit("webrtc-ice-candidate", { callId, candidate });
  });

  // ── Disconnect ────────────────────────────────────────────────────────
  socket.on("disconnect", () => {
    const userId = socket.userId;
    if (!userId) return;
    const userData = onlineUsers.get(userId);
    if (!userData) return;

    userData.disconnectedAt = Date.now();
    broadcastUserList();
    console.log(`⏳ ${userData.name} disconnected — ${RECONNECT_GRACE_MS / 1000}s grace period...`);

    const timer = setTimeout(() => {
      for (const [callId, call] of activeCalls) {
        if (call.callerId === userId || call.calleeId === userId) {
          const otherUserId = call.callerId === userId ? call.calleeId : call.callerId;
          const otherSocket = getSocketByUserId(otherUserId);
          if (otherSocket) {
            otherSocket.emit("call-ended", {
              callId,
              duration: call.startedAt ? Math.floor((Date.now() - call.startedAt) / 1000) : 0,
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

// ─── Serve static frontend ─────────────────────────────────────────────────

app.use(express.static(path.join(__dirname, "public")));

// ─── Start ──────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
  console.log(`
  ╔═══════════════════════════════════════════╗
  ║   🕐 OneMinute Signaling Server           ║
  ║   Running on http://localhost:${PORT}        ║
  ║   60-second calls enforced server-side    ║
  ║   Avatars: ${supabase ? "Supabase ✅" : "Local JSON (no DB)"}            ║
  ╚═══════════════════════════════════════════╝
  `);
});
