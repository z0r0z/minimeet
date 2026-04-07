# MiniMeet Trollbox Integration Guide

Embed the MiniMeet public trollbox into your external dapp. Users connect their wallet, get reverse-resolved `.eth`/`.wei` display names, and chat in a shared global room — messages appear on both your dapp and [minimeet.cc](https://minimeet.cc) in real time.

---

## Architecture Overview

```
Your Dapp (client)
  ├── Wallet connect (wagmi / ethers / WalletConnect)
  ├── EIP-191 signature for auth
  ├── Socket.IO client → wss://minimeet.cc
  │     ├── "register" (wallet-auth'd)
  │     ├── "chat-public" (send)
  │     ├── "chat-public" (receive)
  │     ├── "chat-history" (load last 50)
  │     ├── "chat-react" (send/receive)
  │     └── "chat-history" (receive)
  └── ENS/.wei reverse resolution (ethers.js on-chain)
```

Messages are stored in MiniMeet's Supabase backend (`public_messages` table) and broadcast via Socket.IO to all connected clients — including the main MiniMeet app.

---

## Prerequisites

- **Socket.IO client** v4.x (`socket.io-client`)
- **ethers.js** v6.x (wallet signing + ENS/.wei resolution)
- A web3 wallet provider (MetaMask, WalletConnect, etc.)
- Your dapp's origin added to MiniMeet's `ALLOWED_ORIGINS` (coordinate with MiniMeet admin)

---

## Step 1: CORS — Allow Your Origin

MiniMeet's Socket.IO server restricts connections to whitelisted origins. Your dapp's domain must be added to the `ALLOWED_ORIGINS` environment variable on the MiniMeet server:

```bash
# On MiniMeet server
ALLOWED_ORIGINS=https://minimeet.cc,https://yourdapp.com
```

Without this, Socket.IO connections from your dapp will be rejected with a CORS error.

---

## Step 2: Wallet Auth Flow

MiniMeet uses EIP-191 message signing with a server-issued nonce. The flow:

1. **Request nonce** — `GET https://minimeet.cc/auth/wallet/nonce?address=0x...`
2. **Sign message** — User signs `"Sign in to minimeet.cc\n\nNonce: <nonce>"` with their wallet
3. **Register via Socket.IO** — Send the signature in the `register` event

### Nonce Request

```js
async function getNonce(address) {
  const res = await fetch(
    `https://minimeet.cc/auth/wallet/nonce?address=${encodeURIComponent(address)}`
  );
  if (!res.ok) throw new Error("Failed to get nonce");
  return res.json(); // { message, nonce }
}
```

**Rate limit:** 10 nonce requests per IP per minute. Nonces expire after 5 minutes.

### Sign the Message

```js
async function signAuth(signer, address) {
  const { message, nonce } = await getNonce(address);
  const signature = await signer.signMessage(message);
  return { signature, nonce };
}
```

---

## Step 3: Reverse Resolve Display Name (.wei / .eth)

Before connecting, resolve the wallet address to a human-readable name. MiniMeet checks `.wei` first, then `.eth`, then falls back to a truncated address.

```js
import { ethers } from "ethers";

const RPC_URL = "https://ethereum.publicnode.com";

async function resolveDisplayName(address) {
  const timeout = (p, ms) =>
    Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), ms))]);

  const rpc = new ethers.JsonRpcProvider(RPC_URL, 1, { staticNetwork: true });

  // 1. Try .wei reverse resolution
  try {
    const ns = new ethers.Contract(
      "0x0000000000696760E15f265e828DB644A0c242EB",
      ["function reverseResolve(address) view returns (string)"],
      rpc
    );
    const weiName = await timeout(ns.reverseResolve(address), 5000);
    if (weiName) return weiName.toLowerCase();
  } catch {}

  // 2. Try ENS .eth reverse resolution
  try {
    const ensName = await timeout(rpc.lookupAddress(address), 5000);
    if (ensName) return ensName.toLowerCase();
  } catch {}

  // 3. Fallback: truncated address
  return address.slice(0, 6) + "..." + address.slice(-4);
}
```

---

## Step 4: Connect Socket.IO & Register

```js
import { io } from "socket.io-client";

const MINIMEET_URL = "https://minimeet.cc";

let socket = null;
let myUserId = null;

async function connectTrollbox(signer) {
  const address = (await signer.getAddress()).toLowerCase();
  const displayName = await resolveDisplayName(address);
  const { signature, nonce } = await signAuth(signer, address);

  socket = io(MINIMEET_URL, {
    transports: ["websocket", "polling"],
    reconnection: true,
    reconnectionAttempts: Infinity,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 10000,
  });

  socket.on("connect", () => {
    socket.emit("register", {
      name: displayName,
      walletAddress: address,
      walletSignature: signature,
      walletNonce: nonce,
    });
  });

  socket.on("registered", (data) => {
    myUserId = data.userId;
    // Request chat history
    socket.emit("chat-history");
  });

  socket.on("register-error", ({ message }) => {
    console.error("Trollbox register failed:", message);
  });

  // Listen for events
  socket.on("chat-public", onNewMessage);
  socket.on("chat-history", onHistory);
  socket.on("chat-react", onReaction);
}
```

### Reconnection

On reconnect, re-register with `reconnectUserId` to reclaim your session:

```js
socket.on("reconnect", () => {
  socket.emit("register", {
    name: displayName,
    reconnectUserId: myUserId,
    walletAddress: address,
  });
});
```

---

## Step 5: Send & Receive Messages

### Send a Message

```js
function sendMessage(text) {
  if (!socket || !myUserId) return;
  const trimmed = text.trim().slice(0, 500);
  if (!trimmed) return;
  socket.emit("chat-public", { text: trimmed });
}
```

**Rate limit:** 10 messages per 10 seconds per user.

### Receive Messages

```js
// Single new message
function onNewMessage(msg) {
  // msg = { id, userId, name, avatar, text, image, ts, xUsername, walletAddress }
  appendMessage(msg);
}

// Initial history (last 50 messages)
function onHistory(messages) {
  clearMessages();
  messages.forEach(appendMessage);
}
```

### Message Shape

```ts
interface ChatMessage {
  id: string;           // 10-char unique ID
  userId: string;       // 8-char user session ID
  name: string;         // display name (ENS/wei/truncated addr)
  avatar: string | null;// data:image base64 or null
  xUsername: string | null;
  walletAddress: string | null;
  text: string;         // message text (max 500 chars)
  image: string | null; // data:image base64 (max 500KB) or null
  ts: number;           // Unix timestamp in ms
  reactions?: Record<string, string>; // { [userId]: emoji }
}
```

---

## Step 6: Reactions

```js
// Toggle a reaction
function toggleReaction(msgId, emoji) {
  socket.emit("chat-react", { msgId, emoji });
}

// Receive updated reactions
function onReaction({ msgId, reactions }) {
  // reactions = { [userId]: emoji }
  updateReactionDisplay(msgId, reactions);
}
```

Available emojis (matches MiniMeet UI): `👍 ❤️ 😂 🔥 👀 🙏`

**Rate limit:** 20 reactions per 10 seconds.

---

## Step 7: Render the Chat UI

Below is a minimal embeddable widget. Adapt the styling to match your dapp.

```html
<div id="trollbox" style="
  position: fixed; bottom: 0; right: 20px;
  width: 360px; max-height: 450px;
  background: #0A0A0F; border: 1px solid rgba(255,255,255,0.08);
  border-radius: 12px 12px 0 0; display: flex; flex-direction: column;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  color: #EEEEF0; z-index: 9999;
">
  <div style="padding: 10px 14px; border-bottom: 1px solid rgba(255,255,255,0.06); font-size: 13px; font-weight: 600; cursor: pointer;" onclick="toggleTrollbox()">
    Trollbox <span id="tb-unread" style="display:none; background:#E8453C; color:#fff; border-radius:10px; padding:1px 6px; font-size:11px; margin-left:6px;">0</span>
  </div>
  <div id="tb-messages" style="flex:1; overflow-y:auto; padding:8px; min-height:200px; max-height:350px;"></div>
  <div style="display:flex; gap:6px; padding:8px; border-top:1px solid rgba(255,255,255,0.06);">
    <input id="tb-input" type="text" maxlength="500" placeholder="Say something..."
      style="flex:1; background:rgba(255,255,255,0.06); border:1px solid rgba(255,255,255,0.1); border-radius:8px; padding:8px 10px; color:#EEEEF0; font-size:13px; outline:none;"
    />
    <button onclick="tbSend()" style="background:#E8453C; border:none; color:#fff; border-radius:8px; padding:6px 14px; font-size:13px; cursor:pointer;">Send</button>
  </div>
</div>
```

### Rendering Logic

```js
function appendMessage(msg) {
  const container = document.getElementById("tb-messages");
  const el = document.createElement("div");
  el.dataset.msgId = msg.id;
  el.style.cssText = "display:flex; gap:8px; padding:4px 0; font-size:13px;";

  const color = stringToColor(msg.name);
  const time = new Date(msg.ts);
  const hh = String(time.getHours()).padStart(2, "0");
  const mm = String(time.getMinutes()).padStart(2, "0");

  // Build display name with wallet link
  let displayName = escapeHtml(msg.name);
  if (msg.walletAddress && !msg.name.includes("...") && !msg.name.endsWith(".wei") && !msg.name.endsWith(".eth")) {
    const short = msg.walletAddress.slice(0, 6) + "..." + msg.walletAddress.slice(-4);
    displayName += ` <a href="https://etherscan.io/address/${msg.walletAddress}" target="_blank" style="color:#888;text-decoration:none;">${short}</a>`;
  }

  el.innerHTML = `
    <div style="flex-shrink:0; width:28px; height:28px; border-radius:50%; background:${msg.avatar ? `url(${msg.avatar}) center/cover` : color}; display:flex; align-items:center; justify-content:center;">
      ${msg.avatar ? "" : `<span style="font-size:10px;font-weight:700;color:#fff">${msg.name.slice(0,2).toUpperCase()}</span>`}
    </div>
    <div style="min-width:0;">
      <span style="color:${color};font-weight:600;">${displayName}</span>
      <span style="color:#555;font-size:11px;margin-left:6px;">${hh}:${mm}</span>
      ${msg.text ? `<div style="margin-top:2px;word-break:break-word;">${linkify(escapeHtml(msg.text))}</div>` : ""}
      ${msg.image ? `<img src="${escapeHtml(msg.image)}" style="max-width:180px;max-height:120px;border-radius:6px;margin-top:4px;display:block;cursor:pointer;" onclick="window.open(this.src)">` : ""}
    </div>
  `;
  container.appendChild(el);
  container.scrollTop = container.scrollHeight;
}

function clearMessages() {
  document.getElementById("tb-messages").innerHTML = "";
}

function tbSend() {
  const input = document.getElementById("tb-input");
  sendMessage(input.value);
  input.value = "";
}

// Enter to send
document.getElementById("tb-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); tbSend(); }
});
```

### Utility Functions

```js
function escapeHtml(s) {
  return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function linkify(text) {
  return text.replace(/(https?:\/\/[^\s<]+)/g, '<a href="$1" target="_blank" rel="noopener" style="color:#7B8CFF;">$1</a>');
}

function stringToColor(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) hash = str.charCodeAt(i) + ((hash << 5) - hash);
  return `hsl(${hash % 360}, 70%, 60%)`;
}
```

---

## Complete Minimal Example

```html
<!DOCTYPE html>
<html>
<head>
  <title>My Dapp + Trollbox</title>
  <script src="https://cdn.socket.io/4.8.3/socket.io.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/ethers/6.16.0/ethers.umd.min.js"></script>
</head>
<body>
  <!-- Your dapp content here -->

  <!-- Trollbox widget (paste the HTML from Step 7 here) -->

  <script>
    const MINIMEET_URL = "https://minimeet.cc";
    const WEI_REGISTRY = "0x0000000000696760E15f265e828DB644A0c242EB";
    const RPC_URL = "https://ethereum.publicnode.com";

    let socket, myUserId, displayName, walletAddr;

    // --- Wallet Connect (use your existing provider) ---
    async function connectWallet() {
      if (!window.ethereum) return alert("No wallet detected");
      const provider = new ethers.BrowserProvider(window.ethereum);
      const signer = await provider.getSigner();
      walletAddr = (await signer.getAddress()).toLowerCase();

      // Resolve display name
      displayName = await resolveDisplayName(walletAddr);

      // Get nonce & sign
      const nonceRes = await fetch(`${MINIMEET_URL}/auth/wallet/nonce?address=${walletAddr}`);
      const { message, nonce } = await nonceRes.json();
      const signature = await signer.signMessage(message);

      // Connect socket
      socket = io(MINIMEET_URL, {
        transports: ["websocket", "polling"],
        reconnection: true,
        reconnectionAttempts: Infinity,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 10000,
      });

      socket.on("connect", () => {
        socket.emit("register", {
          name: displayName,
          walletAddress: walletAddr,
          walletSignature: signature,
          walletNonce: nonce,
        });
      });

      socket.on("registered", (data) => {
        myUserId = data.userId;
        socket.emit("chat-history");
      });

      socket.on("register-error", ({ message }) => alert("Auth failed: " + message));
      socket.on("chat-public", appendMessage);
      socket.on("chat-history", (msgs) => { clearMessages(); msgs.forEach(appendMessage); });
      socket.on("chat-react", ({ msgId, reactions }) => updateReactionDisplay(msgId, reactions));

      socket.on("reconnect", () => {
        socket.emit("register", {
          name: displayName,
          reconnectUserId: myUserId,
          walletAddress: walletAddr,
        });
      });
    }

    async function resolveDisplayName(address) {
      const timeout = (p, ms) => Promise.race([p, new Promise((_, r) => setTimeout(() => r(), ms))]);
      const rpc = new ethers.JsonRpcProvider(RPC_URL, 1, { staticNetwork: true });

      try {
        const ns = new ethers.Contract(WEI_REGISTRY,
          ["function reverseResolve(address) view returns (string)"], rpc);
        const w = await timeout(ns.reverseResolve(address), 5000);
        if (w) return w.toLowerCase();
      } catch {}

      try {
        const e = await timeout(rpc.lookupAddress(address), 5000);
        if (e) return e.toLowerCase();
      } catch {}

      return address.slice(0, 6) + "..." + address.slice(-4);
    }

    // --- Paste escapeHtml, linkify, stringToColor, appendMessage, clearMessages, tbSend from Step 7 ---
  </script>
</body>
</html>
```

---

## Important Notes

### Server-Side Requirements (MiniMeet Admin)

1. **Add your origin** to `ALLOWED_ORIGINS` env var
2. **Update CSP** `connect-src` to allow your domain's requests if needed
3. **Update `X-Frame-Options`** if you plan to iframe MiniMeet (currently set to `DENY`)

### Rate Limits

| Action | Limit |
|--------|-------|
| Nonce requests | 10/min per IP |
| Chat messages | 10 per 10s per user |
| Reactions | 20 per 10s per user |
| Message length | 500 chars max |
| Image size | 500KB max (data:image/* base64) |

### Security Notes

- The nonce signing message is hardcoded to `"Sign in to minimeet.cc\n\nNonce: <nonce>"` — your users will see this in their wallet signing prompt
- Nonces are single-use and expire after 5 minutes
- Wallet signature is verified server-side using `ethers.verifyMessage`
- All message text is limited to 500 chars and images to 500KB

### What Users See

- On your dapp: wallet-connected users see messages from both your dapp and minimeet.cc
- On minimeet.cc: users see messages from your dapp users with their resolved `.eth`/`.wei` names
- Display name resolution: `.wei` domains checked first, then `.eth` ENS, then truncated `0x1234...abcd`
- If a wallet user's name already ends in `.eth` or `.wei`, no redundant address suffix is shown

### Session Persistence

The MiniMeet server issues a `sessionToken` on registration (returned in the `registered` event). Store it in `localStorage` and pass it on future `register` calls to reclaim the same username without re-signing:

```js
socket.on("registered", (data) => {
  myUserId = data.userId;
  if (data.sessionToken) localStorage.setItem("mm_session", data.sessionToken);
});

// On next connect:
socket.emit("register", {
  name: displayName,
  walletAddress: walletAddr,
  sessionToken: localStorage.getItem("mm_session"),
});
```

---

## Socket.IO Events Reference

| Event | Direction | Payload | Description |
|-------|-----------|---------|-------------|
| `register` | client → server | `{ name, walletAddress, walletSignature, walletNonce, reconnectUserId?, sessionToken? }` | Authenticate & join |
| `registered` | server → client | `{ userId, sessionToken, users, ... }` | Auth success |
| `register-error` | server → client | `{ message }` | Auth failure |
| `chat-public` | client → server | `{ text, image? }` | Send message |
| `chat-public` | server → client | `{ id, userId, name, avatar, text, image, ts, xUsername, walletAddress }` | New message broadcast |
| `chat-history` | client → server | `{}` | Request last 50 messages |
| `chat-history` | server → client | `ChatMessage[]` | History response |
| `chat-react` | client → server | `{ msgId, emoji }` | Toggle reaction |
| `chat-react` | server → client | `{ msgId, reactions }` | Updated reactions |
