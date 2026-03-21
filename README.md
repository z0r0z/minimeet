# minimeet.cc — mini meets

A browser-based video calling app where every call is limited to exactly **60 seconds**. Built with WebRTC for peer-to-peer video and Socket.IO for signaling.

## How It Works

```
┌──────────┐     Socket.IO      ┌──────────────────┐     Socket.IO      ┌──────────┐
│  Caller  │ ◄────────────────► │  Signaling Server │ ◄────────────────► │  Callee  │
│ (Browser)│                    │   (Node.js)       │                    │ (Browser)│
└────┬─────┘                    └──────────────────┘                    └────┬─────┘
     │                                                                       │
     │                    WebRTC (Peer-to-Peer)                              │
     │ ◄───────────────────────────────────────────────────────────────────► │
     │                  Video + Audio (direct)                               │
```

1. Users join by entering their name or signing in with X
2. The server tracks who's online and relays signaling messages
3. When a call is accepted, WebRTC establishes a direct peer-to-peer video connection
4. The server enforces a 60-second hard limit — when time's up, both sides are notified
5. Call ended screen shows duration and option to call again

## Features

- **1-minute video calls** — WebRTC peer-to-peer with 60-second timer
- **Live streaming** — go live and let others watch (1-to-many WebRTC)
- **Public chat** — global message board for all online users
- **Stream chat** — chat overlay for streamers and viewers
- **DMs** — ephemeral direct messages and pokes
- **Auto-Meet** — automatically call mutual contacts you haven't talked to recently
- **Contacts** — save users, see who's online/offline
- **X (Twitter) OAuth** — sign in with your X account
- **Avatars & stats** — profile pictures, pickup rates, streaks
- **Call links** — share a personal link to auto-call you

## Quick Start

```bash
# Install dependencies
npm install

# Start the server
npm start
```

Then open **http://localhost:3001** in two browser tabs (or two different devices on the same network).

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3001` | Server port |
| `SUPABASE_URL` | — | Supabase project URL (optional, falls back to local JSON) |
| `SUPABASE_KEY` | — | Supabase anon/service key |
| `X_CLIENT_ID` | — | X OAuth 2.0 client ID |
| `X_CLIENT_SECRET` | — | X OAuth 2.0 client secret |
| `X_CALLBACK_URL` | `http://localhost:3001/auth/x/callback` | OAuth callback URL |
| `TURN_SECRET` | — | Shared secret for HMAC-based TURN credentials |
| `TURN_URLS` | — | Comma-separated TURN server URLs |
| `ALLOWED_ORIGINS` | `http://localhost:3001,https://minimeet.cc` | CORS allowed origins |
| `AUTO_REACH_COOLDOWN_HOURS` | `24` | Default Auto-Meet cooldown |

## Supabase Tables

```sql
create table if not exists x_profiles (
  username text primary key,
  x_id text not null,
  display_name text,
  avatar text,
  updated_at timestamptz default now()
);

create table if not exists avatars (
  name text primary key,
  data text,
  updated_at timestamptz default now()
);

create table if not exists call_stats (
  name text primary key,
  received int default 0,
  accepted int default 0,
  declined int default 0,
  missed int default 0,
  streak int default 0,
  best_streak int default 0,
  updated_at timestamptz default now()
);

create table if not exists contacts (
  owner text not null,
  contact_name text not null,
  created_at timestamptz default now(),
  primary key (owner, contact_name)
);

create table if not exists last_calls (
  pair text primary key,
  called_at timestamptz default now()
);

create table if not exists user_prefs (
  name text primary key,
  auto_reach boolean default false,
  auto_reach_cooldown_hours integer default 24,
  updated_at timestamptz default now()
);

create table if not exists session_tokens (
  name text primary key,
  token_hash text not null,
  updated_at timestamptz default now()
);
```

## Architecture

### Server (`server.js`)

Express + Socket.IO signaling server. No media passes through the server — it only coordinates connections.

- **User registry** — tracks online users, names, avatars, stats in-memory (`onlineUsers` Map)
- **Call management** — initiation, accept/decline, 60s enforcement, ring timeout (20s), reconnect grace (15s)
- **Stream management** — 1-to-many live streams with per-viewer WebRTC peer connections
- **Chat relay** — public broadcast, stream-scoped, and ephemeral P2P direct messages
- **Auto-Meet** — periodic matcher (every 30s) pairs mutual contacts who haven't called recently
- **Persistence** — Supabase when configured, falls back to local JSON files in `/data/`
- **Auth** — X OAuth 2.0 with PKCE, guest session tokens (SHA-256 hashed)
- **Security** — rate limiting (calls, chat, pokes), CORS origin restriction, avatar size validation, server-side TURN credential generation

### Client (`public/index.html`)

Single-page app — all HTML, CSS, and JS in one file.

- **Screens** — login, contacts/lobby, call, stream, ended (plus incoming-call overlay and DM drawer)
- **WebRTC** — `RTCPeerConnection` per call; streamers maintain one PC per viewer
- **TURN credentials** — fetched from `/api/turn-credentials` on page load (HMAC short-lived)
- **Chat** — public chat panel (contacts screen), stream chat overlay, DM bottom-sheet
- **Responsive** — media queries for mobile (480px) and tiny screens (360px)

### Signaling Flow (Calls)

```
Caller                  Server                  Callee
  │                       │                       │
  │── call-user ─────────►│                       │
  │                       │──── incoming-call ───►│
  │◄── call-ringing ──────│                       │
  │                       │◄──── accept-call ─────│
  │◄── call-accepted ─────│──── call-accepted ───►│
  │                       │                       │
  │── webrtc-offer ──────►│──── webrtc-offer ────►│
  │                       │◄──── webrtc-answer ───│
  │◄── webrtc-answer ─────│                       │
  │                       │                       │
  │◄─── ice-candidates ──►│◄─── ice-candidates ──►│
  │                       │                       │
  │     [60 seconds pass]                         │
  │                       │                       │
  │◄── call-timeout ──────│──── call-timeout ────►│
```

### Streaming Flow

```
Streamer                Server                  Viewer
  │                       │                       │
  │── start-stream ──────►│                       │
  │◄── stream-started ────│                       │
  │                       │◄──── join-stream ─────│
  │◄── viewer-joined ─────│──── stream-joined ───►│
  │                       │                       │
  │── stream-offer ──────►│──── stream-offer ────►│
  │                       │◄──── stream-answer ───│
  │◄── stream-answer ─────│                       │
  │                       │                       │
  │◄─ ice-candidates ────►│◄── ice-candidates ───►│
  │                       │                       │
  │  [repeats per viewer]                         │
```

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/x` | Start X OAuth flow |
| GET | `/auth/x/callback` | OAuth callback |
| GET | `/auth/resolve/:token` | Resolve auth token to profile |
| GET | `/api/turn-credentials` | Get short-lived TURN credentials |

## Project Structure

```
├── server.js          # Signaling server (Express + Socket.IO)
├── package.json       # Dependencies
├── public/
│   └── index.html     # Full client app (HTML + CSS + JS)
└── README.md
```

## Browser Support

- Chrome 80+
- Firefox 80+
- Safari 14+
- Edge 80+

## License

MIT
