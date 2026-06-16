# Basic & Digest Auth — SimpleDesk Demo

SimpleDesk is an internal IT helpdesk for submitting and tracking support tickets. This demo shows why HTTP Basic Auth is risky (credentials in every request) and how session tokens improve the model.

## How It Works

```
HTTP Basic Auth flow:
  Client                      Server
     │                           │
     ├─── GET /api/tickets ─────→│  401 + WWW-Authenticate: Basic
     │←── 401 ───────────────────┤
     │                           │
     ├─── GET /api/tickets ─────→│
     │    Authorization:         │
     │    Basic YWxpY2U6cGFzczEyMzQ=  │  ← atob() → "alice:pass1234"
     │←── 200 tickets ───────────┤
     │                           │
     │  (every request repeats   │
     │   the Authorization header)
```

## The vulnerability

`atob("YWxpY2U6cGFzczEyMzQ=")` → `"alice:pass1234"` — one line in any browser console. The password travels with every request and is visible in proxy logs, load balancer access logs, browser history (if embedded in URL), and any packet capture on the network.

## Run the demo

```bash
cd auth-concepts/basic-digest
npm install
npm run basic    # terminal 1 → localhost:3049 (Basic Auth)
npm run guide    # terminal 2 → localhost:3050 (concept guide)
npm run session  # terminal 3 → localhost:3051 (Session Auth)
```

## Walkthrough

1. Open **localhost:3049** — browser shows native Basic Auth dialog. Enter alice / pass1234.
2. Open DevTools → Network → any request → Headers → `Authorization: Basic YWxpY2U6cGFzczEyMzQ=`
3. Open **localhost:3050** — paste that header value into the decoder → see credentials instantly
4. Click "Send request → :3049 + show header" → see what's sent with every API call
5. Open **localhost:3051** — HTML login form, session token issued. Check Network: subsequent requests send `Bearer <token>`, not the password.

## Key concepts

**Base64 ≠ Encryption:** Base64 is a binary-to-text encoding format. It is completely reversible without a key. `atob(encoded)` decodes it instantly in any browser.

**Stateless by design (and that's the problem):** Because HTTP is stateless, Basic Auth re-sends credentials with every request. There is no server-side session — and therefore no way to "log out." The browser caches the credentials and keeps sending them until the tab is closed.

**Digest improves but doesn't solve it:** Digest Auth never sends the password, but the server must store password hashes in a crackable MD5 format. Modern databases use bcrypt/Argon2, which are incompatible with Digest. Digest is obsolete.

**When Basic Auth is acceptable:** Internal tools over HTTPS with a reverse proxy and HTTP Strict Transport Security — the TLS layer provides the encryption that Basic Auth lacks. Still can't logout. Still can't do MFA. Session tokens are almost always better.

## Ports

| Port | Server | Role |
|------|--------|------|
| 3049 | `basic-server.js` | HTTP Basic Auth — credentials base64-encoded on every request |
| 3050 | `guide-server.js` | Concept guide — decoder, intercept demo, comparison table |
| 3051 | `session-server.js` | Improved — session token via `Authorization: Bearer` |

## Demo credentials

| Username | Password |
|----------|----------|
| alice | pass1234 |
| bob | qwerty123 |
| admin | admin456 |
