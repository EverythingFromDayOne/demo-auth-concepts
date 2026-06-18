# Cursor Prompt — 04: JWT & Bearer
# Ports: 3058 (vulnerable) · 3059 (guide) · 3060 (secure)

Build three Node.js Express servers in `auth-concepts/jwt-bearer/` that teach JWT security.

---

## File structure to create

```
jwt-bearer/
  jwt-server.js         ← port 3058, vulnerable
  guide-server.js       ← port 3059, guide
  jwt-strong-server.js  ← port 3060, secure
  public/
    index.html          ← TaskFlow playground SPA (shared)
    style.css
    guide.html
    guide.css
  package.json
```

---

## package.json

```json
{
  "name": "jwt-bearer",
  "scripts": {
    "vulnerable": "node jwt-server.js",
    "guide": "node guide-server.js",
    "secure": "node jwt-strong-server.js",
    "start": "node jwt-server.js"
  },
  "dependencies": { "express": "^4.18.2", "cors": "^2.8.5", "jsonwebtoken": "^9.0.0" }
}
```

---

## Shared app: TaskFlow (task management API)

**Users:** `alice / pass1234`, `bob / qwerty123`

**Tasks data:** 3 sample tasks per user (id, title, status: open/done, dueDate)

---

## jwt-server.js (port 3058) — vulnerable

Top comment: `* Terminal 1: cd auth-concepts/jwt-bearer && npm install && npm run vulnerable`

**Vulnerability:** JWT signed with weak hardcoded secret `"secret"` and 24-hour expiry — brute-forceable offline.

```js
const SECRET = 'secret'; // ⚠️ Weak, hardcoded, brute-forceable
jwt.sign({ sub: user.id, username: user.username, role: 'user' }, SECRET, { expiresIn: '24h' })
```

**JWT verification:** `jwt.verify(token, SECRET)` — no algorithm restriction (accepts `{ algorithms: ['HS256', 'none'] }` — or omit algorithms entirely, leaving `alg:none` attack possible).

**Routes:**
- `POST /api/login` → validate creds → return `{ token: <jwt> }`
- `GET /api/tasks` — `Authorization: Bearer <token>` → requireJWT → return tasks
- `GET /api/me` — requireJWT → return user info
- `GET /api/config` → `{ mode: 'vulnerable', port: 3058 }`
- Static + catch-all → `public/index.html`

---

## jwt-strong-server.js (port 3060) — secure

Top comment: `* Terminal 3: cd auth-concepts/jwt-bearer && npm run secure`

**Fix:** 64-byte random secret generated at startup, 15-minute expiry, strict algorithm allowlist.

```js
const SECRET = require('crypto').randomBytes(64).toString('hex'); // ✅ Strong, ephemeral
jwt.sign({ sub: user.id, username: user.username, role: 'user' }, SECRET, { expiresIn: '15m', algorithm: 'HS256' })
jwt.verify(token, SECRET, { algorithms: ['HS256'] }) // ✅ No alg:none
```

**Routes:** same as vulnerable. `GET /api/config` → `{ mode: 'secure', port: 3060 }`.

---

## public/index.html — TaskFlow playground SPA (shared)

On load:
1. `fetch('/api/config')` → set banner:
   - vulnerable: orange — `⚠ WEAK JWT: signed with "secret" (brute-forceable) and 24h expiry. Paste token at jwt.io to inspect.`
   - secure: green — `✅ STRONG JWT: 64-byte random secret, 15min expiry, HS256 algorithm enforced.`

**UI panels:**
- Login form (username + password) → `POST /api/login` → store token in `sessionStorage`
- Token display: show raw JWT, decoded header + payload (base64 decode in JS)
- Task list: `GET /api/tasks` with stored token → display tasks
- Manual token test: paste any JWT → `GET /api/me` with it → show response

---

## guide-server.js (port 3059) — guide

Top comment: `* Terminal 2: cd auth-concepts/jwt-bearer && npm run guide`

Thin static server serving `public/guide.html`.

**`public/guide.html`** — dark terminal-green theme:
- Title: "JWT & Bearer Auth"
- Target switcher: "Vulnerable JWT (3058)" dark slate, "Hardened JWT (3060)" green `#16a34a`
- Content: JWT structure (header.payload.signature), interactive decoder (paste JWT → see decoded parts), algorithm confusion attack (`alg:none`), weak secret brute-force demo, comparison table (weak vs strong config), best practices (short expiry, strong secret, algorithm pinning, rotate on logout).
