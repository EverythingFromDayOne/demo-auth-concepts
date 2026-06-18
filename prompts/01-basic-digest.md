# Cursor Prompt — 01: Basic & Digest Auth
# Ports: 3049 (vulnerable) · 3050 (guide) · 3051 (secure)

Build three Node.js Express servers in `auth-concepts/basic-digest/` that teach HTTP Basic Auth.

---

## File structure to create

```
basic-digest/
  basic-server.js           ← port 3049, vulnerable
  guide-server.js           ← port 3050, guide
  session-server.js         ← port 3051, secure
  public/
    index.html              ← SimpleDesk dashboard SPA (for basic-server.js)
    style.css               ← SimpleDesk styles
    session-index.html      ← login + dashboard SPA (for session-server.js)
    session-style.css       ← session server styles
    guide.html              ← guide page
    guide.css               ← guide styles
  package.json
```

---

## package.json

```json
{
  "name": "basic-digest",
  "scripts": {
    "vulnerable": "node basic-server.js",
    "guide": "node guide-server.js",
    "secure": "node session-server.js",
    "start": "node basic-server.js"
  },
  "dependencies": { "express": "^4.18.2", "cors": "^2.8.5" }
}
```

---

## basic-server.js (port 3049) — vulnerable

Top comment:
```
* Terminal 1: cd auth-concepts/basic-digest && npm install && npm run vulnerable
* SimpleDesk — HTTP Basic Auth demo (port 3049)
```

**What it does:** IT helpdesk app (SimpleDesk) that protects every route with HTTP Basic Auth. Credentials are sent as `Authorization: Basic base64(username:password)` on every request — trivially decoded.

**Users:** `alice / pass1234`, `bob / qwerty123`, `admin / admin456`

**Tickets data (in-memory):**
- `{ id:1, title:'Printer not working', status:'open', priority:'low', author:'alice' }`
- `{ id:2, title:'VPN access request', status:'open', priority:'medium', author:'bob' }`
- `{ id:3, title:'Software license', status:'closed', priority:'low', author:'alice' }`

**Middleware `basicAuth`:** reads `Authorization` header, decodes base64, finds user. Returns 401 with `WWW-Authenticate: Basic realm="SimpleDesk"` if missing/wrong.

**Routes:**
- `GET /` — protected by basicAuth → serve `public/index.html`
- `GET /api/me` — protected by basicAuth → return `{ username, fullName, role }`
- `GET /api/tickets` — protected by basicAuth → return tickets array
- `GET /api/config` → return `{ mode: 'vulnerable', port: 3049 }`

**Static files:** `app.use(express.static(path.join(__dirname, 'public')))`

**`public/index.html`** — SimpleDesk dashboard:
- On load: `fetch('/api/config')` → set demo banner (orange: `background:#fffbeb; border-bottom:2px solid #f59e0b; color:#92400e`)
- Banner text: `⚠ BASIC AUTH: your credentials (username:password) are sent base64-encoded with EVERY request. Open DevTools → Network → any request → Authorization header to see them.`
- `fetch('/api/me')` → populate `<span id="user-display">` with `fullName (username)`
- `fetch('/api/tickets')` → render tickets table
- Clean sidebar layout: logo "SimplDesk", sidebar links (Tickets, Profile), main area with tickets table showing ID, Title, Priority (badge), Status (badge)

---

## guide-server.js (port 3050) — guide

Top comment: `* Terminal 2: cd auth-concepts/basic-digest && npm run guide`

Thin static server:
```js
const path = require('path');
const express = require('express');
const app = express();
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'guide.html')));
app.listen(3050, () => console.log('Guide at http://localhost:3050'));
```

**`public/guide.html`** — dark terminal-green theme (`#0a0a0a` bg, `#00ff41` text, `font-family: 'Courier New'`):
- Title: "Basic & Digest Auth"
- Target switcher (fixed bottom-left): "Vulnerable Basic Auth (3049)" button (dark slate `#1e293b`), "Hardened Session Auth (3051)" button (green `#16a34a`). Clicking switches `window.location.href`.
- Content: how Basic Auth works (base64 decode demo with interactive input), what Digest Auth adds (nonce, not covered here), why Base64 ≠ encryption, comparison table (Basic Auth vs Session tokens), the fix.

---

## session-server.js (port 3051) — secure

Top comment: `* Terminal 3: cd auth-concepts/basic-digest && npm run secure`

**What it does:** Same SimpleDesk app, but replaces HTTP Basic Auth with a session token issued at login. Credentials sent once, session token used thereafter.

**Routes:**
- `POST /api/login` → validate credentials → create session (`crypto.randomBytes(32).toString('hex')`) → set `Authorization: Bearer <token>` in response body (or store as cookie) → return `{ success: true, token }`
- `GET /api/me` — `requireAuth` → return user
- `GET /api/tickets` — `requireAuth` → return tickets
- `GET /api/config` → `{ mode: 'secure', port: 3051 }`
- Catch-all → `res.sendFile(path.join(__dirname, 'public', 'session-index.html'))`

**Static files:** `app.use(express.static(path.join(__dirname, 'public')))`

**`public/session-index.html`** — SPA with login form + dashboard:
- On load: `fetch('/api/config')` → banner (green: `background:#f0fdf4; border-bottom:2px solid #22c55e; color:#166534`)
- Banner text: `✅ SESSION TOKEN: credentials sent once at login. Subsequent requests use a session token — credentials never travel again.`
- `fetch('/api/me')` with stored token → if 401 show login form, if 200 show dashboard
- Login form → `POST /api/login` → store token in `sessionStorage` → reload
- Dashboard: same SimpleDesk layout as basic server
