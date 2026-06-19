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

---

## Inline Comments

Every `// ⚠️` and `// ✅` comment must answer three questions:

1. **What** is wrong (or fixed)
2. **Why** it is exploitable (or why the fix is safe)
3. **How** the attack works mechanically (step by step)

Format:
```js
// ⚠️ VULNERABLE — <one-line summary>
// <explanation: what is wrong, why it matters, how an attacker exploits it>
// <mechanical detail: what the attacker does step by step, what they gain>
const badThing = ...;

// ✅ PROTECTED — <one-line summary>
// <explanation: what the fix does and why it closes the attack vector>
// <mechanical detail: what would need to be true for this to still fail>
const goodThing = ...;
```

**Never shorten an existing comment. Only expand.**
Annotate **vulnerable servers and secure servers only** — never guide servers.

### basic-digest

**`basic-digest/basic-server.js`** — root causes to annotate:
- `basicAuth` function: credentials base64-encoded and sent on every request. `atob()` decodes them in one line in any browser console. No session = no logout. Every proxy log, CDN access log, and packet capture contains the plaintext-equivalent password.
- No token issuance: the server is stateless, so there is nothing to invalidate if credentials are compromised.

**`basic-digest/session-server.js`** — fixes to annotate:
- Password sent once at `POST /api/login`, then discarded. Subsequent requests use an opaque random token.
- `sessions.delete(token)` on logout genuinely invalidates access — server-side state makes revocation possible.
- Token stored in `localStorage` and sent via `Authorization: Bearer` header. Scope-limited: only code that runs in this origin can read it.

---

## README

Follow this canonical section order for this concept's `README.md`. Use `---` between every section:

```
# [Concept Name] — [App Name]
(one-paragraph description)
---
## Port Reference
---
## How It Works
---
## The Vulnerability
---
## The Fix
---
## How to Run
---
## Demo Walkthrough
---
## Hardened Demo
---
## Vulnerable Lines
---
## Defense Details
---
## Credentials   ← only if needed; always last
```

**Section rename mappings:**

| Old name | Canonical name |
|----------|----------------|
| `## How it works` | `## How It Works` |
| `## Vulnerability (port XXXX)` | `## The Vulnerability` |
| `## Fix (port XXXX)` | `## The Fix` |
| `## Run the demo` / `## Run` | `## How to Run` |
| `## Walkthrough` | `## Demo Walkthrough` |
| `## Hardened Demo` / `## Protected Demo` | `## Hardened Demo` |
| `## Key concepts` | `## Defense Details` |
| `## Demo credentials` / `## Demo API keys` | `## Credentials` |
| `## Ports` | `## Port Reference` |

**Script names to fix:**

| Old | Correct |
|-----|---------|
| `npm run basic` | `npm run vulnerable` |
| `npm run session` (in basic-digest) | `npm run secure` |
| `npm run url` | `npm run vulnerable` |
| `npm run header` | `npm run secure` |
| `npm run weak` | `npm run vulnerable` |
| `npm run strong` | `npm run secure` |
| `npm run hardened` | `npm run secure` |
| `npm run session` (in session/) | `npm run vulnerable` |

### Per-concept README instructions — basic-digest (SimpleDesk)

This README already has excellent deep content. **Do not delete any existing section.**
Restructure into canonical order and add the missing sections:

**`## Vulnerable Lines`** — add this section with:
```js
// ⚠️ VULNERABLE — HTTP Basic Auth sends base64(username:password) on every request.
// atob("YWxpY2U6cGFzczEyMzQ=") === "alice:pass1234" — one line in any browser console.
function basicAuth(req, res, next) {
  // ... Authorization: Basic <base64> checked on every single request
  res.setHeader('WWW-Authenticate', 'Basic realm="SimpleDesk"');
  return res.status(401).json({ error: 'Authentication required' });
}
```

**`## Defense Details`** — consolidate existing "Session Auth (port 3051)", "When Basic Auth is acceptable", "Digest Auth" sections under this heading with sub-headings:
- `### Why session tokens fix the problem`
- `### Digest Auth — the fix that wasn't`
- `### When Basic Auth is acceptable in the real world`

Keep all existing prose verbatim within those sub-sections.

**`## Hardened Demo`** — add:
1. Open `localhost:3051` — login with `alice / pass1234`
2. Open DevTools → Network → any request — `Authorization` header shows `Bearer a3f9...`, not base64 credentials
3. `POST /api/logout` → server calls `sessions.delete(token)` — the token is immediately invalid
4. Attempt the old `atob()` trick in the console — there is no `Authorization: Basic` header to decode
