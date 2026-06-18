# Cursor Prompt — 05: Access + Refresh Tokens
# Ports: 3061 (vulnerable) · 3062 (guide) · 3063 (secure)

Build three Node.js Express servers in `auth-concepts/access-refresh/` that teach refresh token rotation.

---

## File structure to create

```
access-refresh/
  flow-server.js        ← port 3061, vulnerable
  guide-server.js       ← port 3062, guide
  flow-strong-server.js ← port 3063, secure
  public/
    index.html          ← dashboard SPA (shared)
    style.css
    guide.html
    guide.css
  package.json
```

---

## package.json

```json
{
  "name": "access-refresh",
  "scripts": {
    "vulnerable": "node flow-server.js",
    "guide": "node guide-server.js",
    "secure": "node flow-strong-server.js",
    "start": "node flow-server.js"
  },
  "dependencies": { "express": "^4.18.2", "cors": "^2.8.5", "jsonwebtoken": "^9.0.0" }
}
```

---

## Token design (both servers)

- **Access token:** JWT, short-lived (15 min). Payload: `{ sub, username, type: 'access' }`.
- **Refresh token:** opaque `crypto.randomBytes(32).toString('hex')`, stored in server-side Map.
- **Login returns:** `{ accessToken, refreshToken, expiresIn: 900 }`.

---

## flow-server.js (port 3061) — vulnerable

Top comment: `* Terminal 1: cd auth-concepts/access-refresh && npm install && npm run vulnerable`

**Vulnerability:** refresh tokens are never rotated. A stolen refresh token grants indefinite access.

**In-memory store:** `const refreshTokens = new Map(); // token → { username, createdAt }`

**Routes:**
- `POST /api/login` → issue accessToken + refreshToken, store in Map
- `POST /api/refresh` → if token in Map → issue new accessToken, **old refresh token kept valid** → return `{ accessToken }`
- `GET /api/resource` — requireAccess → return `{ data: '...', user: req.user }`
- `POST /api/logout` → delete refresh token from Map
- `GET /api/config` → `{ mode: 'vulnerable', port: 3061 }`
- Static + catch-all → `public/index.html`

---

## flow-strong-server.js (port 3063) — secure

Top comment: `* Terminal 3: cd auth-concepts/access-refresh && npm run secure`

**Fix:** refresh token rotation + reuse detection. Every use of a refresh token issues a new one and invalidates the old one. Reuse of an invalidated token revokes the entire family.

**Token family tracking:**
```js
// familyId groups tokens from same login session
// usedTokens Set tracks consumed tokens (for reuse detection)
const tokenFamilies = new Map(); // familyId → Set of valid tokens
const usedTokens = new Set();
```

**`POST /api/refresh` logic:**
1. If token in `usedTokens` → REUSE DETECTED → revoke entire family → 401
2. If token valid → mark old token as used → issue new accessToken + new refreshToken in same family → return both

**Routes:** same as vulnerable + rotation logic. `GET /api/config` → `{ mode: 'secure', port: 3063 }`.

---

## public/index.html — Token Flow Dashboard SPA (shared)

On load:
1. `fetch('/api/config')` → set banner:
   - vulnerable: orange — `⚠ NO ROTATION: refresh tokens never expire. A stolen token grants indefinite access.`
   - secure: green — `✅ TOKEN ROTATION: each refresh issues a new token. Reuse detection revokes the entire session family.`

**UI panels:**
- Login button → show accessToken (decoded) + refreshToken (truncated)
- Token status: access token expiry countdown, refresh token status
- "Use Resource" button → `GET /api/resource` with accessToken
- "Refresh Tokens" button → `POST /api/refresh` → update displayed tokens
- "Simulate Stolen Token" button (vulnerable mode): allow pasting an old refresh token and show it still works
- Token timeline visualization showing rotation vs no-rotation

---

## guide-server.js (port 3062) — guide

Top comment: `* Terminal 2: cd auth-concepts/access-refresh && npm run guide`

Thin static server serving `public/guide.html`.

**`public/guide.html`** — dark terminal-green theme:
- Title: "Access + Refresh Tokens"
- Target switcher: "Vulnerable Flow (3061)" dark slate, "Hardened Flow (3063)" green `#16a34a`
- Content: token lifecycle diagram (login → access → refresh → new access), why access tokens expire, what refresh token rotation prevents, reuse detection flow, family revocation on reuse, comparison table.
