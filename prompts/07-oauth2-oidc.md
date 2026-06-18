# Cursor Prompt — 07: OAuth2 & OIDC
# Ports: 3067 (vulnerable) · 3068 (guide) · 3069 (secure)

Build three Node.js Express servers in `auth-concepts/oauth2-oidc/` that teach OAuth2 state parameter and PKCE.

---

## File structure to create

```
oauth2-oidc/
  oauth-server.js         ← port 3067, vulnerable
  guide-server.js         ← port 3068, guide
  oauth-strong-server.js  ← port 3069, secure
  public/
    index.html            ← ConnectApp home + dashboard SPA (static)
    style.css
    guide.html
    guide.css
  package.json
```

---

## package.json

```json
{
  "name": "oauth2-oidc",
  "scripts": {
    "vulnerable": "node oauth-server.js",
    "guide": "node guide-server.js",
    "secure": "node oauth-strong-server.js",
    "start": "node oauth-server.js"
  },
  "dependencies": { "express": "^4.18.2", "cors": "^2.8.5" }
}
```

---

## Architecture

Each server simulates both **ConnectApp** (OAuth client app) and **GrantID** (OAuth authorization server / IdP) in one Express app:

- `/`, `/dashboard`, `/callback`, `/api/*` → ConnectApp
- `/auth/authorize`, `/auth/login`, `/auth/token` → GrantID IdP

**Registered client:**
```js
const CLIENT = {
  clientId: 'connectapp-client-id',
  clientSecret: 'connectapp-secret',
  redirectUri: 'http://localhost:PORT/callback', // PORT = 3067 or 3069
  scopes: ['openid', 'profile', 'email']
}
```

**GrantID users:** `alice / pass1234 (email: alice@corp.com)`, `bob / qwerty123 (email: bob@corp.com)`

**Auth codes:** opaque `crypto.randomBytes(8).toString('hex')`, stored in Map with `{ userId, scopes, codeChallenge?, codeChallengeMethod?, expiresAt }`.

---

## ⚠ SSR REQUIRED FOR AUTHORIZE PAGE — DO NOT CONVERT TO STATIC

The `/auth/authorize` consent page MUST use `res.send(AUTHORIZE_HTML(opts))` because:
- `client_id`, `redirect_uri`, `state`, `scope` come from query string and must be embedded in `<input type="hidden">` form fields for the form POST to `/auth/login`
- In the secure server: `code_challenge` and `code_challenge_method` are also embedded

The ConnectApp home (`/`) and dashboard (`/dashboard`) ARE served statically from `public/`.

```js
// Keep as SSR — OAuth params must be in hidden form fields
app.get('/auth/authorize', (req, res) => {
  const { client_id, redirect_uri, scope, state, code_challenge, code_challenge_method } = req.query;
  res.send(AUTHORIZE_HTML({ clientId: client_id, redirectUri: redirect_uri, scope, state, codeChallenge: code_challenge, codeChallengeMethod: code_challenge_method }));
});
```

---

## oauth-server.js (port 3067) — vulnerable

Top comment: `* Terminal 1: cd auth-concepts/oauth2-oidc && npm install && npm run vulnerable`

**Vulnerability:** ConnectApp does NOT generate or validate `state` parameter → CSRF attack possible. Attacker can trick victim into `/callback?code=ATTACKER_CODE` → victim's app linked to attacker's account.

**`GET /` (ConnectApp home):** serve `public/index.html` via `res.sendFile`

**`GET /auth/authorize`:** SSR → AUTHORIZE_HTML (no state in hidden fields for vulnerable version — or show it as optional/unchecked)

**`POST /auth/login` (GrantID):** validate credentials → generate auth code → redirect to `redirect_uri?code=<code>&state=<state_if_present>`

**`GET /callback` (ConnectApp):** receive code → exchange at `/auth/token` → **NO state validation** → store tokens in session → redirect to `/dashboard`

**`POST /auth/token`:** validate code → return `{ access_token, id_token, token_type: 'Bearer' }`

**Routes:**
- `GET /` → `res.sendFile('public/index.html')`
- `GET /dashboard` → serve `public/index.html` (SPA handles showing dashboard)
- `GET /auth/authorize` → SSR
- `POST /auth/login` → issue code + redirect
- `GET /callback` → exchange code (no state check) → session → redirect `/dashboard`
- `POST /auth/token` → exchange code → tokens
- `GET /api/me` → return session user + tokens
- `GET /api/config` → `{ mode: 'vulnerable', port: 3067 }`
- `app.use(express.static(path.join(__dirname, 'public')))`

---

## oauth-strong-server.js (port 3069) — secure

Top comment: `* Terminal 3: cd auth-concepts/oauth2-oidc && npm run secure`

**Fix 1 — state parameter:** ConnectApp generates `state = crypto.randomBytes(16).toString('hex')`, stores in session, validates on callback.

```js
// In GET /: generate state, store in session
const state = crypto.randomBytes(16).toString('hex');
req.session.oauthState = state;
// redirect to /auth/authorize?...&state=${state}

// In GET /callback:
if (req.query.state !== req.session.oauthState) {
  return res.status(400).send('State mismatch — possible CSRF');
}
```

**Fix 2 — PKCE:** ConnectApp generates `code_verifier = crypto.randomBytes(32).toString('base64url')`, derives `code_challenge = SHA256(verifier)` (base64url), sends challenge with authorize request, sends verifier with token exchange.

```js
const { createHash } = require('crypto');
const codeVerifier = crypto.randomBytes(32).toString('base64url');
const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
```

**`POST /auth/token`:** verify `code_verifier` against stored `code_challenge`:
```js
const derived = createHash('sha256').update(codeVerifier).digest('base64url');
if (derived !== storedCodeChallenge) return res.status(400).json({ error: 'invalid_grant' });
```

Same routes as vulnerable. `GET /api/config` → `{ mode: 'secure', port: 3069 }`.

---

## public/index.html — ConnectApp SPA (shared)

On load:
1. `fetch('/api/config')` → set banner:
   - vulnerable: orange — `⚠ NO STATE PARAM: CSRF attack possible — attacker can link their account to victim's ConnectApp`
   - secure: green — `✅ STATE + PKCE: CSRF prevented by state validation; code interception prevented by PKCE`
2. `fetch('/api/me')` → if 401 show "Connect with GrantID" button; if 200 show dashboard

**"Connect with GrantID" button:** on click, redirect to `/auth/authorize?client_id=...&redirect_uri=...&scope=openid+profile+email&state=<generated>&code_challenge=<derived>&code_challenge_method=S256`

**Dashboard:** show username, email, access_token (truncated), id_token (decoded claims)

---

## AUTHORIZE_HTML(opts) — SSR template (inline in server file)

Clean consent page (white/light theme for GrantID):
- GrantID logo
- "**{clientName}** is requesting access to your account"
- Scopes list with checkboxes (display only)
- Vulnerability/secure banner
- Hidden inputs: `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge` (secure only), `code_challenge_method` (secure only)
- Username + password fields
- "Allow Access" submit button

---

## guide-server.js (port 3068) — guide

Top comment: `* Terminal 2: cd auth-concepts/oauth2-oidc && npm run guide`

Thin static server serving `public/guide.html`.

**`public/guide.html`** — dark terminal-green theme:
- Title: "OAuth2 & OIDC"
- Target switcher: "Vulnerable OAuth2 (3067)" dark slate, "Hardened OAuth2 (3069)" green `#16a34a`
- Content: authorization code flow diagram (5 steps), what state parameter prevents (CSRF walkthrough), PKCE flow (verifier → challenge → verify), OIDC id_token claims, comparison table (no state vs state vs state+PKCE).
