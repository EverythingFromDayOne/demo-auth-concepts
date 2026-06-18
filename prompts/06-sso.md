# Cursor Prompt — 06: SSO (Single Sign-On)
# Ports: 3064 (vulnerable) · 3065 (guide) · 3066 (secure)

Build three Node.js Express servers in `auth-concepts/sso/` that teach SSO redirect_uri validation.

---

## File structure to create

```
sso/
  sso-server.js         ← port 3064, vulnerable
  guide-server.js       ← port 3065, guide
  sso-strong-server.js  ← port 3066, secure
  public/
    index.html          ← WorkHub SP home + dashboard SPA (static, shared)
    style.css
    guide.html
    guide.css
  package.json
```

---

## package.json

```json
{
  "name": "sso",
  "scripts": {
    "vulnerable": "node sso-server.js",
    "guide": "node guide-server.js",
    "secure": "node sso-strong-server.js",
    "start": "node sso-server.js"
  },
  "dependencies": { "express": "^4.18.2", "cors": "^2.8.5" }
}
```

---

## Architecture

Each server simulates both the **Service Provider (SP)** (WorkHub, a project management app) and the **Identity Provider (IdP)** (CorpID) in one Express app using route prefixes:

- `/` and `/dashboard` and `/api/*` → WorkHub SP
- `/auth/authorize`, `/auth/login`, `/auth/callback` → CorpID IdP

**Registered clients (in-memory):**
```js
const CLIENTS = {
  'workhub-client-id': {
    name: 'WorkHub',
    allowedRedirectUris: ['http://localhost:PORT/callback'] // PORT = 3064 or 3066
  }
}
```

**IdP users:** `alice / pass1234`, `bob / qwerty123`

**Assertion tokens:** opaque `crypto.randomBytes(16).toString('hex')` stored in `assertions` Map.

---

## ⚠ SSR REQUIRED FOR IDP LOGIN PAGE — DO NOT CONVERT TO STATIC

The IdP login page (`/auth/authorize`) MUST use `res.send(IDP_LOGIN_HTML(opts))` because:
1. `clientName` requires server-side lookup: `CLIENTS[clientId].name`
2. `redirect_uri`, `state`, `client_id` must be injected into `<input type="hidden">` form fields for the login form POST

```js
// Keep as SSR — hidden fields carry OAuth state through the form POST
app.get('/auth/authorize', (req, res) => {
  const { client_id, redirect_uri, state } = req.query;
  const client = CLIENTS[client_id];
  res.send(IDP_LOGIN_HTML({
    clientName: client?.name || 'Unknown App',
    clientId: client_id,
    redirectUri: redirect_uri,
    state,
  }));
});
```

The SP home (`/`) and SP dashboard (`/dashboard`) ARE served statically from `public/`.

---

## sso-server.js (port 3064) — vulnerable

Top comment: `* Terminal 1: cd auth-concepts/sso && npm install && npm run vulnerable`

**Vulnerability:** `redirect_uri` is NOT validated against the registered allowlist. Any URI is accepted → open redirect attack: attacker crafts `/auth/authorize?redirect_uri=http://attacker.com/steal` → victim logs in → assertion token sent to attacker.

**`POST /auth/login`:** validate credentials → generate assertion token → redirect to `redirect_uri?token=<assertion>` **without checking if redirect_uri is allowed**.

**SP callback `GET /callback`:** receive `token` from query → exchange with IdP (`assertions` Map) → set session → redirect to `/dashboard`.

**Routes:**
- `GET /` → serve `public/index.html` (WorkHub home)
- `GET /dashboard` → requireSPSession → serve `public/index.html` (or redirect to `/auth/authorize` if not logged in)
- `GET /auth/authorize` → **SSR** → IDP_LOGIN_HTML with hidden fields
- `POST /auth/login` → validate + redirect (no URI check)
- `GET /callback` → exchange token → set session
- `GET /api/me` → return session user
- `POST /api/logout` → clear session
- `GET /api/config` → `{ mode: 'vulnerable', port: 3064 }`
- `app.use(express.static(path.join(__dirname, 'public')))`

---

## sso-strong-server.js (port 3066) — secure

Top comment: `* Terminal 3: cd auth-concepts/sso && npm run secure`

**Fix:** `redirect_uri` validated against exact allowlist before login form is shown AND before redirect is issued.

```js
// Check on authorize:
if (!client || !client.allowedRedirectUris.includes(redirect_uri)) {
  return res.status(400).send('Invalid redirect_uri');
}

// Check again on login POST:
if (!client.allowedRedirectUris.includes(redirect_uri)) {
  return res.status(400).json({ error: 'redirect_uri not allowed' });
}
```

Same routes as vulnerable. `GET /api/config` → `{ mode: 'secure', port: 3066 }`.

---

## public/index.html — WorkHub SPA

On load:
1. `fetch('/api/config')` → set banner:
   - vulnerable: orange — `⚠ OPEN REDIRECT: redirect_uri is not validated — any URI accepted as callback target`
   - secure: green — `✅ STRICT ALLOWLIST: redirect_uri validated against registered URIs before login`
2. `fetch('/api/me')` → if 401 show "Login with CorpID" button → redirect to `/auth/authorize?client_id=workhub-client-id&redirect_uri=http://localhost:PORT/callback&state=<random>`; if 200 show dashboard with user info

---

## IDP_LOGIN_HTML(opts) — SSR template (inline in server file)

Dark IdP theme (navy: `#1e1e2e` bg, `#cdd6f4` text):
- CorpID logo
- "Signing in to: **{clientName}**" 
- Vulnerability banner (orange) for vulnerable server, secure banner for strong server
- Username + password form
- Hidden inputs: `redirect_uri`, `state`, `client_id`
- Error display

---

## guide-server.js (port 3065) — guide

Top comment: `* Terminal 2: cd auth-concepts/sso && npm run guide`

Thin static server serving `public/guide.html`.

**`public/guide.html`** — dark terminal-green theme:
- Title: "SSO — Single Sign-On"
- Target switcher: "Vulnerable SSO (3064)" dark slate, "Hardened SSO (3066)" green `#16a34a`
- Content: IdP/SP flow diagram, what the assertion token is, open redirect attack walkthrough step-by-step, strict allowlist fix, real-world examples (OAuth2 redirect_uri registration).
