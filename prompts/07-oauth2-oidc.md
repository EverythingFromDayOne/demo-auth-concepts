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

### oauth2-oidc

**`oauth2-oidc/oauth-server.js`** — root causes to annotate:
- No `state` parameter: ConnectApp does not generate or validate a CSRF token in the OAuth flow. An attacker can pre-initiate an authorization request, obtain an auth code bound to the attacker's account, then trick the victim into visiting `/callback?code=ATTACKER_CODE`. The victim's ConnectApp session becomes linked to the attacker's GrantID account. The attacker then logs into ConnectApp using their own credentials and has access to whatever the victim's ConnectApp session can do.
- No PKCE: without a code challenge, an auth code intercepted in transit (e.g. from a log, a compromised redirect) can be exchanged for tokens by any party — the `/auth/token` endpoint accepts codes unconditionally.

**`oauth2-oidc/oauth-strong-server.js`** — fixes to annotate:
- `state` parameter: ConnectApp generates `crypto.randomBytes(16).toString('hex')`, stores it in session, and sends it in the authorization URL. On callback, it checks `req.query.state === req.session.oauthState`. A forged callback with a mismatched state is rejected before any code exchange happens.
- PKCE: ConnectApp generates a random `code_verifier`, derives `code_challenge = SHA256(verifier)`, and sends the challenge with the authorization request. The `/auth/token` endpoint re-derives the challenge from the submitted verifier and compares — if they don't match, the code is invalid. Even if the auth code is intercepted, it's useless without the verifier that only the legitimate client knows.

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

### Per-concept README instructions — oauth2-oidc (ConnectApp + GrantID)

**`## How It Works`** — expand the 5-step flow with PKCE:

```
1. ConnectApp generates:
     state         = crypto.randomBytes(16).toString('hex')        [hardened only]
     code_verifier = crypto.randomBytes(32).toString('base64url')  [hardened only]
     code_challenge = SHA256(code_verifier)                         [hardened only]

2. ConnectApp redirects to GrantID /auth/authorize:
     ?client_id=connectapp-client-id
     &redirect_uri=http://localhost:3069/callback
     &scope=openid profile email
     &state=<state>                    [hardened only]
     &code_challenge=<challenge>       [hardened only]
     &code_challenge_method=S256       [hardened only]

3. User logs in at GrantID and approves scopes

4. GrantID redirects to ConnectApp:
     /callback?code=<auth_code>&state=<state>

5. ConnectApp verifies state [hardened only], exchanges code:
     POST /auth/token { code, client_id, client_secret, code_verifier }
                                                           [hardened only]

6. GrantID validates code + PKCE → returns { access_token, id_token }

7. ConnectApp calls GitBucket API with access_token
   Decodes id_token to get user identity (OIDC)
```

**Note:** The `/auth/authorize` authorization page must use `res.send()` for SSR (hidden form fields). Do not convert to JSON.

**`## The Vulnerability`** — two separate attacks:

**Attack 1 — CSRF (no state):**
```
1. Attacker initiates OAuth flow with their own GrantID account → gets auth code
2. Attacker stops before /callback — does NOT exchange the code
3. Attacker tricks victim into loading: /callback?code=ATTACKER_CODE
4. Victim's ConnectApp (no state check) exchanges the code → gets tokens for ATTACKER's account
5. Victim's ConnectApp session is now linked to the attacker's GitBucket identity
6. Attacker logs into ConnectApp normally → shares victim's ConnectApp session data
```

**Attack 2 — Code interception (no PKCE):**
```
1. Auth code appears in the redirect URL: /callback?code=abc123
2. Code logged by reverse proxies, visible in browser history, leakable via Referer header
3. Attacker captures the code and races to POST /auth/token { code: "abc123" }
4. No code_verifier check → tokens issued to attacker
```

**`## Vulnerable Lines`**:
```js
// In GET /callback (vulnerable server):
// ⚠️ VULNERABLE — state not generated, not stored, not validated on return
// Any request to /callback with a valid code is accepted, regardless of who initiated the flow
const code = req.query.code;
// req.query.state is ignored entirely

// In POST /auth/token (vulnerable server):
// ⚠️ VULNERABLE — no code_challenge/code_verifier check
// Any party that has the auth code can exchange it for tokens
const stored = authCodes.get(code);
if (!stored) return res.status(400).json({ error: 'invalid_grant' });
authCodes.delete(code);
// code_verifier never checked
```

**`## Defense Details`**:
- `### State parameter (CSRF protection)` — cryptographic binding between the authorize request and the callback. State is generated by the client, stored in session, compared on callback. A forged callback will have a mismatched state and is rejected before any code exchange.
- `### PKCE (code interception protection)` — code_verifier is a random secret held only by the legitimate client. The challenge (SHA256 of verifier) is sent with the authorize request. Any party that intercepts the auth code still cannot exchange it without the verifier that only the legitimate client knows.
- `### Why both are needed` — state protects who initiates the flow; PKCE protects who exchanges the code. They are independent defenses against different attack vectors.

**`## Hardened Demo`**:
1. Open `localhost:3069` — open DevTools Network tab, click **Connect with GitBucket**
2. Observe the authorize URL: contains `state=...` and `code_challenge=...`
3. After login, observe `/callback?code=...&state=...`
4. Try `/callback?code=fake&state=wrong` — state mismatch error
5. Try exchanging a valid auth code without `code_verifier` (use curl/fetch directly) — rejected
