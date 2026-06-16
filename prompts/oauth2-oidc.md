# Cursor Prompt: OAuth2 & OIDC Demo — ConnectApp (Ports 3067–3069)

## Global UI Standard

| Server type | Theme |
|-------------|-------|
| Guide server | Clone `DASHBOARD_HTML` from `demo-attacked/reverse-tabnabbing/attacker-server.js` — `#0a0a0a` bg, `#00ff41` text, `'Courier New'` font. Copy `<style>` verbatim. |
| App / Auth servers | Realistic product UI matching their brand |

**Guide pages:** Copy `<style>` verbatim. `padding: 2rem` body. No `max-width` wrapper. Fixed bottom-left `target-switcher` navigation only.
- **After** the verbatim `<style>` block, always add this override: `.flow-box { max-width: 900px; }`

## Code Comment Standard

Use these comment markers throughout all three server files:
- `// ⚠️ VULNERABILITY:` — marks insecure code with a short explanation of what's wrong
- `// ✅ PROTECTED:` — marks the secure replacement with a short explanation of what it fixes

---

## Context

**Concept:** OAuth2 Authorization Code Flow + OpenID Connect (OIDC)  
**App names:**
- Client app: ConnectApp — a third-party todo app ("Connect your tools, get things done")
- Authorization Server: GrantID — a mini OAuth2 + OIDC server ("Authorize once, access everywhere")
- Resource Server: GitBucket — a mock code hosting API (provides access to repos)
**Folder:** `auth-concepts/oauth2-oidc/`

OAuth2 is about **authorization** (granting access to resources on another service). OIDC adds **authentication** (who the user is) on top of OAuth2 by adding an ID token. The vulnerable version omits the `state` parameter, making it vulnerable to CSRF attacks. The secure version adds `state` and PKCE (`code_challenge` / `code_verifier`).

---

## Port Layout

| Port | Role | App |
|------|------|-----|
| 3067 | Client app (ConnectApp) + mini Auth Server (GrantID) + Resource Server (GitBucket) | All-in-one demo |
| 3068 | Concept guide | OAuth2 & OIDC Lab |
| 3069 | Improved: state + PKCE | ConnectApp + hardened GrantID |

---

## Architecture Note for Cursor

Ports 3067 and 3069 each run **three logical services on one port**:
- `/auth/*` routes — Authorization Server (GrantID): login, authorize, token endpoint
- `/api/*` routes — Resource Server (GitBucket): protected endpoints requiring access token
- All other routes — Client App (ConnectApp): dashboard, callback handler

This is intentional for demo simplicity.

## Files to create

```
auth-concepts/oauth2-oidc/
├── oauth-server.js        # port 3067 — vulnerable (no state)
├── guide-server.js        # port 3068 — concept guide
├── oauth-strong-server.js # port 3069 — state + PKCE
├── package.json
└── README.md
```

---

## Port 3067 — ConnectApp + Vulnerable GrantID

### File: `oauth2-oidc/oauth-server.js`

**Dependencies:** `express ^4.18.2`, `cors ^2.8.5`, `jsonwebtoken ^9.0.2`

```js
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Auth server secrets
const AUTH_SECRET = 'oauth-secret';

// ⚠️ No state parameter validation — CSRF possible
// Registered OAuth2 clients
const CLIENTS = {
  'connectapp': {
    name: 'ConnectApp',
    clientSecret: 'connectapp-secret',
    redirectUris: ['http://localhost:3067/callback'],
    scopes: ['read:repos', 'read:profile', 'openid', 'email']
  }
};

// Authorization codes (short-lived, single-use)
const authCodes = new Map(); // code → { clientId, userId, scope, redirectUri, expiresAt }

// Access tokens
const accessTokens = new Map(); // token → { userId, scope, expiresAt }

// Auth server user store
const AUTH_USERS = [
  { id: 1, email: 'alice@example.com', password: 'pass1234', name: 'Alice Chen', avatar: 'AC' },
  { id: 2, email: 'bob@example.com',   password: 'qwerty123',  name: 'Bob Martinez', avatar: 'BM' },
];

// Resource (GitBucket repos)
const REPOS = [
  { id: 1, name: 'auth-concepts', description: 'Auth demo project', stars: 42, private: false },
  { id: 2, name: 'api-gateway',   description: 'Custom API gateway',  stars: 7,  private: true },
];
```

### Authorization Server routes (`/auth/*`)

```js
// GET /auth/authorize
// ⚠️ VULNERABLE: state parameter is not required or validated
app.get('/auth/authorize', (req, res) => {
  const { client_id, redirect_uri, scope, response_type, state } = req.query;
  const client = CLIENTS[client_id];

  if (!client) return res.status(400).send('Unknown client_id: ' + client_id);
  if (!client.redirectUris.includes(redirect_uri)) return res.status(400).send('redirect_uri not registered');
  if (response_type !== 'code') return res.status(400).send('Only response_type=code supported');

  // ⚠️ state not validated — just passed through
  res.send(AUTHORIZE_HTML({
    clientName: client.name,
    scope: scope || '',
    requestedScopes: (scope || '').split(' '),
    redirectUri: redirect_uri,
    clientId: client_id,
    state: state || '', // ⚠️ may be empty — CSRF possible
    warning: !state ? '⚠ No state parameter — this request is vulnerable to CSRF' : null
  }));
});

// POST /auth/approve — user approves the authorization request
app.post('/auth/approve', (req, res) => {
  const { username, password, client_id, redirect_uri, scope, state } = req.body;
  const user = AUTH_USERS.find(u => u.email === username && u.password === password);

  if (!user) return res.redirect(`/auth/authorize?error=access_denied&client_id=${client_id}&redirect_uri=${encodeURIComponent(redirect_uri)}&scope=${scope}&state=${state}`);

  // Issue authorization code (short-lived, single-use)
  const code = crypto.randomBytes(16).toString('hex');
  authCodes.set(code, {
    clientId: client_id,
    userId: user.id,
    scope: scope || '',
    redirectUri: redirect_uri,
    expiresAt: Date.now() + 60000 // 1 minute
  });

  // ⚠️ VULNERABLE: state is echoed back without being validated client-side (in the vulnerable demo)
  const callbackUrl = `${redirect_uri}?code=${code}&state=${encodeURIComponent(state || '')}`;
  console.log(`[Auth] Code issued for user ${user.email}, redirecting to: ${callbackUrl}`);
  res.redirect(callbackUrl);
});

// POST /auth/token — exchange code for tokens
app.post('/auth/token', (req, res) => {
  const { grant_type, code, redirect_uri, client_id, client_secret } = req.body;
  if (grant_type !== 'authorization_code') return res.status(400).json({ error: 'unsupported_grant_type' });

  const client = CLIENTS[client_id];
  if (!client || client.clientSecret !== client_secret) return res.status(401).json({ error: 'invalid_client' });

  const authCode = authCodes.get(code);
  if (!authCode || authCode.expiresAt < Date.now() || authCode.clientId !== client_id) {
    return res.status(400).json({ error: 'invalid_grant' });
  }

  // Single-use: delete the code
  authCodes.delete(code);

  const user = AUTH_USERS.find(u => u.id === authCode.userId);
  const scopes = authCode.scope.split(' ');

  // Issue access token
  const accessToken = crypto.randomBytes(32).toString('hex');
  accessTokens.set(accessToken, {
    userId: user.id, scope: authCode.scope, expiresAt: Date.now() + 3600000 // 1 hour
  });

  const response = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: authCode.scope
  };

  // OIDC: if 'openid' scope was requested, include ID token
  if (scopes.includes('openid')) {
    response.id_token = jwt.sign({
      iss: 'http://localhost:3067/auth',
      sub: String(user.id),
      aud: client_id,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      email: scopes.includes('email') ? user.email : undefined,
      name: user.name,
    }, AUTH_SECRET, { algorithm: 'HS256' });
  }

  res.json(response);
});
```

### Resource Server routes (`/api/*`)

```js
function requireAccessToken(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const stored = accessTokens.get(token);
  if (!stored || stored.expiresAt < Date.now()) {
    return res.status(401).json({ error: 'invalid_token' });
  }
  req.tokenInfo = stored;
  req.user = AUTH_USERS.find(u => u.id === stored.userId);
  next();
}

app.get('/api/repos', requireAccessToken, (req, res) => {
  if (!req.tokenInfo.scope.includes('read:repos')) {
    return res.status(403).json({ error: 'insufficient_scope', required: 'read:repos' });
  }
  res.json(REPOS.map(r => ({ ...r, owner: req.user.email })));
});

app.get('/api/user/profile', requireAccessToken, (req, res) => {
  res.json({ id: req.user.id, email: req.user.email, name: req.user.name, avatar: req.user.avatar });
});
```

### Client App routes (ConnectApp)

```js
app.get('/', (req, res) => {
  const session = sessions.get(getSid(req));
  if (session) return res.redirect('/dashboard');
  res.send(HOME_HTML);
});

// Dashboard — SSR: embed session data directly into HTML
// Do NOT use a static template + client-side /api/me call.
// The session already contains profile, accessToken, and idToken from the callback.
// Decode the idToken claims server-side and pass them to the template.
app.get('/dashboard', (req, res) => {
  const session = sessions.get(getSid(req));
  if (!session) return res.redirect('/');

  // Decode idToken claims server-side for display (already verified during callback)
  function b64Decode(str) {
    try { return JSON.parse(Buffer.from(str.replace(/-/g,'+').replace(/_/g,'/'), 'base64').toString()); }
    catch(e) { return {}; }
  }
  const idClaims = session.idToken ? b64Decode(session.idToken.split('.')[1]) : {};

  res.send(DASHBOARD_HTML({ profile: session.profile, idClaims, accessTokenPreview: session.accessToken.substring(0, 8) + '...' }));
});
```

`DASHBOARD_HTML` is a **function** accepting `{ profile, idClaims, accessTokenPreview }` and returning an HTML string. Not a string constant.

// ⚠️ VULNERABLE: does not generate or validate state
app.get('/connect', (req, res) => {
  // ⚠️ No state parameter — CSRF possible
  const authUrl = `http://localhost:3067/auth/authorize?` +
    `client_id=connectapp&` +
    `redirect_uri=http://localhost:3067/callback&` +
    `scope=read:repos+read:profile+openid+email&` +
    `response_type=code`;
  // ⚠️ Note: no &state=... added
  res.redirect(authUrl);
});

// GET /callback?code=...&state=...
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  // ⚠️ VULNERABLE: state is NOT verified against what was sent
  if (!code) return res.status(400).send('No code received');

  // Exchange code for tokens
  const tokenRes = await fetch('http://localhost:3067/auth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      code,
      redirect_uri: 'http://localhost:3067/callback',
      client_id: 'connectapp',
      client_secret: 'connectapp-secret'
    })
  });
  const tokens = await tokenRes.json();

  // Get user profile
  const profileRes = await fetch('http://localhost:3067/api/user/profile', {
    headers: { 'Authorization': 'Bearer ' + tokens.access_token }
  });
  const profile = await profileRes.json();

  const sid = crypto.randomBytes(32).toString('hex');
  sessions.set(sid, { profile, accessToken: tokens.access_token, idToken: tokens.id_token });
  res.setHeader('Set-Cookie', `connect_session=${sid}; Path=/; HttpOnly; SameSite=Lax`);
  res.redirect('/dashboard');
});
```

### UI design

**ConnectApp home** (`HOME_HTML`): Clean SaaS landing. Colors: `#ffffff` bg, `#0f172a` text, `#3b82f6` accent. "ConnectApp" heading, tagline, "Connect with GitBucket" button.

**GrantID authorize page** (`AUTHORIZE_HTML`): Two-tone. Colors: `#1a1a2e` bg, `#e2e8f0` text, `#7c3aed` accent (purple). "GrantID" header, "ConnectApp wants to access" title, list of requested scopes with descriptions, login form, "Approve" button.

Show scope descriptions:
```
openid        → Verify your identity
email         → See your email address
read:repos    → Read access to your GitBucket repositories
read:profile  → See your profile information
```

**ConnectApp dashboard**: After OAuth flow. Shows connected GitBucket repos. Shows user avatar with name from OIDC `id_token`. Shows `access_token` (first 8 chars + ...) and decoded `id_token` claims.

**Disconnect / Sign Out:** "Sign Out" button in top-right. Calls `POST /api/disconnect` to delete the ConnectApp session, then redirects to home:

```js
app.post('/api/disconnect', (req, res) => {
  const raw = req.headers.cookie || '';
  const match = raw.match(/(?:^|;\s*)connect_session=([^;]+)/);
  const sid = match ? match[1] : null;
  if (sid) sessions.delete(sid);
  res.setHeader('Set-Cookie', 'connect_session=; Path=/; Max-Age=0');
  res.json({ message: 'Disconnected — GitBucket access revoked from ConnectApp' });
});
```

Note: disconnecting from ConnectApp revokes the local session but does NOT revoke the access_token at GitBucket's resource server — tokens remain valid until they expire. In a production system, the SP would call the authorization server's revocation endpoint (`/oauth/revoke`) as well.

**Amber banner on ConnectApp home:**
```
⚠ VULNERABLE: /connect generates no state parameter — CSRF attack possible.
See the guide (port 3068) to understand the attack.
```

---

## Port 3068 — OAuth2 & OIDC Concept Guide

### File: `oauth2-oidc/guide-server.js`

Copy `<style>` from `DASHBOARD_HTML` verbatim.

**Title:** `🔐 OAuth2 & OpenID Connect — How They Work`

**Section 1 — OAuth2 vs OIDC** (`.flow-box`)

Heading: `OAuth2 vs OpenID Connect — One Question Each`

```
OAuth2 answers:        "Can application X access resource Y on behalf of user Z?"
                       → Issues ACCESS TOKEN
                       → User approves specific scopes (read:repos, write:calendar)

OpenID Connect adds:   "Who is the user?"
                       → Issues ID TOKEN (a JWT with user identity claims)
                       → Built on top of OAuth2 (uses the same flow)
                       → Adds the 'openid' scope + /userinfo endpoint

Think of it as:
  OAuth2 = authorization (permission to do things)
  OIDC   = authentication (who you are) built on OAuth2
```

**Section 2 — Authorization Code Flow** (`.flow-box`)

Heading: `Authorization Code Flow — Step by Step`

```
ACTORS:
  User        — wants to connect GitBucket to ConnectApp
  ConnectApp  — the OAuth2 client (our app, wants access)
  GrantID     — the authorization server (owns the user account)
  GitBucket   — the resource server (has the repos)

1. ConnectApp initiates the flow
   ConnectApp                     GrantID (Auth Server)
       │                                 │
       ├── Redirect user to ────────────→│
       │   /auth/authorize               │
       │   ?client_id=connectapp         │
       │   &redirect_uri=.../callback    │
       │   &scope=read:repos+openid      │
       │   &response_type=code           │
       │   &state=abc123  ← CSRF token   │

2. User logs in and approves
       │                                 │ Show login + consent screen
       │←── User approves ──────────────┤
       │                                 │ Issue authorization code
       │←── 302 .../callback ───────────┤
       │    ?code=xyz789                 │
       │    &state=abc123  ← echoed back │

3. ConnectApp verifies state and exchanges code
       │ Verify: state === 'abc123' (what we sent)  ← CSRF check
       │
       ├── POST /auth/token ───────────→ │
       │   { code, client_secret, ... }   │
       │                                 │ Verify code + client_secret
       │←── { access_token, id_token } ──┤

4. ConnectApp uses access_token to call GitBucket API
   ConnectApp                        GitBucket (Resource Server)
       │                                 │
       ├── GET /api/repos ─────────────→ │
       │   Authorization: Bearer <token> │
       │←── 200 + repos ────────────────┤
```

**Section 3 — The CSRF Attack (Missing State)** (`.flow-box`)

Heading: `⚠ Attack: Missing state Parameter — CSRF on OAuth Callback`

```
Setup:
  Victim is logged in to ConnectApp.
  ConnectApp has an /oauth/connect endpoint that starts a new OAuth flow.

Attack (port 3067 — no state):

  1. Attacker starts an OAuth flow at GrantID:
     GET /auth/authorize?client_id=connectapp&redirect_uri=.../callback...
     Attacker does NOT complete login — stops just before the authorization code is issued.

  2. Attacker captures the authorization URL that would redirect back:
     /callback?code=ATTACKER_CODE

  3. Attacker tricks victim into clicking:
     <img src="http://localhost:3067/callback?code=ATTACKER_CODE">
     or embeds it in an email/page

  4. Victim's browser (already authenticated on ConnectApp) loads that URL.
     ConnectApp exchanges ATTACKER_CODE for tokens → victim's ConnectApp account
     is now linked to ATTACKER'S GitBucket account.

  Result: Attacker can view victim's ConnectApp activity, or victim's
          data is sent to attacker's GitBucket.
```

**Section 4 — The Fix: state + PKCE** (`.flow-box`)

Heading: `✅ Fix: state Parameter + PKCE`

```js
// CLIENT SIDE — ConnectApp /connect endpoint
app.get('/connect', (req, res) => {
  // ✅ Generate random state and store in session
  const state = crypto.randomBytes(16).toString('hex');
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

  pendingStates.set(state, { codeVerifier, createdAt: Date.now() });

  const authUrl = `http://localhost:3069/auth/authorize?` +
    `client_id=connectapp&redirect_uri=.../callback&scope=...&response_type=code&` +
    `state=${state}&` +            // ← CSRF protection
    `code_challenge=${codeChallenge}&` + // ← PKCE
    `code_challenge_method=S256`;

  res.redirect(authUrl);
});

// CLIENT SIDE — Callback
app.get('/callback', (req, res) => {
  const { code, state } = req.query;
  const pending = pendingStates.get(state);

  // ✅ Verify state matches what we generated
  if (!pending) {
    return res.status(400).send('Invalid state parameter — possible CSRF attack');
  }
  pendingStates.delete(state); // single-use

  // ✅ Include code_verifier in token exchange (PKCE)
  // ...exchange code with code_verifier...
});
```

```
PKCE (Proof Key for Code Exchange) — RFC 7636
  code_verifier  = random string (generated by client, kept secret)
  code_challenge = base64url(SHA256(code_verifier))
  
  Sent with /authorize: ?code_challenge=<challenge>&code_challenge_method=S256
  Sent with /token:     body includes code_verifier

  Auth server verifies: SHA256(code_verifier) == code_challenge
  
  Why: Even if an attacker intercepts the authorization code, they cannot
       exchange it without knowing the code_verifier (which was never sent over the network).
```

**Section 5 — OIDC ID Token** (`.flow-box`)

Heading: `OIDC Identity Token (id_token)`

```
The id_token is a JWT issued alongside the access_token when 'openid' scope is requested.

Standard OIDC claims:
  sub   → Unique user ID at the issuer ("1", never changes)
  iss   → Token issuer ("http://localhost:3067/auth")
  aud   → Intended audience (your client_id: "connectapp")
  exp   → Expiry (same as access token)
  iat   → Issued at
  email → User's email (only if 'email' scope approved)
  name  → User's display name (only if 'profile' scope approved)

Difference from access_token:
  access_token → given to your app to call APIs on the user's behalf
                 (opaque string OR JWT, depending on auth server)
  id_token     → proves to YOUR app who the user is
                 (always a JWT, verified with auth server's public key)

Rule: NEVER send the id_token to your own API endpoints — it's for your client only.
      Use the access_token for API calls.
```

**CSS extensions** (add after verbatim `<style>` copy):

```css
/* Override default flow-box width from copied style */
.flow-box { max-width: 900px; }

.decoded-box {
  background: #0a0a0a;
  border: 1px solid #1a3a1a;
  border-radius: 4px;
  padding: 1rem;
  font-family: 'Courier New', monospace;
  font-size: 0.85rem;
  white-space: pre-wrap;
  word-break: break-all;
  color: #00ff41;
  min-height: 3rem;
  margin-top: 0.5rem;
}
.result-banner {
  padding: 0.6rem 1rem;
  border-radius: 4px;
  font-size: 0.85rem;
  margin-top: 0.5rem;
  display: none;
}
.result-banner.success { background: #052e16; border: 1px solid #16a34a; color: #4ade80; }
.result-banner.failure { background: #450a0a; border: 1px solid #dc2626; color: #fca5a5; }
.result-banner.info    { background: #0c1a2e; border: 1px solid #1e40af; color: #93c5fd; }
input.field, textarea.token-input {
  background: #111;
  border: 1px solid #1a3a1a;
  color: #00ff41;
  font-family: 'Courier New', monospace;
  padding: 0.5rem 0.75rem;
  border-radius: 4px;
  width: 100%;
  box-sizing: border-box;
  outline: none;
  font-size: 0.9rem;
}
textarea.token-input { resize: vertical; min-height: 5rem; }
input.field:focus, textarea.token-input:focus { border-color: #00ff41; }
```

**`showResult` helper** (add in a `<script>` block, shared across all interactive sections):

```js
function showResult(id, type, msg) {
  var el = document.getElementById(id);
  if (!el) return;
  el.className = 'result-banner ' + type;
  el.textContent = msg;
  el.style.display = 'block';
}
```

**Section 6 — Interactive Labs** (add as the final `.flow-box` before Navigation)

Heading: `🔬 Interactive Labs`

HTML:

```html
<!-- PKCE Generator -->
<div class="flow-box">
  <h2>PKCE Demo — Generate code_verifier + code_challenge</h2>
  <p>PKCE (Proof Key for Code Exchange) generates a random verifier, then computes a SHA-256 challenge from it.
  The challenge is sent with the authorization request; the verifier is sent only at token exchange.</p>
  <button id="btn-gen-pkce">Generate PKCE pair</button>
  <div style="margin-top:1rem">
    <div style="margin-bottom:0.5rem; color:#888">code_verifier (keep secret, send at token exchange):</div>
    <div class="decoded-box" id="pkce-verifier">—</div>
    <div style="margin-top:0.75rem; margin-bottom:0.5rem; color:#888">code_challenge = base64url(SHA-256(verifier)) — send with /authorize:</div>
    <div class="decoded-box" id="pkce-challenge">—</div>
    <div style="margin-top:0.75rem; margin-bottom:0.5rem; color:#888">Verification math:</div>
    <div class="decoded-box" id="pkce-math">—</div>
  </div>
  <div class="result-banner" id="pkce-result"></div>
</div>

<!-- id_token Decoder -->
<div class="flow-box">
  <h2>id_token Decoder — Inspect OIDC Claims</h2>
  <p>Paste an id_token JWT from port 3067 or 3069 (after completing the OAuth flow) to inspect its claims.</p>
  <textarea class="token-input" id="id-token-input" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."></textarea>
  <button id="btn-decode-id-token" style="margin-top:0.5rem">Decode id_token</button>
  <div style="margin-top:0.75rem; margin-bottom:0.5rem; color:#888">Header:</div>
  <div class="decoded-box" id="id-token-header">—</div>
  <div style="margin-top:0.75rem; margin-bottom:0.5rem; color:#888">Payload (OIDC claims):</div>
  <div class="decoded-box" id="id-token-payload">—</div>
  <div class="result-banner" id="id-token-result"></div>
</div>

<!-- State Demo -->
<div class="flow-box">
  <h2>State Parameter Demo — CSRF Token</h2>
  <p>The state parameter is a random nonce sent with /authorize and echoed back in the callback.
  ConnectApp verifies it matches before exchanging the code. A mismatch means the callback was forged.</p>
  <button id="btn-gen-state">Generate state value</button>
  <div style="margin-top:0.75rem; margin-bottom:0.5rem; color:#888">Generated state:</div>
  <div class="decoded-box" id="state-out">—</div>
  <div style="margin-top:0.5rem; color:#888; font-size:0.85rem">
    This value is stored in server memory (pendingFlows Map). If the callback arrives with a different state,
    the request is rejected as a potential CSRF attack.
  </div>
</div>
```

JavaScript:

```js
// PKCE Generator
document.getElementById('btn-gen-pkce').addEventListener('click', async function() {
  try {
    // Generate random 32-byte verifier using Web Crypto
    var verifierBytes = new Uint8Array(32);
    crypto.getRandomValues(verifierBytes);
    // base64url encode (no padding, URL-safe)
    var verifier = btoa(String.fromCharCode.apply(null, verifierBytes))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    // Compute SHA-256 challenge using Web Crypto subtle
    var msgBuffer = new TextEncoder().encode(verifier);
    var hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    var hashArray = new Uint8Array(hashBuffer);
    var challenge = btoa(String.fromCharCode.apply(null, hashArray))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    document.getElementById('pkce-verifier').textContent = verifier;
    document.getElementById('pkce-challenge').textContent = challenge;
    document.getElementById('pkce-math').textContent =
      'SHA256("' + verifier.substring(0, 12) + '...") → base64url → "' + challenge + '"';
    showResult('pkce-result', 'success', '✓ PKCE pair generated — verifier is ' + verifier.length + ' chars, challenge is ' + challenge.length + ' chars');
  } catch(e) {
    showResult('pkce-result', 'failure', '✗ ' + e.message);
  }
});

// id_token Decoder
function b64urlDecode(str) {
  try {
    // Pad to multiple of 4, replace URL-safe chars
    var padded = str.replace(/-/g, '+').replace(/_/g, '/');
    while (padded.length % 4) padded += '=';
    return JSON.parse(atob(padded));
  } catch(e) {
    return { raw: str, error: 'could not decode' };
  }
}

document.getElementById('btn-decode-id-token').addEventListener('click', function() {
  var token = document.getElementById('id-token-input').value.trim();
  if (!token) { showResult('id-token-result', 'failure', '✗ Paste an id_token first'); return; }

  var parts = token.split('.');
  if (parts.length !== 3) { showResult('id-token-result', 'failure', '✗ Not a valid JWT — expected 3 parts separated by dots'); return; }

  var header  = b64urlDecode(parts[0]);
  var payload = b64urlDecode(parts[1]);

  document.getElementById('id-token-header').textContent = JSON.stringify(header, null, 2);
  document.getElementById('id-token-payload').textContent = JSON.stringify(payload, null, 2);

  var claims = [];
  if (payload.sub)   claims.push('sub: ' + payload.sub);
  if (payload.iss)   claims.push('iss: ' + payload.iss);
  if (payload.aud)   claims.push('aud: ' + payload.aud);
  if (payload.email) claims.push('email: ' + payload.email);
  if (payload.name)  claims.push('name: ' + payload.name);
  if (payload.exp)   claims.push('exp: ' + new Date(payload.exp * 1000).toISOString());

  showResult('id-token-result', 'success', '✓ OIDC claims — ' + (claims.length ? claims.join(' | ') : 'no standard claims found'));
});

// State Generator
document.getElementById('btn-gen-state').addEventListener('click', function() {
  var stateBytes = new Uint8Array(16);
  crypto.getRandomValues(stateBytes);
  var state = Array.from(stateBytes).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
  document.getElementById('state-out').textContent = state + '\n\n' +
    'Added to pendingFlows Map:\n' +
    '  pendingFlows.set("' + state + '", { codeVerifier: "...", createdAt: ' + Date.now() + ' })\n\n' +
    'Sent with /authorize:\n' +
    '  ...&state=' + state + '&code_challenge=...\n\n' +
    'Callback verifies:\n' +
    '  pendingFlows.has(req.query.state) → must match exactly, then deleted';
});
```

**Navigation:**
- `Vulnerable OAuth (3067)` → `window.open('http://localhost:3067')`
- `Hardened OAuth (3069)` → `window.open('http://localhost:3069')`

---

## Port 3069 — ConnectApp + Hardened GrantID

### File: `oauth2-oidc/oauth-strong-server.js`

Same as port 3067 including the SSR `/dashboard` route (`DASHBOARD_HTML({ profile, idClaims, accessTokenPreview })` function). Key differences:

**Strong secret:**
```js
const crypto = require('crypto');
const AUTH_SECRET = crypto.randomBytes(64).toString('hex');
```

**State generation and validation:**
```js
const pendingFlows = new Map(); // state → { codeVerifier, createdAt }

// ✅ ConnectApp /connect: generate state + PKCE
app.get('/connect', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

  // Store for callback verification
  pendingFlows.set(state, { codeVerifier, createdAt: Date.now() });

  const authUrl = `http://localhost:3069/auth/authorize?` +
    `client_id=connectapp&redirect_uri=http://localhost:3069/callback&` +
    `scope=read:repos+read:profile+openid+email&response_type=code&` +
    `state=${state}&code_challenge=${codeChallenge}&code_challenge_method=S256`;

  res.redirect(authUrl);
});

// ✅ ConnectApp /callback: verify state
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  const pending = pendingFlows.get(state);

  if (!pending) {
    return res.status(400).send('Invalid or missing state parameter — possible CSRF attack. <a href="/">Start over</a>');
  }
  pendingFlows.delete(state); // single-use

  // Exchange code with code_verifier (PKCE)
  const tokenRes = await fetch('http://localhost:3069/auth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      code,
      redirect_uri: 'http://localhost:3069/callback',
      client_id: 'connectapp',
      client_secret: 'connectapp-secret',
      code_verifier: pending.codeVerifier // ✅ PKCE
    })
  });
  // ... rest of callback
});
```

**Auth server validates PKCE:**
```js
// ✅ Store code_challenge with authorization code
authCodes.set(code, {
  clientId: client_id,
  userId: user.id,
  scope: scope || '',
  redirectUri: redirect_uri,
  codeChallenge: req.body.code_challenge,
  codeChallengeMethod: req.body.code_challenge_method,
  expiresAt: Date.now() + 60000
});

// ✅ In /auth/token: verify code_verifier matches code_challenge
app.post('/auth/token', (req, res) => {
  const { code, code_verifier } = req.body;
  const authCode = authCodes.get(code);

  if (authCode.codeChallenge) {
    const expected = crypto.createHash('sha256').update(code_verifier).digest('base64url');
    if (expected !== authCode.codeChallenge) {
      return res.status(400).json({ error: 'invalid_grant', detail: 'code_verifier mismatch' });
    }
  }
  // ... issue tokens
});
```

**Green banner:**
```
✅ HARDENED: state parameter prevents CSRF. PKCE prevents authorization code interception.
```

---

## Key technical notes for Cursor

1. **Three logical services on one port.** Ports 3067 and 3069 each serve ConnectApp (client), GrantID (auth server `/auth/*`), and GitBucket (resource server `/api/*`) from a single Express app. Keep all routes in one file — this is by design for demo simplicity.

2. **`fetch` for server-side token exchange.** In the `/callback` handler, the server makes a `fetch('http://localhost:306X/auth/token', { method: 'POST', ... })` call to exchange the authorization code. This is a server-to-server call. Node 18+ has `fetch` built-in; no import needed. If using Node 16, add `const fetch = require('node-fetch')` and `"node-fetch": "^2.6.7"` to package.json.

3. **PKCE uses Web Crypto API (`crypto.subtle`).** In `guide-server.js`, the PKCE lab runs in the browser. Use `crypto.getRandomValues(new Uint8Array(32))` for the verifier and `crypto.subtle.digest('SHA-256', ...)` for the challenge — both are browser APIs, not Node crypto. On the Node side (port 3069), use `crypto.randomBytes(32).toString('base64url')` and `crypto.createHash('sha256').update(verifier).digest('base64url')`.

4. **State is stored in server memory (`pendingFlows` Map).** The state value is generated on `/connect`, stored in `pendingFlows`, and deleted after one use in `/callback`. Do not store state in a cookie or client-side — it must live server-side so it cannot be forged.

5. **CORS setup.** Port 3068 (guide) calls port 3069 (`/idp/validate-redirect` equivalent) — not needed here since the guide's interactive sections are browser-side only (Web Crypto + JWT decode). If guide labs call port 3067 or 3069 APIs, add `cors({ origin: 'http://localhost:3068' })` to those servers.

6. **`id_token` vs `access_token` usage.** The `id_token` (OIDC JWT with `sub`, `iss`, `aud`, `email`, `name`) is for the ConnectApp front-end to identify the user — it is decoded on the client, never sent to GitBucket. The `access_token` is what gets passed as `Authorization: Bearer` to `/api/repos` and `/api/user/profile`. Cursor should enforce this separation in the dashboard template: show `id_token` claims in the profile section, use `access_token` for API calls.

---

## Shared `package.json` at `oauth2-oidc/`

```json
{
  "name": "oauth2-oidc-demo",
  "version": "1.0.0",
  "scripts": {
    "vulnerable": "node oauth-server.js",
    "guide":      "node guide-server.js",
    "strong":     "node oauth-strong-server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "jsonwebtoken": "^9.0.2"
  }
}
```

---

## README at `oauth2-oidc/README.md`

### OAuth2 Authorization Code Flow

```
1. User clicks "Connect with GitBucket" on ConnectApp
2. ConnectApp redirects to GrantID /auth/authorize with state + code_challenge
3. User logs in at GrantID and approves scopes
4. GrantID redirects to ConnectApp /callback?code=...&state=...
5. ConnectApp verifies state, exchanges code + code_verifier for tokens
6. ConnectApp uses access_token to call GitBucket API
7. id_token proves who the user is (OIDC)
```

### Vulnerability (port 3067)

No `state` parameter. CSRF attack: trick victim into loading `/callback?code=ATTACKER_CODE` → victim's account linked to attacker's identity.

### Fix (port 3069)

`state` = cryptographically random, verified in callback. PKCE: `code_challenge` sent with authorize, `code_verifier` sent with token exchange — auth server verifies they match.

### Run the demo

```bash
cd auth-concepts/oauth2-oidc
npm install
npm run vulnerable  # terminal 1 → localhost:3067
npm run guide       # terminal 2 → localhost:3068
npm run strong      # terminal 3 → localhost:3069
```
