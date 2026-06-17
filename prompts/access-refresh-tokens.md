# Cursor Prompt: Access & Refresh Token Demo — FlowAPI (Ports 3061–3063)

## Global UI Standard

| Server type | Theme |
|-------------|-------|
| Guide server | Clone `DASHBOARD_HTML` from `demo-attacked/reverse-tabnabbing/attacker-server.js` — `#0a0a0a` bg, `#00ff41` text, `'Courier New'` font. Copy `<style>` verbatim. |
| Victim servers | Realistic product UI matching their brand |

**Guide pages:** Copy `<style>` verbatim. `padding: 2rem` body. No `max-width` wrapper. Fixed bottom-left `target-switcher` navigation only.
- **After** the verbatim `<style>` block, always add this override: `.flow-box { max-width: 900px; }`

---

## Context

**Concept:** Access Tokens + Refresh Tokens  
**App name:** FlowAPI — a project management API  
**Tagline:** "Ship faster, stay secure"  
**Folder:** `auth-concepts/access-refresh/`

Access tokens are short-lived JWTs used for API calls. Refresh tokens are long-lived opaque tokens stored server-side, used only to get new access tokens. **Refresh tokens always live in an httpOnly cookie** — not in JS memory or localStorage — so they survive page reloads (F5) and are invisible to JavaScript. The vulnerable version stores a cookie that never expires and never rotates. The secure version rotates the cookie on every use and revokes all tokens on password change.

---

## Code Comment Standard — use throughout all three files

```
// ⚠️ VULNERABILITY: <what is wrong and why it matters>
// ✅ PROTECTED: <what was changed and why it is now safe>
```

No lorem ipsum. All copy must be realistic product language.

---

## Files to create

```
auth-concepts/access-refresh/
├── flow-server.js        # FlowAPI — no rotation, tokens never expire  — port 3061
├── guide-server.js       # Token Lifecycle Lab                         — port 3062
├── flow-strong-server.js # FlowAPI — rotation + revocation             — port 3063
├── package.json
└── README.md
```

---

## Port Layout

| Port | Role | App |
|------|------|-----|
| 3061 | Concept: Refresh token (no rotation, never expires) | FlowAPI (vulnerable) |
| 3062 | Concept guide | Token Lifecycle Lab |
| 3063 | Improved: Refresh token rotation + revocation | FlowAPI (hardened) |

---

## Port 3061 — FlowAPI (Vulnerable Refresh Tokens)

### File: `access-refresh/flow-server.js`

**Dependencies:** `express ^4.18.2`, `cors ^2.8.5`, `jsonwebtoken ^9.0.2`

```js
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// ⚠️ VULNERABLE: No rotation, no expiry on refresh token
const ACCESS_SECRET = 'access-secret-weak';
const ACCESS_EXPIRY = '15m';
const REFRESH_SECRET = 'refresh-secret-weak';
// ⚠️ Refresh tokens stored in memory — never expire, never rotated
const refreshTokenStore = new Map(); // token → { userId, username, issuedAt }
```

### Users

```js
const USERS = [
  { id: 1, username: 'alice', password: 'pass1234', role: 'user' },
  { id: 2, username: 'bob',   password: 'qwerty123',  role: 'user' },
  { id: 3, username: 'admin', password: 'admin456',   role: 'admin' },
];
```

### Token generation helpers

```js
function issueAccessToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username, role: user.role, type: 'access' },
    ACCESS_SECRET,
    { expiresIn: ACCESS_EXPIRY, algorithm: 'HS256' }
  );
}

function issueRefreshToken(user) {
  const token = crypto.randomBytes(40).toString('hex');
  // ⚠️ VULNERABLE: stored forever, never rotated
  refreshTokenStore.set(token, {
    userId: user.id, username: user.username, issuedAt: Date.now()
  });
  return token;
}
```

### Cookie helper + CORS

```js
// Refresh token travels in httpOnly cookie — not in request body
app.use(cors({ origin: 'http://localhost:3062', credentials: true }));

function getRefreshCookie(req) {
  const raw = req.headers.cookie || '';
  const match = raw.match(/(?:^|;\s*)ar_refresh=([^;]+)/);
  return match ? match[1] : null;
}
```

### Endpoints

```js
// POST /api/login → sets ar_refresh httpOnly cookie + returns { accessToken }
// ⚠️ VULNERABLE: cookie never expires and is never rotated
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = USERS.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const refreshToken = issueRefreshToken(user);
  res.setHeader('Set-Cookie', 'ar_refresh=' + refreshToken + '; HttpOnly; SameSite=Strict; Path=/');
  res.json({
    accessToken: issueAccessToken(user),
    tokenType: 'Bearer',
    expiresIn: '15m',
    note: '⚠ Refresh cookie never expires and is never rotated',
  });
});

// POST /api/refresh — reads cookie, issues new access token, does NOT rotate cookie
// ⚠️ VULNERABLE: same cookie stays valid forever
app.post('/api/refresh', (req, res) => {
  const refreshToken = getRefreshCookie(req);
  const stored = refreshToken ? refreshTokenStore.get(refreshToken) : null;
  if (!stored) return res.status(401).json({ error: 'No valid refresh token' });

  const user = USERS.find(u => u.id === stored.userId);
  // ⚠️ Cookie NOT rotated — same token remains valid forever
  res.json({
    accessToken: issueAccessToken(user),
    tokenType: 'Bearer',
    expiresIn: '15m',
    warning: '⚠ Refresh cookie not rotated. Store size: ' + refreshTokenStore.size,
  });
});

// Auth middleware (verifies access token only)
function requireAccess(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Access token required' });
  try {
    req.user = jwt.verify(token, ACCESS_SECRET, { algorithms: ['HS256'] });
    next();
  } catch(err) {
    res.status(401).json({ error: err.name === 'TokenExpiredError' ? 'Access token expired — use refresh token' : 'Invalid token' });
  }
}

app.get('/api/projects', requireAccess, (req, res) => {
  res.json([
    { id: 1, name: 'Auth Concepts Demo', status: 'active' },
    { id: 2, name: 'Security Audit Q3',  status: 'pending' },
  ]);
});

app.get('/api/me', requireAccess, (req, res) => {
  res.json({ sub: req.user.sub, username: req.user.username, role: req.user.role, tokenExpiresAt: new Date(req.user.exp * 1000).toISOString() });
});

// POST /api/logout — reads cookie, deletes from store, clears cookie
app.post('/api/logout', (req, res) => {
  const refreshToken = getRefreshCookie(req);
  if (refreshToken) refreshTokenStore.delete(refreshToken);
  res.setHeader('Set-Cookie', 'ar_refresh=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  res.json({ message: 'Logged out — refresh cookie cleared' });
});
```

### UI design — developer API dashboard

Colors: `#0f172a` background, `#1e293b` card, `#f1f5f9` text, `#0ea5e9` accent (sky blue).

**Four-panel layout (all panels except login are hidden until authenticated):**

1. **Login panel** — username/password → server sets httpOnly cookie + returns access token
2. **Token status panel** — shows access token; refresh token section explains it's in httpOnly cookie
3. **API test panel** — call `/api/me` and `/api/projects`
4. **Refresh panel** — call `POST /api/refresh` with no body (cookie sent automatically)

**Silent session restore on page load (F5 keeps user logged in):**

```js
var liveAccessToken = null;

function showDashboard(accessToken) {
  liveAccessToken = accessToken;
  document.getElementById('access-token-display').textContent = accessToken;
  document.getElementById('login-panel').style.display = 'none';
  document.getElementById('token-status').style.display = '';
  document.getElementById('api-panel').style.display = '';
  document.getElementById('refresh-panel').style.display = '';
  document.getElementById('btn-signout').style.display = '';
}

function showLogin() {
  liveAccessToken = null;
  document.getElementById('token-status').style.display = 'none';
  document.getElementById('api-panel').style.display = 'none';
  document.getElementById('refresh-panel').style.display = 'none';
  document.getElementById('btn-signout').style.display = 'none';
  document.getElementById('login-panel').style.display = '';
}

// On every page load: try to restore session silently using the httpOnly cookie
(async function restoreSession() {
  try {
    var res = await fetch('/api/refresh', { method: 'POST' });
    if (res.ok) { var data = await res.json(); showDashboard(data.accessToken); }
  } catch (e) {}
})();
```

**Token status panel — refresh token described as httpOnly cookie (not shown in JS):**

```html
<div>
  <label>REFRESH TOKEN (httpOnly cookie — survives F5, invisible to JS)</label>
  <div class="token-box" style="color:#94a3b8;font-size:0.8rem">
    Stored in <code style="color:#f87171">ar_refresh</code> httpOnly cookie.
    JavaScript cannot read it — but it is sent automatically on every request to this origin.<br><br>
    ⚠ Vulnerability: this cookie never expires and is never rotated on use.
  </div>
</div>
```

**Sign Out button** — no body needed; server reads and clears the cookie:

```js
document.getElementById('btn-signout').addEventListener('click', async function() {
  await fetch('/api/logout', { method: 'POST' }).catch(function() {});
  showLogin();
});
```

**Amber banner:**
```
⚠ VULNERABLE: Refresh tokens never expire and are never rotated on use.
```

---

## Port 3062 — Token Lifecycle Concept Guide

### File: `access-refresh/guide-server.js`

Copy `<style>` from `DASHBOARD_HTML` verbatim.

**Title:** `🔄 Access Tokens + Refresh Tokens — How They Work`

**Section 1 — Why Two Tokens?** (`.flow-box`)

Heading: `The Problem With Long-Lived Access Tokens`

```
Option A: Long-lived access token (24h or more)
  ✓ Simpler — one token does everything
  ✗ If stolen: attacker has 24h of unchecked access
  ✗ No way to add claims granularly (e.g. step-up auth)

Option B: Short access token (15 min) + long refresh token (7–30 days)
  ✓ Stolen access token expires in 15 min
  ✓ Refresh token can be stored securely (httpOnly cookie or secure storage)
  ✓ Can revoke all refresh tokens on logout or password change
  ✗ More complex — client must handle 401 → refresh → retry
```

**Section 2 — The Token Lifecycle Flow** (`.flow-box`)

Heading: `Token Lifecycle`

```
1. LOGIN
   Client                              Server
      │                                   │
      ├── POST /api/login ───────────────→│
      │   { username, password }          │
      │                                   │ accessToken = jwt.sign({...}, secret, { expiresIn: '15m' })
      │                                   │ refreshToken = crypto.randomBytes(40) → stored in DB
      │←── { accessToken, refreshToken } ─┤
      │
      │   Client stores:
      │     accessToken  → memory (short-lived, ok to lose on page reload)
      │     refreshToken → httpOnly cookie or secure storage

2. NORMAL API CALL (access token valid)
      ├── GET /api/projects ────────────→ │
      │   Authorization: Bearer <access>  │
      │                                   │ jwt.verify(access, secret) → ok → serve response
      │←── 200 + data ────────────────────┤

3. ACCESS TOKEN EXPIRED
      ├── GET /api/projects ────────────→ │
      │   Authorization: Bearer <access>  │
      │                                   │ jwt.verify → TokenExpiredError → 401
      │←── 401 Access token expired ──────┤
      │
      ├── POST /api/refresh ────────────→ │
      │   { refreshToken }                │
      │                                   │ DB lookup: valid? → issue new accessToken
      │                                   │ [ROTATION] issue new refreshToken, invalidate old
      │←── { accessToken, refreshToken } ─┤
      │
      ├── GET /api/projects (retry) ────→ │
      │   Authorization: Bearer <new>     │
      │←── 200 + data ────────────────────┤

4. LOGOUT
      ├── POST /api/logout ─────────────→ │
      │   { refreshToken }                │ DB: delete refreshToken row
      │←── 200 ────────────────────────── │
      │
      Future /api/refresh calls → 401 (token not in DB)
```

**Section 3 — Rotation and Revocation** (`.flow-box`)

Heading: `🔄 Refresh Token Rotation — Why It Matters`

```
WITHOUT rotation (port 3061):
  refreshToken = "abc123" → issues access token → "abc123" still valid forever
  Stolen "abc123" → attacker generates access tokens indefinitely

WITH rotation (port 3063):
  refreshToken = "abc123" → server issues:
    new accessToken
    new refreshToken = "xyz789"
    deletes "abc123" from DB
  Stolen "abc123" → used by attacker → server sees BOTH "abc123" and "xyz789"
  appear to be used → detects reuse → revoke ALL tokens for that user

This is called Refresh Token Rotation with Reuse Detection.
```

```html
<table style="width:100%;border-collapse:collapse;font-size:0.82rem">
  <tr style="color:#64748b;border-bottom:1px solid #1a3a1a">
    <th style="text-align:left;padding:0.5rem">Scenario</th>
    <th>Without Rotation (3061)</th>
    <th>With Rotation (3063)</th>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">Normal use</td>
    <td style="padding:0.5rem;color:#94a3b8">One refresh token used indefinitely</td>
    <td style="padding:0.5rem;color:#94a3b8">New refresh token on every use</td>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">Token stolen from logs</td>
    <td style="padding:0.5rem;color:#fca5a5">⚠ Permanent access for attacker</td>
    <td style="padding:0.5rem;color:#4ade80">✅ Detected on reuse → all revoked</td>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">Password change</td>
    <td style="padding:0.5rem;color:#fca5a5">⚠ Old refresh tokens still valid</td>
    <td style="padding:0.5rem;color:#4ade80">✅ All refresh tokens revoked</td>
  </tr>
  <tr>
    <td style="padding:0.5rem;color:#94a3b8">Logout from all devices</td>
    <td style="padding:0.5rem;color:#fca5a5">⚠ Can't invalidate individual tokens</td>
    <td style="padding:0.5rem;color:#4ade80">✅ Delete all tokens for user in DB</td>
  </tr>
</table>
```

**Section 4 — Where to Store Tokens** (`.flow-box`)

Heading: `Token Storage Trade-offs`

```
ACCESS TOKEN:
  ✅ In-memory variable (JS) — safest: cleared on page close, not accessible to other tabs
  ⚠ localStorage — persistent, but readable by any XSS script
  ⚠ sessionStorage — tab-scoped, cleared on tab close, but still XSS-readable

REFRESH TOKEN:
  ✅ httpOnly cookie — browser sends automatically, JS cannot read, safe from XSS
     (set Secure + SameSite=Strict for CSRF protection)
  ⚠ localStorage — readable by XSS, do not use for high-value refresh tokens
  ✅ Secure native storage (mobile: iOS Keychain / Android Keystore)
```

**Helper CSS (append inside `<style>` after the verbatim block):**

```css
/* Override default flow-box width from copied style */
.flow-box { max-width: 900px; }

textarea.token-input {
  width: 100%; background: #111; border: 1px solid #1a3a1a; color: #00ff41;
  font-family: 'Courier New', Courier, monospace; font-size: 0.78rem;
  padding: 0.75rem; border-radius: 4px; resize: vertical; min-height: 80px;
}
.decoded-box {
  background: #0a0a0a; border: 1px solid #1a3a1a; border-radius: 4px;
  padding: 0.75rem; font-size: 0.78rem; color: #cbd5e1;
  white-space: pre-wrap; word-break: break-all; min-height: 60px; margin-top: 0.5rem;
}
.result-banner {
  padding: 0.6rem 1rem; border-radius: 4px; font-size: 0.82rem;
  margin-top: 0.75rem; display: none;
}
.result-banner.success { background: #052e16; border: 1px solid #16a34a; color: #4ade80; }
.result-banner.failure { background: #450a0a; border: 1px solid #dc2626; color: #fca5a5; }
.result-banner.info    { background: #0c1a2e; border: 1px solid #1e40af; color: #93c5fd; }
input.field {
  background: #111; border: 1px solid #1a3a1a; color: #00ff41;
  font-family: 'Courier New', Courier, monospace; font-size: 0.82rem;
  padding: 0.4rem 0.6rem; border-radius: 4px;
}
```

**`showResult` helper + full guide interactive JS:**

```js
function showResult(id, type, msg) {
  var el = document.getElementById(id);
  el.className = 'result-banner ' + type;
  el.textContent = msg;
  el.style.display = 'block';
}

// Section 5 — Live Token Demo
// The guide lets the user login on :3061, get tokens, manually refresh, and see the difference
// ⚠️ DEMO ONLY: Both tokens stored in JS memory variables so they are visible on screen.
// In production: access token → JS memory (fine), refresh token → httpOnly cookie (never JS).
// Storing the refresh token in JS makes it readable by XSS — this is intentional here
// so the guide can show both tokens and demonstrate the rotation/reuse vulnerability visually.
var liveAccessToken = null;
var liveRefreshToken = null;

document.getElementById('btn-live-login').addEventListener('click', async function() {
  var u = document.getElementById('live-user').value || 'alice';
  var p = document.getElementById('live-pass').value || 'pass1234';
  try {
    var res = await fetch('http://localhost:3061/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: u, password: p })
    });
    var data = await res.json();
    if (!res.ok) { showResult('live-result', 'failure', '✗ ' + data.error); return; }
    liveAccessToken  = data.accessToken;
    liveRefreshToken = data.refreshToken;
    document.getElementById('access-token-out').textContent  = data.accessToken;
    document.getElementById('refresh-token-out').textContent = data.refreshToken +
      '\n\n⚠ This refresh token never expires and is never rotated (port 3061 — vulnerable)';
    showResult('live-result', 'success', '✓ Logged in. Access token expires in 15 min. Refresh token: permanent.');
  } catch(e) { showResult('live-result', 'failure', '✗ ' + e.message + ' — is port 3061 running?'); }
});

document.getElementById('btn-live-api').addEventListener('click', async function() {
  if (!liveAccessToken) { showResult('live-result', 'failure', '✗ Login first'); return; }
  try {
    var res = await fetch('http://localhost:3061/api/projects', {
      headers: { 'Authorization': 'Bearer ' + liveAccessToken }
    });
    var data = await res.json();
    if (res.ok) {
      document.getElementById('api-out').textContent = JSON.stringify(data, null, 2);
      showResult('live-result', 'success', '✓ 200 — access token valid');
    } else {
      document.getElementById('api-out').textContent = JSON.stringify(data, null, 2);
      showResult('live-result', 'failure', '✗ ' + res.status + ' — ' + data.error + ' → use refresh token');
    }
  } catch(e) { showResult('live-result', 'failure', '✗ ' + e.message); }
});

document.getElementById('btn-live-refresh').addEventListener('click', async function() {
  if (!liveRefreshToken) { showResult('live-result', 'failure', '✗ Login first to get a refresh token'); return; }
  try {
    var res = await fetch('http://localhost:3061/api/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: liveRefreshToken })
    });
    var data = await res.json();
    if (res.ok) {
      liveAccessToken = data.accessToken;
      document.getElementById('access-token-out').textContent  = data.accessToken;
      // On 3061: refresh token is NOT rotated — still the same
      document.getElementById('refresh-token-out').textContent = liveRefreshToken +
        '\n\n⚠ OLD refresh token still valid — port 3061 does NOT rotate it';
      showResult('live-result', 'info', 'ℹ New access token issued. OLD refresh token still valid (no rotation).');
    } else {
      showResult('live-result', 'failure', '✗ ' + data.error);
    }
  } catch(e) { showResult('live-result', 'failure', '✗ ' + e.message); }
});
```

**HTML for Section 5 (Live Demo):**

```html
<div class="flow-box">
  <strong>🧪 Live Token Demo — Port 3061</strong>
  <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;margin:0.75rem 0">
    <input class="field" id="live-user" value="alice" style="width:100px" placeholder="username">
    <input class="field" id="live-pass" value="pass1234" style="width:130px" placeholder="password" type="password">
    <button class="demo-btn" id="btn-live-login">Login → :3061</button>
  </div>
  <div style="margin-bottom:0.5rem">
    <div style="font-size:0.75rem;color:#94a3b8">Access token (15 min JWT):</div>
    <pre class="decoded-box" id="access-token-out" style="color:#a78bfa">–</pre>
  </div>
  <div style="margin-bottom:0.75rem">
    <div style="font-size:0.75rem;color:#f87171">Refresh token (never expires ⚠):</div>
    <pre class="decoded-box" id="refresh-token-out" style="color:#fca5a5">–</pre>
  </div>
  <div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin-bottom:0.75rem">
    <button class="demo-btn" id="btn-live-api">GET /api/projects (uses access token)</button>
    <button class="demo-btn" id="btn-live-refresh">POST /api/refresh (get new access token)</button>
  </div>
  <div class="result-banner" id="live-result"></div>
  <pre class="decoded-box" id="api-out" style="min-height:60px">–</pre>
</div>
```

**Navigation:**
- `Vulnerable Refresh (3061)` → `window.open('http://localhost:3061')`
- `Hardened Refresh (3063)` → `window.open('http://localhost:3063')`

---

## Port 3063 — FlowAPI (Hardened Refresh Tokens)

### File: `access-refresh/flow-strong-server.js`

Same as port 3061 but with strong secrets, cookie rotation, reuse detection, and per-user revocation.

**Cookie helpers + CORS:**
```js
app.use(cors({ origin: 'http://localhost:3062', credentials: true }));

function getRefreshCookie(req) {
  const raw = req.headers.cookie || '';
  const match = raw.match(/(?:^|;\s*)ar_refresh=([^;]+)/);
  return match ? match[1] : null;
}

function setRefreshCookie(res, token) {
  res.setHeader('Set-Cookie',
    'ar_refresh=' + token + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=' + (7 * 24 * 60 * 60)
  );
}

function clearRefreshCookie(res) {
  res.setHeader('Set-Cookie', 'ar_refresh=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
}
```

**Strong secrets:**
```js
const ACCESS_SECRET = crypto.randomBytes(64).toString('hex');
const REFRESH_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
```

**Refresh token store with family tracking:**
```js
// ✅ Each refresh token entry has a family ID — reuse of an old token revokes the whole family
const refreshTokenStore = new Map(); // token → { userId, username, familyId, version, issuedAt }
const revokedFamilies = new Set();
const rotatedTokens = new Map();     // old token → familyId (for reuse detection)
```

**Login — sets cookie, returns access token only:**
```js
app.post('/api/login', (req, res) => {
  const user = USERS.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const refreshToken = issueRefreshToken(user);
  setRefreshCookie(res, refreshToken);
  res.json({ accessToken: issueAccessToken(user), tokenType: 'Bearer', expiresIn: '15m',
    note: '✅ Refresh token in httpOnly cookie. Rotates on every /api/refresh call.' });
});
```

**Rotation + reuse detection on refresh — old cookie cleared, new cookie set:**
```js
app.post('/api/refresh', (req, res) => {
  const refreshToken = getRefreshCookie(req);
  const stored = refreshToken ? refreshTokenStore.get(refreshToken) : null;

  if (!stored) {
    const familyId = refreshToken ? rotatedTokens.get(refreshToken) : null;
    if (familyId) { revokeFamily(familyId); clearRefreshCookie(res); }
    return res.status(401).json({ error: 'No valid refresh token' });
  }

  if (revokedFamilies.has(stored.familyId)) {
    clearRefreshCookie(res);
    return res.status(401).json({ error: 'Session revoked — please log in again' });
  }

  if (Date.now() - stored.issuedAt > REFRESH_MAX_AGE_MS) {
    refreshTokenStore.delete(refreshToken);
    clearRefreshCookie(res);
    return res.status(401).json({ error: 'Refresh token expired — please log in again' });
  }

  const user = USERS.find(u => u.id === stored.userId);

  // ✅ ROTATION: delete old, record as rotated, issue new token in new cookie
  refreshTokenStore.delete(refreshToken);
  rotatedTokens.set(refreshToken, stored.familyId);

  const newToken = crypto.randomBytes(40).toString('hex');
  refreshTokenStore.set(newToken, {
    userId: user.id, username: user.username, familyId: stored.familyId,
    version: stored.version + 1, issuedAt: stored.issuedAt,
  });

  setRefreshCookie(res, newToken); // old cookie replaced by new cookie
  res.json({ accessToken: issueAccessToken(user), tokenType: 'Bearer', expiresIn: '15m',
    note: '✅ Refresh cookie rotated — old token invalidated, new cookie set.' });
});
```

**Logout — reads cookie, revokes, clears cookie:**
```js
app.post('/api/logout', (req, res) => {
  const refreshToken = getRefreshCookie(req);
  if (refreshToken && refreshTokenStore.has(refreshToken)) {
    const stored = refreshTokenStore.get(refreshToken);
    rotatedTokens.set(refreshToken, stored.familyId);
    refreshTokenStore.delete(refreshToken);
  }
  clearRefreshCookie(res);
  res.json({ message: '✅ Logged out — refresh cookie cleared' });
});
```

**Revoke all sessions on password change — clears cookie:**
```js
app.post('/api/change-password', requireAccess, (req, res) => {
  const userId = req.user.sub;
  for (const [token, data] of refreshTokenStore.entries()) {
    if (data.userId === userId) {
      rotatedTokens.set(token, data.familyId);
      revokedFamilies.add(data.familyId);
      refreshTokenStore.delete(token);
    }
  }
  clearRefreshCookie(res);
  res.json({ message: '✅ Password changed. All sessions revoked — please log in again on all devices.' });
});
```

**Client JS — same `showDashboard()` / `showLogin()` / `restoreSession()` pattern as port 3061:**
- No `liveRefreshToken` variable
- Refresh button sends `POST /api/refresh` with no body — browser sends cookie, server sets new cookie
- Change-password button sends only `Authorization: Bearer` — no refresh token in body
- Sign out button sends `POST /api/logout` with no body

**Green banner:**
```
✅ HARDENED: Refresh tokens rotate on every use, expire after 7 days, live in httpOnly cookie, and are revoked on password change.
```

---

## Shared `package.json` at `access-refresh/`

```json
{
  "name": "access-refresh-demo",
  "version": "1.0.0",
  "scripts": {
    "vulnerable": "node flow-server.js",
    "guide":      "node guide-server.js",
    "strong":     "node flow-strong-server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "jsonwebtoken": "^9.0.2"
  }
}
```

---

## README at `access-refresh/README.md`

### Token Relationship

```
ACCESS TOKEN                         REFRESH TOKEN
──────────────────────────────────   ──────────────────────────────────
JWT (signed, self-contained)         Opaque random bytes (crypto.randomBytes)
Short-lived: 15 minutes              Long-lived: 7–30 days
Used on every API call               Used ONLY at /api/refresh
Stateless: no server lookup          Stateful: stored in server DB / Map
If expired → 401 → use refresh       If expired/stolen → full re-login
```

### The attack (port 3061)

Refresh token never rotates. One stolen token → indefinite access.

### The fix (port 3063)

Refresh token rotates on every `/api/refresh` call. Old token immediately invalid. Reuse of an old token triggers family revocation.

### Run the demo

```bash
cd auth-concepts/access-refresh
npm install
npm run vulnerable  # terminal 1 → localhost:3061
npm run guide       # terminal 2 → localhost:3062
npm run strong      # terminal 3 → localhost:3063
```

---

## Key technical notes for Cursor

1. **Access token is a JWT; refresh token is opaque.** The access token is signed with `jwt.sign()` and contains claims (sub, role, exp). The refresh token is `crypto.randomBytes(40).toString('hex')` — a random string with no internal structure. This is intentional: the refresh token is looked up in a server-side Map/DB, so there's no need to embed data in it.

2. **`REFRESH_SECRET` is unused in this demo.** We define it for completeness (as production would use it to sign refresh tokens) but the demo stores refresh tokens as opaque bytes in a Map. Remove `REFRESH_SECRET` if it causes confusion, or keep it with a comment explaining when it would apply.

3. **CORS on ports 3061 and 3063.** The guide (3062) calls both servers. Add `cors({ origin: 'http://localhost:3062', credentials: true })` to both. The live demo buttons in the guide target port 3061 specifically. `credentials: true` is required for the browser to send/receive cookies on cross-origin requests.

4. **Family ID for reuse detection (port 3063).** Generate `familyId = crypto.randomUUID()` at login and store it with the first refresh token. On rotation: keep the same familyId, increment `version`. Track used (rotated-away) tokens in a `revokedFamilies` Set — if a token arrives whose familyId is in this Set, revoke ALL tokens for that family. Without this, simple rotation still has a brief window where the old token can be replayed.

5. **The `revokedFamilies` Set is in-memory.** On server restart it clears. For the demo this is fine and expected. Add a comment: `// In production: store revoked families in Redis with a TTL matching the max refresh token lifetime.`

6. **The guide's live demo targets port 3061 (vulnerable) intentionally.** The user should observe that after calling `/api/refresh`, the OLD refresh cookie is still valid on port 3061. This is the entire vulnerability. The button labels should make this explicit.

7. **Refresh token is always in an httpOnly cookie — never in JS memory or localStorage.** On page reload (F5), the access token (in JS memory) is lost, but the httpOnly cookie survives. The page calls `POST /api/refresh` on load — if the cookie is valid, a new access token is issued silently and the user never sees the login screen. This is the correct real-world pattern.

8. **The `restoreSession()` IIFE runs on every page load.** It calls `POST /api/refresh` with no body. If the httpOnly cookie is present and valid, the server returns a new access token and (on port 3063) also sets a new rotated cookie. If not, the user stays on the login panel.

9. **No `liveRefreshToken` variable exists in the client.** The refresh token is entirely managed by the browser cookie mechanism — the JS never sees it. Any code that passes `refreshToken` in a request body is wrong for this pattern.
