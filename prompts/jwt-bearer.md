# Cursor Prompt: JWT & Bearer Token Demo — AuthFlow (Ports 3058–3060)

## Global UI Standard

| Server type | Theme |
|-------------|-------|
| Guide server | Clone `DASHBOARD_HTML` from `demo-attacked/reverse-tabnabbing/attacker-server.js` — `#0a0a0a` bg, `#00ff41` text, `'Courier New'` font. Copy `<style>` verbatim. |
| Victim servers | Realistic product UI matching their brand |

**Guide pages:** Copy `<style>` verbatim. `padding: 2rem` body. No `max-width` wrapper. `.flow-box` / `.credentials-panel`. Fixed bottom-left `target-switcher` only.
- **After** the verbatim `<style>` block, always add this override: `.flow-box { max-width: 900px; }`

---

## Context

**Concept:** JWT (JSON Web Token) & Bearer Token Authentication  
**App name:** AuthFlow — a task management API  
**Tagline:** "Stateless auth for modern apps"  
**Folder:** `auth-concepts/jwt-bearer/`

Note: `demo-attacked/jwt-attacks/` already demonstrates JWT attacks (alg:none, weak secret brute force). This demo focuses on **how JWTs work** — the three-part structure, the signing/verification flow, claims, and what makes stateless auth different from sessions. The vulnerable server uses a weak secret ("secret") to show what breaks when secrets are predictable.

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
auth-concepts/jwt-bearer/
├── jwt-server.js        # AuthFlow — JWT with weak secret   — port 3058
├── guide-server.js      # JWT & Bearer Lab                  — port 3059
├── jwt-strong-server.js # AuthFlow — JWT with strong secret — port 3060
├── package.json
└── README.md
```

---

## Port Layout

| Port | Role | App |
|------|------|-----|
| 3058 | Concept: JWT with weak secret | AuthFlow (HS256, secret="secret") |
| 3059 | Concept guide | JWT & Bearer Lab (visual decoder + flow) |
| 3060 | Improved: JWT with strong secret + RS256 concept | AuthFlow (strong HS256 + short expiry) |

---

## Port 3058 — AuthFlow (Weak JWT Secret)

### File: `jwt-bearer/jwt-server.js`

**Dependencies:** `express ^4.18.2`, `cors ^2.8.5`, `jsonwebtoken ^9.0.2`

```js
const jwt = require('jsonwebtoken');
const cors = require('cors');
app.use(cors({ origin: 'http://localhost:3059' }));
app.use(express.json());

// ⚠️ VULNERABLE: weak, predictable secret
const JWT_SECRET = 'secret';
const JWT_EXPIRES_IN = '24h'; // ⚠️ Long expiry
```

### Users

```js
const USERS = [
  { id: 1, username: 'alice', password: 'pass1234', role: 'user',  fullName: 'Alice Chen' },
  { id: 2, username: 'bob',   password: 'qwerty123',  role: 'user',  fullName: 'Bob Martinez' },
  { id: 3, username: 'admin', password: 'admin456',   role: 'admin', fullName: 'Admin User' },
];
```

### Login — issues JWT

```js
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = USERS.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  // Payload (claims) embedded in the token
  const payload = {
    sub: user.id,           // subject (user ID)
    username: user.username,
    role: user.role,
    fullName: user.fullName,
    iat: Math.floor(Date.now() / 1000), // issued at
  };

  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN, algorithm: 'HS256' });

  res.json({
    token,
    tokenType: 'Bearer',
    expiresIn: JWT_EXPIRES_IN,
    user: { id: user.id, username: user.username, role: user.role }
  });
});
```

### Auth middleware

```js
function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';

  if (!token) return res.status(401).json({ error: 'Bearer token required' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired', expiredAt: err.expiredAt });
    }
    return res.status(401).json({ error: 'Invalid token: ' + err.message });
  }
}
```

### Endpoints

```js
app.get('/api/me', requireAuth, (req, res) => {
  res.json({
    sub: req.user.sub,
    username: req.user.username,
    role: req.user.role,
    fullName: req.user.fullName,
    issuedAt: new Date(req.user.iat * 1000).toISOString(),
    expiresAt: new Date(req.user.exp * 1000).toISOString(),
    note: 'All this data is inside the JWT itself — server checked the signature, not a database'
  });
});

app.get('/api/tasks', requireAuth, (req, res) => {
  res.json([
    { id: 1, title: 'Implement auth demo', done: true,  assignee: 'alice' },
    { id: 2, title: 'Write JWT guide',     done: false, assignee: 'alice' },
    { id: 3, title: 'Deploy to staging',   done: false, assignee: 'bob' },
  ]);
});

app.get('/api/admin/users', requireAuth, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin role required' });
  res.json(USERS.map(u => ({ id: u.id, username: u.username, role: u.role })));
});
```

### UI design — minimal developer API playground

Colors: `#0f172a` background, `#1e293b` card, `#f8fafc` text, `#8b5cf6` accent (violet).

**Page layout:** Single page with three panels:
1. **Login panel** — username/password → issues JWT
2. **Token display panel** — shows the raw JWT + decoded parts (header, payload, signature) in three colored boxes
3. **API test panel** — call `/api/me`, `/api/tasks`, `/api/admin/users` with the issued token

**Token display after login:**

```html
<div id="token-display" style="display:none">
  <div style="margin-bottom:1rem">
    <label style="font-size:0.75rem;color:#94a3b8">Raw JWT:</label>
    <div id="raw-token" style="font-family:monospace;font-size:0.72rem;word-break:break-all;background:#1e293b;padding:0.75rem;border-radius:6px;margin-top:0.25rem">
      <!-- token in 3 colors: red.purple.blue -->
    </div>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:0.75rem">
    <div>
      <div style="font-size:0.72rem;color:#f87171;font-weight:600;margin-bottom:0.25rem">HEADER (base64url)</div>
      <pre id="jwt-header" style="background:#1e293b;padding:0.5rem;border-radius:4px;font-size:0.72rem;color:#fca5a5"></pre>
    </div>
    <div>
      <div style="font-size:0.72rem;color:#a78bfa;font-weight:600;margin-bottom:0.25rem">PAYLOAD (base64url)</div>
      <pre id="jwt-payload" style="background:#1e293b;padding:0.5rem;border-radius:4px;font-size:0.72rem;color:#c4b5fd"></pre>
    </div>
    <div>
      <div style="font-size:0.72rem;color:#60a5fa;font-weight:600;margin-bottom:0.25rem">SIGNATURE (HS256)</div>
      <pre id="jwt-sig" style="background:#1e293b;padding:0.5rem;border-radius:4px;font-size:0.72rem;color:#93c5fd"></pre>
    </div>
  </div>
</div>
```

```js
function displayToken(token) {
  var parts = token.split('.');
  // Color-code the raw token
  document.getElementById('raw-token').innerHTML =
    '<span style="color:#f87171">' + parts[0] + '</span>' +
    '<span style="color:#475569">.</span>' +
    '<span style="color:#a78bfa">' + parts[1] + '</span>' +
    '<span style="color:#475569">.</span>' +
    '<span style="color:#60a5fa">' + parts[2] + '</span>';

  function b64Decode(str) {
    try { return JSON.parse(atob(str.replace(/-/g,'+').replace(/_/g,'/'))); }
    catch(e) { return str; }
  }
  document.getElementById('jwt-header').textContent = JSON.stringify(b64Decode(parts[0]), null, 2);
  document.getElementById('jwt-payload').textContent = JSON.stringify(b64Decode(parts[1]), null, 2);
  document.getElementById('jwt-sig').textContent = parts[2] + '\n\n(HMAC-SHA256 of header.payload using the server secret)';
  document.getElementById('token-display').style.display = '';
}
```

**Sign Out button** in the top-right of the AuthFlow UI. Clicking it:
1. Clears `currentToken = null` in memory
2. Hides the token display panel and API test panel
3. Shows the login panel again

```js
document.getElementById('btn-signout').addEventListener('click', function() {
  currentToken = null;
  document.getElementById('token-display').style.display = 'none';
  document.getElementById('api-panel').style.display = 'none';
  document.getElementById('login-panel').style.display = '';
});
```

Show a note next to the button:
```
⚠ JWT logout is client-side only — the token is still valid on the server until it expires.
  True revocation requires a server-side denylist. See the Access/Refresh demo (port 3063).
```

**Amber banner:**
```
⚠ JWT signed with secret="secret" — brute-forceable. See demo-attacked/jwt-attacks/ for the full attack.
```

---

## Port 3059 — JWT & Bearer Concept Guide

### File: `jwt-bearer/guide-server.js`

Copy `<style>` from `DASHBOARD_HTML` verbatim.

**Title:** `🪙 JWT & Bearer Token Authentication — How It Works`

**Section 1 — JWT Structure** (`.flow-box`)

Heading: `JSON Web Token — Three Parts`

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjEsInVzZXJuYW1lIjoiYWxpY2UiLCJyb2xlIjoidXNlciIsImlhdCI6MTcxODUxMjAwMH0.xK9zPqr4mN2vL8tY3wB6Qf1hUjSdEcMaIoRkPlWn
│──────────────────────────────────────│────────────────────────────────────────────────────────────────────│──────────────────────────────────────────────────┤
          HEADER (red)                                    PAYLOAD (purple)                                              SIGNATURE (blue)
  base64url({ alg, typ })          base64url({ sub, username, role, iat, exp })          HMAC-SHA256(header + "." + payload, secret)

Decoded HEADER:   { "alg": "HS256", "typ": "JWT" }
Decoded PAYLOAD:  { "sub": 1, "username": "alice", "role": "user",
                    "iat": 1718512000, "exp": 1718598400 }
SIGNATURE:        Proves the header+payload were not tampered with
                  Server verifies: SHA256(header.payload) with its secret = signature?
```

Show this as a `<pre>` with inline color spans matching the token colors.

**Section 2 — Live JWT Decoder** (`.flow-box`)

Heading: `🔍 Paste any JWT — decode it`

```html
<textarea class="field" id="jwt-input" rows="3" style="width:100%;resize:vertical;font-size:0.75rem"
  placeholder="Paste a JWT here (e.g., from port 3058 login)">
</textarea>
<button class="demo-btn" id="btn-decode-jwt" style="margin-top:0.5rem">Decode JWT</button>
<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:0.75rem;margin-top:0.75rem">
  <div>
    <div style="font-size:0.75rem;color:#f87171;margin-bottom:0.25rem">HEADER</div>
    <pre class="decoded-box" id="out-header" style="min-height:60px"></pre>
  </div>
  <div>
    <div style="font-size:0.75rem;color:#a78bfa;margin-bottom:0.25rem">PAYLOAD (claims)</div>
    <pre class="decoded-box" id="out-payload" style="min-height:60px"></pre>
  </div>
  <div>
    <div style="font-size:0.75rem;color:#60a5fa;margin-bottom:0.25rem">SIGNATURE</div>
    <pre class="decoded-box" id="out-sig" style="min-height:60px"></pre>
  </div>
</div>
<div class="result-banner" id="decode-note" style="display:none"></div>
```

```js
function b64urlDecode(str) {
  try { return JSON.parse(atob(str.replace(/-/g,'+').replace(/_/g,'/'))); }
  catch(e) { return { raw: str }; }
}

document.getElementById('btn-decode-jwt').addEventListener('click', function() {
  var token = document.getElementById('jwt-input').value.trim();
  var parts = token.split('.');
  if (parts.length !== 3) {
    showResult('decode-note', 'failure', '✗ Not a valid JWT — needs exactly 3 dot-separated parts');
    return;
  }
  var header = b64urlDecode(parts[0]);
  var payload = b64urlDecode(parts[1]);
  document.getElementById('out-header').textContent = JSON.stringify(header, null, 2);
  document.getElementById('out-payload').textContent = JSON.stringify(payload, null, 2);
  document.getElementById('out-sig').textContent = parts[2] + '\n\n(Cannot verify without the server secret)';

  var notes = [];
  if (payload.exp) notes.push('Expires: ' + new Date(payload.exp * 1000).toLocaleString());
  if (payload.iat) notes.push('Issued: ' + new Date(payload.iat * 1000).toLocaleString());
  if (payload.role) notes.push('Role claim: ' + payload.role);
  showResult('decode-note', 'info', 'ℹ ' + notes.join(' | '));
});
```

**Section 3 — JWT vs Session Comparison** (`.flow-box`)

Heading: `JWT vs Session — Key Differences`

```html
<table style="width:100%;border-collapse:collapse;font-size:0.82rem">
  <tr style="color:#64748b;border-bottom:1px solid #1a3a1a">
    <th style="text-align:left;padding:0.5rem">Property</th>
    <th>Session Token</th>
    <th>JWT</th>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">Server stores session</td>
    <td style="text-align:center;color:#fca5a5">Yes (Map / DB)</td>
    <td style="text-align:center;color:#4ade80">No — stateless</td>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">User data lookup on each request</td>
    <td style="text-align:center;color:#fca5a5">Yes (DB query)</td>
    <td style="text-align:center;color:#4ade80">No — claims in token</td>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">Instant revocation</td>
    <td style="text-align:center;color:#4ade80">Yes (delete session)</td>
    <td style="text-align:center;color:#fca5a5">No — valid until expiry</td>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">Horizontal scaling</td>
    <td style="text-align:center;color:#fca5a5">Needs shared session store</td>
    <td style="text-align:center;color:#4ade80">Easy — any server verifies</td>
  </tr>
  <tr>
    <td style="padding:0.5rem;color:#94a3b8">Secret compromised</td>
    <td style="text-align:center;color:#4ade80">Rotate session keys</td>
    <td style="text-align:center;color:#fca5a5">All tokens invalidated — must re-login</td>
  </tr>
</table>
```

**Section 4 — Standard JWT Claims** (`.flow-box`)

Heading: `Registered JWT Claims (RFC 7519)`

| Claim | Name | Example |
|-------|------|---------|
| `sub` | Subject | User ID: `1` |
| `iss` | Issuer | `"https://auth.myapp.com"` |
| `aud` | Audience | `"https://api.myapp.com"` |
| `exp` | Expiration time | Unix timestamp |
| `iat` | Issued at | Unix timestamp |
| `jti` | JWT ID | Unique token identifier |

**Section 5 — Bearer Token Usage** (`.flow-box`)

Heading: `How to Send a Bearer Token`

```
Correct:
  Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...

Wrong (don't do this):
  Authorization: eyJhbGciOiJIUzI1NiJ9...     ← missing "Bearer " prefix
  Authorization: JWT eyJhbGciOiJIUzI1NiJ9... ← wrong scheme
  ?token=eyJhbGciOiJIUzI1NiJ9...             ← URL param, ends up in logs

The "Bearer" scheme is defined in RFC 6750.
Bearer = "I bear (possess) this token, grant me access."
```

**Section 6 — Live API Test** (`.flow-box`)

Heading: `🧪 Test the JWT Against Port 3058`

```html
<div style="margin-bottom:0.75rem">
  <label style="font-size:0.82rem;color:#94a3b8">Token (paste from port 3058 login):</label>
  <textarea class="token-input" id="live-token" rows="3"
    placeholder="Paste JWT here — login at localhost:3058 first"></textarea>
</div>
<div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin-bottom:0.75rem">
  <button class="demo-btn" id="btn-test-me">GET /api/me</button>
  <button class="demo-btn" id="btn-test-tasks">GET /api/tasks</button>
  <button class="demo-btn" id="btn-test-admin">GET /api/admin/users (admin only)</button>
</div>
<div class="result-banner" id="live-result"></div>
<pre class="decoded-box" id="live-output" style="min-height:80px">–</pre>
```

```js
async function callWithToken(endpoint, resultId, outputId) {
  var token = document.getElementById('live-token').value.trim();
  if (!token) {
    showResult(resultId, 'failure', '✗ Paste a JWT token above first (login at localhost:3058)');
    return;
  }
  try {
    var res = await fetch('http://localhost:3058' + endpoint, {
      headers: { 'Authorization': 'Bearer ' + token }
    });
    var data = await res.json();
    document.getElementById(outputId).textContent = JSON.stringify(data, null, 2);
    if (res.ok) {
      showResult(resultId, 'success', '✓ ' + res.status + ' — server verified the JWT signature, no DB lookup needed');
    } else {
      showResult(resultId, 'failure', '✗ ' + res.status + ' — ' + data.error);
    }
  } catch(e) {
    showResult(resultId, 'failure', '✗ ' + e.message + ' — is port 3058 running?');
    document.getElementById(outputId).textContent = '';
  }
}

document.getElementById('btn-test-me').addEventListener('click', function() {
  callWithToken('/api/me', 'live-result', 'live-output');
});
document.getElementById('btn-test-tasks').addEventListener('click', function() {
  callWithToken('/api/tasks', 'live-result', 'live-output');
});
document.getElementById('btn-test-admin').addEventListener('click', function() {
  callWithToken('/api/admin/users', 'live-result', 'live-output');
});
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
input.field, textarea.field {
  background: #111; border: 1px solid #1a3a1a; color: #00ff41;
  font-family: 'Courier New', Courier, monospace; font-size: 0.82rem;
  padding: 0.4rem 0.6rem; border-radius: 4px;
}
```

**`showResult` helper:**

```js
function showResult(id, type, msg) {
  var el = document.getElementById(id);
  el.className = 'result-banner ' + type;
  el.textContent = msg;
  el.style.display = 'block';
}
```

**Navigation:**
- `Weak JWT (3058)` → `window.open('http://localhost:3058')`
- `Strong JWT (3060)` → `window.open('http://localhost:3060')`

---

## Port 3060 — AuthFlow (Strong JWT)

### File: `jwt-bearer/jwt-strong-server.js`

Same endpoints as port 3058. Differences:

**Strong secret:**
```js
const crypto = require('crypto');
// ✅ 64 random bytes = 512-bit key — not brute-forceable
const JWT_SECRET = crypto.randomBytes(64).toString('hex');
// Generated once at startup. In production: load from environment variable.
console.log('[JWT] Secret generated (64 bytes). In production: store in JWT_SECRET env var.');
```

**Short expiry:**
```js
const JWT_EXPIRES_IN = '15m'; // ✅ 15 minutes, not 24 hours
```

**Algorithm allowlist:**
```js
// ✅ Whitelist algorithm — prevent alg:none attack
const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
```

**Green banner on login page:**
```
✅ STRONG JWT: 64-byte random secret, 15-minute expiry, HS256 algorithm whitelisted.
```

Show note below the token display:
```
This secret was generated with crypto.randomBytes(64) at startup.
In production, set JWT_SECRET as an environment variable (never commit to git).
Expiry: 15 minutes — user must refresh or re-login.
```

---

## Shared `package.json` at `jwt-bearer/`

```json
{
  "name": "jwt-bearer-demo",
  "version": "1.0.0",
  "scripts": {
    "weak":   "node jwt-server.js",
    "guide":  "node guide-server.js",
    "strong": "node jwt-strong-server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "jsonwebtoken": "^9.0.2"
  }
}
```

---

## README at `jwt-bearer/README.md`

### How It Works

```
POST /api/login { username, password }
        ↓
Server: jwt.sign({ sub, username, role, iat, exp }, JWT_SECRET, { algorithm: 'HS256' })
        ↓
Returns: { token: "eyJ...", tokenType: "Bearer" }
        ↓
Client stores token (localStorage or memory)
        ↓
GET /api/tasks
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjEsI...
        ↓
Server: jwt.verify(token, JWT_SECRET) → decoded claims
        ↓
No database lookup — user identity is in the token itself
```

### JWT structure

```
header.payload.signature
  │       │         │
  │       │         └─ HMAC-SHA256(header + "." + payload, secret)
  │       └─ base64url({ sub, username, role, iat, exp })
  └─ base64url({ alg: "HS256", typ: "JWT" })
```

### Vulnerability (port 3058)

`JWT_SECRET = 'secret'` — brute-forceable. See `demo-attacked/jwt-attacks/` for the full attack demo.

### Run the demo

```bash
cd auth-concepts/jwt-bearer
npm install
npm run weak    # terminal 1 → localhost:3058
npm run guide   # terminal 2 → localhost:3059 (concept guide)
npm run strong  # terminal 3 → localhost:3060
```

### Walkthrough

1. Login at **localhost:3058** — observe the three-part JWT
2. Open **localhost:3059** — paste the JWT into the decoder, see header/payload in plain JSON
3. Modify the payload in the decoder — the token is still three parts but the signature will fail verification
4. Compare the **localhost:3060** token — same structure, but 15-minute expiry

---

## Key technical notes for Cursor

1. **`jwt.verify()` vs `jwt.decode()`.** Always use `jwt.verify()` for authentication. `jwt.decode()` skips signature verification entirely and should never be used to establish trust. Only call `jwt.decode()` after a token has already been verified, or for display purposes in the guide.

2. **Algorithm must be whitelisted in `jwt.verify()` options.** Without `{ algorithms: ['HS256'] }`, a crafted token with `"alg": "none"` bypasses signature verification on some library versions. This is the alg:none attack — see `demo-attacked/jwt-attacks/` for the live demo. Port 3060 protects against it; port 3058 does not pass the algorithms option.

3. **CORS must be on ports 3058 and 3060.** The guide (3059) calls both servers to test tokens. Add `cors({ origin: 'http://localhost:3059' })` to both jwt-server.js and jwt-strong-server.js.

4. **Port 3060 tokens are NOT valid on port 3058 and vice versa.** Each server generates its own secret (port 3060 with `crypto.randomBytes(64)`, port 3058 with `'secret'`). The guide's live test section calls port 3058 only — note this in the UI.

5. **`localStorage` for token storage in port 3058/3060 client.** The API playground stores the JWT in a JS variable (`let currentToken = ...`) not in localStorage — localStorage persists across tabs and is XSS-readable. Show this as a comment: `// Stored in memory — cleared on page refresh. For persistent auth, use httpOnly cookie + refresh token.`

6. **The three-color JWT display.** In the token display panel, split by `.` → 3 parts → render as `<span style="color:#f87171">header</span>.<span style="color:#a78bfa">payload</span>.<span style="color:#60a5fa">sig</span>`. The colors must match between the raw display and the three decoded boxes below it.
