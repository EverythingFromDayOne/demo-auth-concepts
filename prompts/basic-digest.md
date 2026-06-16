# Cursor Prompt: Basic & Digest Auth Demo — SimpleDesk (Ports 3049–3051)

## Global UI Standard — applies to every server in this lab

| Server type | Theme |
|-------------|-------|
| Attacker server / Attack guide | Clone `DASHBOARD_HTML` from `demo-attacked/reverse-tabnabbing/attacker-server.js` — `#0a0a0a` bg, `#00ff41` text, `'Courier New'` font. Copy `<style>` verbatim. |
| Internal / target server | Muted corporate — `#1a1a2e` bg, `#e2e8f0` text |
| Victim servers | Realistic product UI matching their brand |

**Attacker/guide pages — non-negotiable rules:**
- Copy the `<style>` block from `DASHBOARD_HTML` in `demo-attacked/reverse-tabnabbing/attacker-server.js` **verbatim**. Never recreate or paraphrase it.
- Body layout: `padding: 2rem` on body. No `max-width` wrapper div. No centering.
- Panels: use `.flow-box` and `.credentials-panel` classes. Full-width. Only `<p>` text may use `max-width`.
- Navigation: **fixed bottom-left `target-switcher` only.**
- **After** the verbatim `<style>` block, always add this override: `.flow-box { max-width: 900px; }`

---

## Code Comment Standard — use throughout all three files

```
// ⚠️ VULNERABILITY: <what is wrong and why it matters>
// ✅ PROTECTED: <what was changed and why it is now safe>
```

No lorem ipsum anywhere. All copy must be realistic product language.

---

## Files to create

```
auth-concepts/basic-digest/
├── basic-server.js       # SimpleDesk — HTTP Basic Auth        — port 3049
├── guide-server.js       # Basic & Digest Auth Lab             — port 3050
├── session-server.js     # SimpleDesk — Session Token Auth     — port 3051
├── package.json
└── README.md
```

---

## Context

**Concept:** HTTP Basic Authentication & Digest Authentication  
**App name:** SimpleDesk — an internal IT helpdesk ticket system  
**Tagline:** "Submit and track IT support tickets"  
**Folder:** `auth-concepts/basic-digest/`

SimpleDesk uses HTTP Basic Auth: the browser sends `Authorization: Basic base64(username:password)` with every single HTTP request. Base64 is trivially reversible — it is encoding, not encryption. Anyone who can see the network traffic (proxy logs, load balancer logs, browser history, Referer headers) can decode the credentials instantly.

**Why it matters:** Basic Auth is still in widespread use for internal tools and APIs. The attack guide shows that base64 decoding requires zero skill — `atob()` in the browser console is sufficient. Digest Auth improves on Basic (credentials never sent in plaintext) but uses MD5, which is offline-crackable. Both are superseded by session tokens or JWT-based authentication.

---

## Port Layout

| Port | Role | App |
|------|------|-----|
| 3049 | Concept: Basic Auth | SimpleDesk (credentials in every request as base64) |
| 3050 | Concept guide | Basic & Digest Auth Lab (explains both mechanisms + attack) |
| 3051 | Improved: Session Auth | SimpleDesk (session token issued on login, not credentials every request) |

---

## Port 3049 — Basic Auth SimpleDesk

### File: `basic-digest/basic-server.js`

**Dependencies:** `express ^4.18.2`, `cors ^2.8.5`

Enable CORS:
```js
const cors = require('cors');
app.use(cors({ origin: 'http://localhost:3050' }));
app.use(express.json());
```

### Users

```js
const USERS = [
  { username: 'alice', password: 'pass1234', fullName: 'Alice Chen',    role: 'user' },
  { username: 'bob',   password: 'qwerty123',  fullName: 'Bob Martinez',  role: 'user' },
  { username: 'admin', password: 'admin456',   fullName: 'Admin User',    role: 'admin' },
];
```

### Basic Auth middleware

```js
function basicAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';

  if (!authHeader.startsWith('Basic ')) {
    // Challenge the client: ask for credentials
    res.setHeader('WWW-Authenticate', 'Basic realm="SimpleDesk"');
    return res.status(401).json({ error: 'Authentication required' });
  }

  // Decode base64: "Basic dXNlcjpwYXNz" → "user:pass"
  const base64 = authHeader.slice(6); // remove "Basic "
  const decoded = Buffer.from(base64, 'base64').toString('utf8');
  const colonIndex = decoded.indexOf(':');
  const username = decoded.substring(0, colonIndex);
  const password = decoded.substring(colonIndex + 1);

  const user = USERS.find(u => u.username === username && u.password === password);
  if (!user) {
    res.setHeader('WWW-Authenticate', 'Basic realm="SimpleDesk"');
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  req.user = user;
  next();
}
```

### Routes

```js
// Every route requires Basic Auth — credentials sent with EVERY request
app.get('/', basicAuth, (req, res) => {
  res.send(DASHBOARD_HTML(req.user));
});

app.get('/api/me', basicAuth, (req, res) => {
  res.json({ username: req.user.username, fullName: req.user.fullName, role: req.user.role });
});

app.get('/api/tickets', basicAuth, (req, res) => {
  res.json([
    { id: 1, title: 'Printer not working', status: 'open',   priority: 'low',    author: 'alice' },
    { id: 2, title: 'VPN access request',  status: 'open',   priority: 'medium', author: 'bob' },
    { id: 3, title: 'Software license',    status: 'closed', priority: 'low',    author: 'alice' },
  ]);
});

app.post('/api/tickets', basicAuth, (req, res) => {
  const { title, priority } = req.body;
  res.json({ id: 4, title, priority, status: 'open', author: req.user.username });
});

// ⚠️ VULNERABILITY: Basic Auth has no logout at all.
// There is no session to destroy, no token to revoke.
// The browser caches credentials and keeps sending them until the tab is closed.
// Do NOT add a logout button — the absence of logout IS the demonstration.
// The guide's comparison table (Section 5) explains this contrast with session auth.
```

### UI design — minimal internal tool

Colors: `#f8fafc` background, `#1e293b` header bar, `#f1f5f9` sidebar, `#2563eb` accent.

**How Basic Auth login works in the browser:** Do NOT build an HTML login form. Let the browser show its native Basic Auth dialog (the browser automatically prompts when it receives a 401 with `WWW-Authenticate: Basic`). This is intentional — it demonstrates exactly how Basic Auth works in practice.

**Main page** (after auth): Show a simple helpdesk dashboard.

Layout:
- Top bar: "SimpleDesk" logo + logged-in user (shown by calling `GET /api/me`)
- Left sidebar: nav — Tickets, Profile
- Main: ticket list from `GET /api/tickets` rendered as a table

Ticket table:
```
| ID | Title                  | Priority | Status |
|----|------------------------|----------|--------|
|  1 | Printer not working    | low      | open   |
|  2 | VPN access request     | medium   | open   |
```

**Amber banner at top of dashboard:**
```
⚠ BASIC AUTH: your credentials (username:password) are sent base64-encoded with EVERY request.
Open DevTools → Network → any request → Authorization header to see them.
```

**No logout button.** Do not add one. The absence of a logout option IS the vulnerability being demonstrated. Users will notice there's no way to sign out — that's the point. The guide (port 3050) explains why in the comparison table.

**`package.json` scripts:**
```json
{
  "scripts": {
    "start": "node basic-server.js",
    "basic": "node basic-server.js"
  },
  "dependencies": { "express": "^4.18.2", "cors": "^2.8.5" }
}
```

---

## Port 3050 — Concept Guide

### File: `basic-digest/guide-server.js`

Open `demo-attacked/reverse-tabnabbing/attacker-server.js`. Find the `DASHBOARD_HTML` constant. Copy its entire `<style>` block **verbatim**. Paste it into this guide's HTML template.

### Page structure

**Title:** `🔐 Basic & Digest Auth — How It Works`

**Section 1 — What is Basic Auth?** (`.flow-box`)

Heading: `How HTTP Basic Auth Works`

ASCII flow:
```
Browser                          Server (3049)
   │                                  │
   ├─── GET / ──────────────────────→ │
   │                                  │
   │ ←── 401 WWW-Authenticate: Basic ─┤
   │                                  │
   │  [Browser shows login dialog]    │
   │                                  │
   ├─── GET / ──────────────────────→ │
   │  Authorization: Basic           │
   │  YWxpY2U6cGFzczEyMzQ=      │ ← base64("alice:pass1234")
   │                                  │
   │ ←── 200 OK ─────────────────────┤
   │                                  │
   │ (EVERY subsequent request also   │
   │  sends the Authorization header) │
```

Show this in a `<pre>` with `color:#00ff41`.

**Section 2 — Decode Basic Auth Live** (`.flow-box`)

Heading: `🔓 Decode any Basic Auth header`

```html
<div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;margin-bottom:0.75rem">
  <input class="field" id="b64-input" style="flex:1" 
    placeholder="Paste Authorization header value or base64 string"
    value="YWxpY2U6cGFzczEyMzQ=">
  <button class="demo-btn" id="btn-decode">Decode</button>
</div>
<pre class="decoded-box" id="decode-output" style="min-height:50px">Click Decode</pre>
```

```js
document.getElementById('btn-decode').addEventListener('click', function() {
  var input = document.getElementById('b64-input').value.trim();
  // Strip "Basic " prefix if present
  if (input.startsWith('Basic ')) input = input.slice(6);
  try {
    var decoded = atob(input);
    var colonIdx = decoded.indexOf(':');
    var username = decoded.substring(0, colonIdx);
    var password = decoded.substring(colonIdx + 1);
    document.getElementById('decode-output').textContent =
      'Decoded: "' + decoded + '"\n\nUsername: ' + username + '\nPassword: ' + password +
      '\n\n→ atob("' + input + '") → "' + decoded + '"' +
      '\n→ Zero tools required. Any browser console can do this.';
  } catch(e) {
    document.getElementById('decode-output').textContent = 'Invalid base64: ' + e.message;
  }
});
```

Auto-populate the encoder too:

```html
<div style="margin-top:1rem">
  <strong>Encode your own:</strong>
  <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;margin-top:0.5rem">
    <input class="field" id="enc-user" placeholder="username" value="alice" style="width:120px">
    <span style="color:#64748b">:</span>
    <input class="field" id="enc-pass" placeholder="password" value="pass1234" style="width:140px">
    <button class="demo-btn" id="btn-encode">Encode →</button>
    <span id="enc-result" style="color:#fbbf24;font-family:monospace;font-size:0.85rem"></span>
  </div>
</div>
```

```js
document.getElementById('btn-encode').addEventListener('click', function() {
  var u = document.getElementById('enc-user').value;
  var p = document.getElementById('enc-pass').value;
  var encoded = btoa(u + ':' + p);
  document.getElementById('enc-result').textContent = 'Basic ' + encoded;
});
document.getElementById('btn-encode').click(); // auto-run on load
```

**Section 3 — Live Credential Intercept** (`.flow-box`)

Heading: `📡 Intercept Credentials from Port 3049`

Button that makes a request to port 3049 with known credentials and shows what was sent:

```html
<div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;margin-bottom:0.75rem">
  <input class="field" id="int-user" value="alice" style="width:100px">
  <span style="color:#64748b">:</span>
  <input class="field" id="int-pass" value="pass1234" style="width:120px">
  <button class="demo-btn" id="btn-intercept">Send request → :3049 + show header</button>
</div>
<div class="result-banner" id="intercept-result"></div>
<pre class="decoded-box" id="intercept-output" style="min-height:80px">–</pre>
```

```js
document.getElementById('btn-intercept').addEventListener('click', async function() {
  var u = document.getElementById('int-user').value;
  var p = document.getElementById('int-pass').value;
  var encoded = btoa(u + ':' + p);
  var header = 'Basic ' + encoded;

  try {
    var res = await fetch('http://localhost:3049/api/tickets', {
      headers: { 'Authorization': header }
    });
    var data = await res.json();
    document.getElementById('intercept-output').textContent =
      'Request sent with:\n  Authorization: ' + header +
      '\n\nBase64 decoded:\n  "' + atob(encoded) + '"' +
      '\n\nServer responded:\n' + JSON.stringify(data, null, 2) +
      '\n\n⚠ This Authorization header is sent with EVERY request to :3049.\n' +
      'Every API call, every page load. Always visible in network logs.';

    showResult('intercept-result', 'success', '✓ Request succeeded — credentials in header as shown below');
  } catch(e) {
    showResult('intercept-result', 'failure', '✗ ' + e.message + ' — is port 3049 running?');
  }
});
```

**Section 4 — What is Digest Auth?** (`.flow-box`)

Heading: `Digest Auth — MD5 Challenge-Response`

ASCII flow:
```
Browser                          Server
   │                                  │
   ├─── GET /api/resource ──────────→ │
   │                                  │
   │ ←── 401 + WWW-Authenticate: ────┤
   │      Digest realm="...",        │
   │      nonce="a3f9b2c1..."        │ ← random value, different each time
   │                                  │
   │  Client computes:                │
   │  HA1 = MD5(username:realm:pass)  │
   │  HA2 = MD5(method:uri)           │
   │  response = MD5(HA1:nonce:HA2)   │
   │                                  │
   ├─── GET + Authorization: Digest ─→│
   │      response="d7a8f3..."        │ ← hash, not the password
   │                                  │
   │ ←── 200 OK ─────────────────────┤
```

Key differences from Basic:
```
Basic Auth:        Authorization: Basic YWxpY2U6cGFzczEyMzQ=
                   → Anyone can decode: alice:pass1234

Digest Auth:       Authorization: Digest response="d7a8f3c9..."
                   → Server verifies the hash, password never sent
                   → BUT: uses MD5 — offline-crackable if nonce is captured
                   → Still no forward secrecy, deprecated in most contexts
```

**Section 5 — Why Both Are Superseded** (`.flow-box`)

Heading: `Why Sessions/Tokens Are Better`

Comparison table:

```html
<table style="width:100%;border-collapse:collapse;font-size:0.82rem;margin-top:0.5rem">
  <tr style="color:#64748b;border-bottom:1px solid #1a3a1a">
    <th style="text-align:left;padding:0.5rem">Property</th>
    <th>Basic Auth</th>
    <th>Digest Auth</th>
    <th>Session Token</th>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">Password over wire</td>
    <td style="text-align:center;color:#fca5a5">Yes (base64)</td>
    <td style="text-align:center;color:#4ade80">No (hashed)</td>
    <td style="text-align:center;color:#4ade80">No</td>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">Sent every request</td>
    <td style="text-align:center;color:#fca5a5">Yes</td>
    <td style="text-align:center;color:#fca5a5">Yes</td>
    <td style="text-align:center;color:#4ade80">No (token only)</td>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">Logout possible</td>
    <td style="text-align:center;color:#fca5a5">No</td>
    <td style="text-align:center;color:#fca5a5">No</td>
    <td style="text-align:center;color:#4ade80">Yes</td>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">MFA support</td>
    <td style="text-align:center;color:#fca5a5">No</td>
    <td style="text-align:center;color:#fca5a5">No</td>
    <td style="text-align:center;color:#4ade80">Yes</td>
  </tr>
  <tr>
    <td style="padding:0.5rem;color:#94a3b8">Offline attack surface</td>
    <td style="text-align:center;color:#fca5a5">Password</td>
    <td style="text-align:center;color:#fbbf24">MD5 hash</td>
    <td style="text-align:center;color:#4ade80">Opaque token</td>
  </tr>
</table>
```

**Navigation:** Fixed bottom-left `target-switcher`:
- `Basic Auth (3049)` → `window.open('http://localhost:3049')`
- `Session Auth (3051)` → `window.open('http://localhost:3051')`

**Helper CSS (append after verbatim style block):**
```css
/* Override default flow-box width from copied style */
.flow-box { max-width: 900px; }

input.field {
  background: #111; border: 1px solid #1a3a1a; color: #00ff41;
  font-family: 'Courier New', Courier, monospace; font-size: 0.82rem;
  padding: 0.4rem 0.6rem; border-radius: 4px;
}
.result-banner { padding: 0.6rem 1rem; border-radius: 4px; font-size: 0.82rem; margin-top: 0.75rem; display: none; }
.result-banner.success { background: #052e16; border: 1px solid #16a34a; color: #4ade80; }
.result-banner.failure { background: #450a0a; border: 1px solid #dc2626; color: #fca5a5; }
.result-banner.info    { background: #0c1a2e; border: 1px solid #1e40af; color: #93c5fd; }
pre.decoded-box {
  background: #0a0a0a; border: 1px solid #1a3a1a; border-radius: 4px;
  padding: 0.75rem; font-size: 0.78rem; color: #cbd5e1;
  white-space: pre-wrap; word-break: break-all; margin-top: 0.5rem;
}
```

```js
function showResult(id, type, msg) {
  var el = document.getElementById(id);
  el.className = 'result-banner ' + type;
  el.textContent = msg;
  el.style.display = 'block';
}
```

**`package.json` scripts:**
```json
{
  "scripts": { "guide": "node guide-server.js" },
  "dependencies": { "express": "^4.18.2" }
}
```

---

## Port 3051 — Session Auth SimpleDesk (Improved)

### File: `basic-digest/session-server.js`

Same app as port 3049. Instead of Basic Auth, uses a login form + session token. Credentials are sent **once** (at login), then a random token is used for all subsequent requests.

```js
const crypto = require('crypto');
const sessions = new Map();

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = USERS.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username: user.username, fullName: user.fullName, role: user.role });
  res.json({ token, user: { username: user.username, fullName: user.fullName } });
});

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const session = sessions.get(token);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });
  req.user = session;
  next();
}

app.get('/api/me', requireAuth, (req, res) => res.json(req.user));
app.get('/api/tickets', requireAuth, (req, res) => res.json([/* same tickets */]));

app.post('/api/logout', requireAuth, (req, res) => {
  sessions.delete(req.headers.authorization.slice(7));
  res.json({ message: 'Logged out' });
});
```

**Login page:** Standard HTML form. Username + password inputs. "Sign In" button. Submit calls `POST /api/login`, stores token in `localStorage.setItem('sdToken', data.token)`.

**Critical — login input CSS:** Both inputs use `class="login-input"` with identical explicit styles — never rely on browser defaults for `input[type="password"]`:

```css
.login-input {
  width: 100%; padding: 0.6rem 0.75rem; border: 1px solid #cbd5e1;
  border-radius: 6px; font-size: 0.95rem; color: #0f172a;
  background: #fff; outline: none; box-sizing: border-box; font-family: inherit;
}
.login-input:focus { border-color: #2563eb; box-shadow: 0 0 0 3px rgba(37,99,235,0.15); }
```

**Green banner on dashboard:**
```
✅ SESSION AUTH: credentials sent once at login. All subsequent requests use an opaque token.
Token is not your password — it can be revoked instantly with logout.
```

**Logout button** in top bar: calls `POST /api/logout`, clears localStorage, redirects to `/login`.

Note visible below the logout button:
```js
// What's different vs Basic Auth:
// POST /api/login → credentials sent once → server returns random 64-char token
// GET  /api/tickets → Authorization: Bearer a3f9b2c1... (opaque, not your password)
// POST /api/logout  → sessions.delete(token) — impossible with Basic Auth
```

**`package.json` scripts:**
```json
{
  "scripts": { "session": "node session-server.js" }
}
```

---

## Shared `package.json` at `basic-digest/`

```json
{
  "name": "basic-digest-demo",
  "version": "1.0.0",
  "scripts": {
    "basic":   "node basic-server.js",
    "guide":   "node guide-server.js",
    "session": "node session-server.js"
  },
  "dependencies": { "express": "^4.18.2", "cors": "^2.8.5" }
}
```

---

## README at `basic-digest/README.md`

### How It Works

```
HTTP Basic Auth flow:
  Client                      Server
     │                           │
     ├─── GET /api/tickets ─────→│  401 + WWW-Authenticate: Basic
     │←── 401 ───────────────────┤
     │                           │
     ├─── GET /api/tickets ─────→│
     │    Authorization:         │
     │    Basic YWxpY2U6c3Vuc2g  │  ← atob() → "alice:pass1234"
     │←── 200 tickets ───────────┤
     │                           │
     │  (every request repeats   │
     │   the Authorization header)
```

### The vulnerability

`atob("YWxpY2U6cGFzczEyMzQ=")` → `"alice:pass1234"` — one line in any browser console. The password travels with every request and is visible in proxy logs, load balancer access logs, browser history (if embedded in URL), and any packet capture on the network.

### Run the demo

```bash
cd auth-concepts/basic-digest
npm install
npm run basic    # terminal 1 → localhost:3049 (Basic Auth)
npm run guide    # terminal 2 → localhost:3050 (concept guide)
npm run session  # terminal 3 → localhost:3051 (Session Auth)
```

### Walkthrough

1. Open **localhost:3049** — browser shows native Basic Auth dialog. Enter alice / pass1234.
2. Open DevTools → Network → any request → Headers → `Authorization: Basic YWxpY2U6cGFzczEyMzQ=`
3. Open **localhost:3050** — paste that header value into the decoder → see credentials instantly
4. Click "Send request → :3049 + show header" → see what's sent with every API call
5. Open **localhost:3051** — HTML login form, session token issued. Check Network: subsequent requests send `Bearer <token>`, not the password.

### Key concepts

**Base64 ≠ Encryption:** Base64 is a binary-to-text encoding format. It is completely reversible without a key. `atob(encoded)` decodes it instantly in any browser.

**Stateless by design (and that's the problem):** Because HTTP is stateless, Basic Auth re-sends credentials with every request. There is no server-side session — and therefore no way to "log out." The browser caches the credentials and keeps sending them until the tab is closed.

**Digest improves but doesn't solve it:** Digest Auth never sends the password, but the server must store password hashes in a crackable MD5 format. Modern databases use bcrypt/Argon2, which are incompatible with Digest. Digest is obsolete.

**When Basic Auth is acceptable:** Internal tools over HTTPS with a reverse proxy and HTTP Strict Transport Security — the TLS layer provides the encryption that Basic Auth lacks. Still can't logout. Still can't do MFA. Session tokens are almost always better.

---

## Key technical notes for Cursor

1. **No HTML login form on port 3049.** The native browser dialog triggered by `WWW-Authenticate: Basic` IS the demo — it shows exactly how Basic Auth works. Adding an HTML form defeats the purpose. **Also: no logout button.** The complete absence of logout is the point — users will notice it's missing. Port 3051 (session auth) has real logout to provide the contrast.

2. **`atob()` vs `Buffer.from()`.** Browser side: `atob(b64)` decodes. Node.js server side: `Buffer.from(b64, 'base64').toString('utf8')`. Both are in the prompt — do not mix them up.

3. **CORS must include credentials on port 3049.** The guide (3050) sends cross-origin requests with an `Authorization` header. Use `cors({ origin: 'http://localhost:3050' })` on port 3049 — the default `cors()` with no options also works but is less explicit.

4. **Port 3051 DOES need an HTML login form.** Unlike 3049, the session-auth version takes credentials once via a POST form, then uses a token. `class="login-input"` on both inputs — never rely on browser defaults for `input[type="password"]`.

5. **The guide's intercept demo (Section 3) calls port 3049 directly from the browser.** If port 3049 is not running, the fetch will fail with a network error. Show a clear error message: "✗ Could not reach :3049 — is it running?"

6. **`btoa()` throws on non-Latin1 characters.** If a user types a password with emojis or Unicode beyond U+00FF, `btoa(u + ':' + p)` will throw. Wrap in try/catch and show a friendly error in the encode section.
