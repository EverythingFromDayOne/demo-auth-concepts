# Cursor Prompt: MFA & TOTP Demo — SecureVault (Ports 3070–3072)

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
auth-concepts/mfa-totp/
├── vulnerable-server.js    # SecureVault — Weak TOTP             — port 3070
├── guide-server.js         # MFA & TOTP Lab                      — port 3071
├── secure-server.js        # SecureVault — Hardened TOTP         — port 3072
├── package.json
└── README.md
```

---

## Context

**Concept:** Multi-Factor Authentication (MFA) using Time-based One-Time Passwords (TOTP)
**App name:** SecureVault — a personal password manager and secrets store
**Tagline:** "Store and access your passwords securely"
**Folder:** `auth-concepts/mfa-totp/`

SecureVault protects sensitive credential data, so a second authentication factor is critical. After entering username + password (factor 1 — something you know), the user must enter a 6-digit TOTP code from their authenticator app (factor 2 — something you have). TOTP codes are computed from a shared secret using HMAC-SHA1 and rotate every 30 seconds.

**Why it matters:** Password theft alone is not enough to breach an MFA-protected account — the attacker also needs the device running the authenticator app. However, weak TOTP implementations allow replay attacks (same code accepted multiple times in the same window) and brute force (no rate limiting on the verify endpoint, combined with an overly large time window). The secure implementation closes both gaps.

---

## Port Layout

| Port | Role | App |
|------|------|-----|
| 3070 | Concept: Weak TOTP | SecureVault (large window, no replay prevention, no rate limit) |
| 3071 | Concept guide | MFA & TOTP Lab (explains TOTP math, attacks, and fixes) |
| 3072 | Improved: Hardened TOTP | SecureVault (strict window, replay prevention, rate limiting, backup codes) |

---

## Shared across all three servers

### Users and TOTP secrets

```js
// ⚠️ DEMO ONLY: TOTP secrets hardcoded in plaintext.
// Production: generate per-user with crypto.randomBytes(20), store encrypted at rest (AES-256-GCM).
// Never log or return TOTP secrets in API responses.

const USERS = [
  {
    username: 'alice',
    password: 'pass1234',
    fullName: 'Alice Chen',
    role: 'user',
    mfaEnabled: true,
    totpSecret: 'JBSWY3DPEHPK3PXP', // base32; otpauth://totp/SecureVault:alice?secret=JBSWY3DPEHPK3PXP&issuer=SecureVault
  },
  {
    username: 'bob',
    password: 'qwerty123',
    fullName: 'Bob Martinez',
    role: 'user',
    mfaEnabled: false, // no MFA — demonstrates contrast; login completes after password only
    totpSecret: null,
  },
  {
    username: 'admin',
    password: 'admin456',
    fullName: 'Admin User',
    role: 'admin',
    mfaEnabled: true,
    totpSecret: 'JBSWY3DPEHPK3PXP',
  },
];
```

**Shared TOTP secret:** `JBSWY3DPEHPK3PXP` (base32, 16 characters). When alice scans the QR code with Google Authenticator / Authy / 1Password, she gets real rotating codes. The same codes appear in the demo helper (`GET /api/current-totp`) for users without an authenticator app.

### Two-phase session model (required for both servers)

MFA requires two login phases. Do not issue a full session token after the password check — issue a short-lived pending token, then upgrade it after TOTP passes.

```js
const crypto = require('crypto');

// Phase 1: password verified, TOTP pending
// Map<pendingToken, { username, expiresAt }>
const pendingSessions = new Map();

// Phase 2: TOTP verified, full session
// Map<sessionToken, { username, fullName, role }>
const completedSessions = new Map();

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const session = completedSessions.get(token);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });
  req.user = session;
  req.token = token;
  next();
}
```

### Demo helper — current TOTP code

Both servers expose this endpoint so users can test without a real authenticator app.

```js
// ⚠️ DEMO ONLY: exposes the current valid TOTP code. Never do this in production.
app.get('/api/current-totp', (req, res) => {
  const { username } = req.query;
  const user = USERS.find(u => u.username === username);
  if (!user || !user.mfaEnabled) return res.status(404).json({ error: 'MFA not enabled for this user' });

  const currentCode = speakeasy.totp.generate({
    secret: user.totpSecret,
    encoding: 'base32',
  });
  const secondsRemaining = 30 - (Math.floor(Date.now() / 1000) % 30);

  res.json({
    code: currentCode,
    secondsRemaining,
    note: 'DEMO ONLY — production servers never expose current TOTP codes',
  });
});
```

### QR code endpoint (both servers)

```js
const QRCode = require('qrcode');

app.get('/api/totp-qr', async (req, res) => {
  const { username } = req.query;
  const user = USERS.find(u => u.username === username);
  if (!user || !user.mfaEnabled) return res.status(404).json({ error: 'MFA not enabled' });

  const otpauthUrl = `otpauth://totp/SecureVault:${username}?secret=${user.totpSecret}&issuer=SecureVault`;
  const qrDataUrl = await QRCode.toDataURL(otpauthUrl);
  // ⚠️ DEMO ONLY: returning the secret. Production: never expose the raw secret after initial setup.
  res.json({ qrDataUrl, otpauthUrl, secret: user.totpSecret });
});
```

---

## Port 3070 — Weak TOTP SecureVault

### File: `mfa-totp/vulnerable-server.js`

**Dependencies:** `express ^4.18.2`, `cors ^2.8.5`, `speakeasy ^2.0.0`, `qrcode ^1.5.3`

Enable CORS:
```js
const cors = require('cors');
app.use(cors({ origin: 'http://localhost:3071' }));
app.use(express.json());
```

### Phase 1 login (password)

```js
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = USERS.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  if (!user.mfaEnabled) {
    // bob: no MFA — issue full session immediately
    const token = crypto.randomBytes(32).toString('hex');
    completedSessions.set(token, { username: user.username, fullName: user.fullName, role: user.role });
    return res.json({ token, mfaRequired: false });
  }

  // alice/admin: MFA required — issue pending token only
  const pendingToken = crypto.randomBytes(16).toString('hex');
  pendingSessions.set(pendingToken, {
    username: user.username,
    expiresAt: Date.now() + 5 * 60 * 1000, // 5-minute window to complete TOTP
  });
  res.json({ mfaRequired: true, pendingToken });
});
```

### Phase 2 TOTP verification — VULNERABLE

```js
app.post('/api/verify-totp', (req, res) => {
  const { pendingToken, code } = req.body;
  const pending = pendingSessions.get(pendingToken);
  if (!pending) return res.status(401).json({ error: 'No pending session — log in again' });

  const user = USERS.find(u => u.username === pending.username);

  // ⚠️ VULNERABILITY 1: window:10 accepts codes from ±5 minutes ago (20 valid codes at once).
  // window:1 is the production standard — allows ±30 seconds for clock skew only.
  const valid = speakeasy.totp.verify({
    secret: user.totpSecret,
    encoding: 'base32',
    token: code,
    window: 10, // ⚠️ 10 steps × 30s = ±5 minutes — far too permissive
  });

  // ⚠️ VULNERABILITY 2: No replay prevention.
  // Once a code passes, it is NOT recorded. The same code can be submitted again
  // within the same 30-second window and will still be accepted.

  // ⚠️ VULNERABILITY 3: No rate limiting on this endpoint.
  // A TOTP code is 6 digits (000000–999999 = 1,000,000 possibilities).
  // With window:10 there are ~20 valid codes active simultaneously.
  // An automated attacker can cycle through all codes — no lockout, no throttle.

  if (!valid) return res.status(401).json({ error: 'Invalid TOTP code' });

  pendingSessions.delete(pendingToken);
  const sessionToken = crypto.randomBytes(32).toString('hex');
  completedSessions.set(sessionToken, {
    username: user.username,
    fullName: user.fullName,
    role: user.role,
  });
  res.json({ token: sessionToken });
});
```

### Information disclosure endpoint

```js
// ⚠️ VULNERABILITY 4: TOTP secret exposed in a "debug" endpoint.
// The secret is the root of trust for MFA — exposing it lets an attacker
// generate valid TOTP codes forever without needing the physical device.
app.get('/api/debug/totp-secret', (req, res) => {
  const { username } = req.query;
  const user = USERS.find(u => u.username === username);
  if (!user || !user.mfaEnabled) return res.status(404).json({ error: 'User not found or MFA disabled' });
  res.json({
    username,
    totpSecret: user.totpSecret, // ⚠️ never expose this
    otpauthUrl: `otpauth://totp/SecureVault:${username}?secret=${user.totpSecret}&issuer=SecureVault`,
  });
});
```

### Protected routes

```js
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ username: req.user.username, fullName: req.user.fullName, role: req.user.role });
});

app.get('/api/vault', requireAuth, (req, res) => {
  res.json([
    { id: 1, site: 'github.com',   username: 'alice@dev.io', passwordPreview: '••••••••' },
    { id: 2, site: 'aws.amazon.com', username: 'alice',       passwordPreview: '••••••••' },
    { id: 3, site: 'stripe.com',   username: 'alice@dev.io', passwordPreview: '••••••••' },
  ]);
});

app.post('/api/logout', requireAuth, (req, res) => {
  completedSessions.delete(req.token);
  res.json({ message: 'Logged out' });
});
```

### UI — two-phase login flow (fully static HTML + client JS)

**Colors:** `#f8fafc` background, `#1e293b` header bar, `#f1f5f9` sidebar, `#7c3aed` accent (purple — signals security).

**Phase 1 panel** (always visible on load): username + password inputs, "Continue" button.

**Phase 2 panel** (hidden until Phase 1 succeeds, `display:none`): 6-digit code input, "Verify" button, "Use backup code" link. Also shows:

```html
<!-- Demo helper: auto-fetches current TOTP from server -->
<div id="totp-helper" style="margin-top:0.75rem;padding:0.6rem;background:#fef3c7;border:1px solid #d97706;border-radius:6px;font-size:0.82rem;color:#78350f">
  ⚠️ Demo helper: current code for <strong id="helper-username"></strong>:
  <strong id="helper-code" style="font-family:monospace;font-size:1.1rem;letter-spacing:0.15em">------</strong>
  <span id="helper-timer" style="margin-left:0.5rem;color:#92400e"></span>
  <br><small>In production, only your authenticator app knows this code.</small>
</div>
```

```js
// Auto-refresh demo helper every second
var helperInterval;
function startHelperRefresh(username) {
  document.getElementById('helper-username').textContent = username;
  helperInterval = setInterval(async function() {
    try {
      var r = await fetch('http://localhost:3070/api/current-totp?username=' + username);
      var d = await r.json();
      document.getElementById('helper-code').textContent = d.code;
      document.getElementById('helper-timer').textContent = '(' + d.secondsRemaining + 's)';
    } catch(e) {}
  }, 1000);
}
```

**Phase 1 JS:**
```js
var pendingToken = null;
var currentUsername = null;

document.getElementById('btn-login').addEventListener('click', async function() {
  var username = document.getElementById('username').value;
  var password = document.getElementById('password').value;
  try {
    var r = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    var d = await r.json();
    if (!r.ok) return showResult('login-result', 'failure', '✗ ' + d.error);
    if (d.mfaRequired) {
      pendingToken = d.pendingToken;
      currentUsername = username;
      document.getElementById('phase1').style.display = 'none';
      document.getElementById('phase2').style.display = '';
      startHelperRefresh(username);
      showResult('totp-result', 'info', 'Password accepted — enter your 6-digit authenticator code');
    } else {
      // bob: no MFA — go straight to dashboard
      localStorage.setItem('svToken', d.token);
      loadDashboard();
    }
  } catch(e) {
    showResult('login-result', 'failure', '✗ Network error — is the server running?');
  }
});
```

**Phase 2 JS:**
```js
document.getElementById('btn-verify').addEventListener('click', async function() {
  var code = document.getElementById('totp-code').value.replace(/\s/g, '');
  try {
    var r = await fetch('/api/verify-totp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pendingToken, code }),
    });
    var d = await r.json();
    if (!r.ok) return showResult('totp-result', 'failure', '✗ ' + d.error);
    clearInterval(helperInterval);
    localStorage.setItem('svToken', d.token);
    loadDashboard();
  } catch(e) {
    showResult('totp-result', 'failure', '✗ ' + e.message);
  }
});
```

**Dashboard panel** (hidden until fully authenticated): shows the vault item list. Red banner:

```
⚠️ WEAK MFA: TOTP window is ±5 minutes (10 steps). Same code accepted multiple times.
No rate limit on /api/verify-totp — brute force possible.
Try: submit the same code twice in a row. It works. Open DevTools → Network to see no rate-limit headers.
```

**Logout button** in header: calls `POST /api/logout`, clears localStorage, reloads page.

**Login input CSS** — both inputs use `class="login-input"`:
```css
.login-input {
  width: 100%; padding: 0.6rem 0.75rem; border: 1px solid #cbd5e1;
  border-radius: 6px; font-size: 0.95rem; color: #0f172a;
  background: #fff; outline: none; box-sizing: border-box; font-family: inherit;
}
.login-input:focus { border-color: #7c3aed; box-shadow: 0 0 0 3px rgba(124,58,237,0.15); }
```

**6-digit code input** — format digits as user types:
```js
document.getElementById('totp-code').addEventListener('input', function() {
  this.value = this.value.replace(/\D/g, '').slice(0, 6);
});
```

---

## Port 3071 — Concept Guide

### File: `mfa-totp/guide-server.js`

Open `demo-attacked/reverse-tabnabbing/attacker-server.js`. Find the `DASHBOARD_HTML` constant. Copy its entire `<style>` block **verbatim**. Paste it into this guide's HTML template.

### Page structure

**Title:** `🔐 MFA & TOTP — How It Works`

**Section 1 — Two Factors** (`.flow-box`)

Heading: `What Makes MFA Different`

```
Factor 1 — Something you KNOW:   password, PIN
Factor 2 — Something you HAVE:   authenticator app, hardware key, SMS
Factor 3 — Something you ARE:    fingerprint, face ID

TOTP uses factor 1 + factor 2.
An attacker who steals your password still cannot log in
without physical access to your device.
```

Show in `<pre>` with `color:#00ff41`.

**Section 2 — TOTP Math** (`.flow-box`)

Heading: `How TOTP Codes Are Generated (RFC 6238)`

ASCII flow:
```
Shared Secret (base32)
  + Current Time (Unix timestamp ÷ 30 = time step T)
        │
        ▼
   HMAC-SHA1(secret, T)                  ← 20-byte hash
        │
        ▼
   Dynamic Truncation                    ← extract 4 bytes from offset
        │
        ▼
   Truncated Value mod 1,000,000         ← 6-digit code, zero-padded
        │
        ▼
   "482 915"
```

```
Time step:   T = Math.floor(Date.now() / 1000 / 30)
             T changes every 30 seconds — so the code changes every 30 seconds.

Both the app and the server compute independently.
If their codes match → authentication succeeds.
No code is ever sent over the network during normal use.
```

Show in `<pre>`.

Live demo widget — "Compute a TOTP code step by step":

```html
<div class="flow-box" style="margin-top:1rem">
  <strong>Secret (base32):</strong>
  <input class="field" id="demo-secret" value="JBSWY3DPEHPK3PXP" style="width:200px;margin:0 0.5rem">
  <button class="demo-btn" id="btn-compute">Compute current code</button>
  <pre class="decoded-box" id="compute-output" style="min-height:80px;margin-top:0.5rem">Click to compute</pre>
</div>
```

```js
document.getElementById('btn-compute').addEventListener('click', async function() {
  var secret = document.getElementById('demo-secret').value.trim().toUpperCase();
  // Ask the server to compute it (server has speakeasy; browser doesn't)
  try {
    var r = await fetch('http://localhost:3070/api/current-totp?username=alice');
    var d = await r.json();
    var T = Math.floor(Date.now() / 1000 / 30);
    document.getElementById('compute-output').textContent =
      'Time step T = Math.floor(' + Math.floor(Date.now()/1000) + ' / 30) = ' + T + '\n\n' +
      'HMAC-SHA1(secret, T) → truncated → mod 1,000,000\n\n' +
      'Current code for alice: ' + d.code + '\n' +
      'Valid for: ' + d.secondsRemaining + ' more seconds\n\n' +
      '(alice\'s secret: JBSWY3DPEHPK3PXP — scan the QR below to follow along in your authenticator)';
  } catch(e) {
    document.getElementById('compute-output').textContent = 'Could not reach :3070 — ' + e.message;
  }
});
document.getElementById('btn-compute').click();
```

**Section 3 — QR Code Setup** (`.flow-box`)

Heading: `📱 Scan to Follow Along`

```html
<p>Scan with Google Authenticator, Authy, or 1Password to get real rotating codes:</p>
<div id="qr-container" style="margin:1rem 0">Loading QR code...</div>
<pre class="decoded-box" id="otpauth-display"></pre>
```

```js
(async function() {
  try {
    var r = await fetch('http://localhost:3070/api/totp-qr?username=alice');
    var d = await r.json();
    document.getElementById('qr-container').innerHTML =
      '<img src="' + d.qrDataUrl + '" style="width:180px;height:180px;border:2px solid #1a3a1a;border-radius:4px">';
    document.getElementById('otpauth-display').textContent =
      'otpauth URL: ' + d.otpauthUrl + '\n\nManual entry secret: ' + d.secret;
  } catch(e) {
    document.getElementById('qr-container').textContent = 'Could not load QR — is :3070 running?';
  }
})();
```

**Section 4 — Attack: Replay Attack** (`.flow-box`)

Heading: `⚠️ Attack: Replay Attack (Port 3070)`

```
The problem: a TOTP code is valid for 30 seconds.
Without replay tracking, the same code can be submitted twice in that window.

Scenario:
  1. Attacker intercepts alice's valid TOTP code (e.g. via phishing or MITM)
  2. Alice uses it to log in — succeeds
  3. Attacker submits the same code within the same 30-second window — ALSO succeeds

The fix: record each used (username, timeStep, code) tuple. Reject duplicates.
```

Live replay demo:

```html
<div style="display:flex;gap:0.5rem;flex-wrap:wrap;align-items:center;margin-bottom:0.75rem">
  <input class="field" id="replay-user" value="alice" style="width:80px">
  <input class="field" id="replay-pass" value="pass1234" style="width:100px">
  <button class="demo-btn" id="btn-replay">Login + replay same code</button>
</div>
<div class="result-banner" id="replay-result"></div>
<pre class="decoded-box" id="replay-output" style="min-height:100px">–</pre>
```

```js
document.getElementById('btn-replay').addEventListener('click', async function() {
  var username = document.getElementById('replay-user').value;
  var password = document.getElementById('replay-pass').value;
  var out = document.getElementById('replay-output');
  try {
    // Step 1: Login with password
    var r1 = await fetch('http://localhost:3070/api/login', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ username, password }),
    });
    var d1 = await r1.json();
    if (!d1.mfaRequired) { out.textContent = 'User has no MFA — try alice'; return; }

    // Step 2: Get the current code
    var r2 = await fetch('http://localhost:3070/api/current-totp?username=' + username);
    var d2 = await r2.json();
    var code = d2.code;
    out.textContent = 'Step 1: logged in, got pendingToken\nStep 2: current TOTP code = ' + code + '\n';

    // Step 3: Submit code — first time
    var r3 = await fetch('http://localhost:3070/api/verify-totp', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ pendingToken: d1.pendingToken, code }),
    });
    var d3 = await r3.json();
    out.textContent += 'Step 3: first submit → ' + (r3.ok ? '✓ SUCCESS (token: ' + d3.token.slice(0,12) + '...)' : '✗ ' + d3.error) + '\n';

    // Step 4: Login again and replay the same code
    var r4 = await fetch('http://localhost:3070/api/login', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ username, password }),
    });
    var d4 = await r4.json();
    var r5 = await fetch('http://localhost:3070/api/verify-totp', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ pendingToken: d4.pendingToken, code }),
    });
    var d5 = await r5.json();
    out.textContent += 'Step 4: replay same code → ' + (r5.ok ? '✓ SUCCEEDED — replay attack works!' : '✗ Blocked');

    showResult('replay-result', r5.ok ? 'failure' : 'success',
      r5.ok ? '⚠ Replay accepted on :3070 — same code used twice' : '✓ Replay blocked');
  } catch(e) {
    showResult('replay-result', 'failure', '✗ ' + e.message + ' — is :3070 running?');
  }
});
```

**Section 5 — Attack: Wide Window** (`.flow-box`)

Heading: `⚠️ Attack: Wide Acceptance Window (Port 3070)`

```
Port 3070 uses window:10 in speakeasy.totp.verify.

window:N means the server accepts codes from N steps before and N steps after the current step.
window:10 → ±10 × 30 seconds = ±5 minutes
             = 21 valid codes are active simultaneously

Why this is dangerous:
  - A captured code stays valid for 5 minutes after capture
  - Phishing attacks have more time to replay stolen codes
  - Combined with no replay prevention: any captured code in the last 5 minutes works

The fix: window:1 (±30 seconds) — enough for clock skew between phone and server.
```

**Section 6 — The Fix: What Hardened TOTP Does** (`.flow-box`)

Heading: `✅ What Port 3072 Does Differently`

Comparison table:

```html
<table style="width:100%;border-collapse:collapse;font-size:0.82rem;margin-top:0.5rem">
  <tr style="color:#64748b;border-bottom:1px solid #1a3a1a">
    <th style="text-align:left;padding:0.5rem">Property</th>
    <th>Port 3070 (Weak)</th>
    <th>Port 3072 (Hardened)</th>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">Acceptance window</td>
    <td style="text-align:center;color:#fca5a5">±5 min (window:10)</td>
    <td style="text-align:center;color:#4ade80">±30 s (window:1)</td>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">Replay prevention</td>
    <td style="text-align:center;color:#fca5a5">None</td>
    <td style="text-align:center;color:#4ade80">Used-code Set per time step</td>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">Rate limiting</td>
    <td style="text-align:center;color:#fca5a5">None</td>
    <td style="text-align:center;color:#4ade80">5 attempts → 5-min lockout</td>
  </tr>
  <tr style="border-bottom:1px solid #0d1f0d">
    <td style="padding:0.5rem;color:#94a3b8">TOTP secret exposure</td>
    <td style="text-align:center;color:#fca5a5">/api/debug/totp-secret</td>
    <td style="text-align:center;color:#4ade80">Never in responses</td>
  </tr>
  <tr>
    <td style="padding:0.5rem;color:#94a3b8">Account recovery</td>
    <td style="text-align:center;color:#fca5a5">None</td>
    <td style="text-align:center;color:#4ade80">Single-use backup codes</td>
  </tr>
</table>
```

**Navigation:** Fixed bottom-left `target-switcher`:
- `Weak TOTP (3070)` → `window.open('http://localhost:3070')`
- `Hardened TOTP (3072)` → `window.open('http://localhost:3072')`

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

---

## Port 3072 — Hardened TOTP SecureVault

### File: `mfa-totp/secure-server.js`

**Dependencies:** `express ^4.18.2`, `cors ^2.8.5`, `speakeasy ^2.0.0`, `qrcode ^1.5.3`

### Rate limiting and replay state

```js
// ✅ PROTECTED: Track failed TOTP attempts per username to enforce lockout
// Map<username, { count: number, lockedUntil: number }>
const failedAttempts = new Map();

// ✅ PROTECTED: Track used codes per (username, timeStep) to prevent replay
// Map<"username:timeStep", Set<code>>
// Cleared every 2 minutes — codes older than that are expired anyway
const usedCodes = new Map();
setInterval(() => {
  const cutoff = Math.floor(Date.now() / 30000) - 4; // keep last 2 minutes of steps
  for (const key of usedCodes.keys()) {
    const step = parseInt(key.split(':')[1], 10);
    if (step < cutoff) usedCodes.delete(key);
  }
}, 2 * 60 * 1000);
```

### Phase 1 login (password) — same as vulnerable server

```js
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = USERS.find(u => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  if (!user.mfaEnabled) {
    const token = crypto.randomBytes(32).toString('hex');
    completedSessions.set(token, { username: user.username, fullName: user.fullName, role: user.role });
    return res.json({ token, mfaRequired: false });
  }

  const pendingToken = crypto.randomBytes(16).toString('hex');
  pendingSessions.set(pendingToken, {
    username: user.username,
    expiresAt: Date.now() + 5 * 60 * 1000,
  });
  res.json({ mfaRequired: true, pendingToken });
});
```

### Phase 2 TOTP verification — HARDENED

```js
app.post('/api/verify-totp', (req, res) => {
  const { pendingToken, code } = req.body;
  const pending = pendingSessions.get(pendingToken);
  if (!pending) return res.status(401).json({ error: 'No pending session — log in again' });

  // ✅ PROTECTED: Pending session expiry check
  if (Date.now() > pending.expiresAt) {
    pendingSessions.delete(pendingToken);
    return res.status(401).json({ error: 'Session expired — log in again' });
  }

  const { username } = pending;
  const user = USERS.find(u => u.username === username);

  // ✅ PROTECTED: Account lockout after 5 failed attempts
  const attempts = failedAttempts.get(username) || { count: 0, lockedUntil: 0 };
  if (Date.now() < attempts.lockedUntil) {
    const remaining = Math.ceil((attempts.lockedUntil - Date.now()) / 1000);
    return res.status(429).json({ error: `Too many attempts. Try again in ${remaining}s` });
  }

  // ✅ PROTECTED: Strict window — ±1 step (±30 seconds) for clock skew only
  const valid = speakeasy.totp.verify({
    secret: user.totpSecret,
    encoding: 'base32',
    token: code,
    window: 1, // ✅ industry standard: ±30 seconds
  });

  if (!valid) {
    // ✅ PROTECTED: Increment failure counter; lock out after 5
    attempts.count++;
    if (attempts.count >= 5) {
      attempts.lockedUntil = Date.now() + 5 * 60 * 1000; // 5-minute lockout
      attempts.count = 0;
      failedAttempts.set(username, attempts);
      return res.status(429).json({ error: 'Too many failed attempts. Account locked for 5 minutes.' });
    }
    failedAttempts.set(username, attempts);
    return res.status(401).json({
      error: 'Invalid TOTP code',
      attemptsRemaining: 5 - attempts.count,
    });
  }

  // ✅ PROTECTED: Replay prevention — reject if this code was already used in this time step
  const timeStep = Math.floor(Date.now() / 30000);
  const codeKey = `${username}:${timeStep}`;
  if (!usedCodes.has(codeKey)) usedCodes.set(codeKey, new Set());
  if (usedCodes.get(codeKey).has(code)) {
    return res.status(401).json({ error: 'Code already used — wait for the next code' });
  }
  usedCodes.get(codeKey).add(code);

  // All checks passed — issue full session
  failedAttempts.delete(username);
  pendingSessions.delete(pendingToken);
  const sessionToken = crypto.randomBytes(32).toString('hex');
  completedSessions.set(sessionToken, {
    username: user.username,
    fullName: user.fullName,
    role: user.role,
  });
  res.json({ token: sessionToken });
});
```

### Backup codes

```js
// ✅ PROTECTED: Single-use backup codes for account recovery.
// ⚠️ DEMO ONLY: stored as plaintext. Production: bcrypt-hash each code at setup time;
// compare with bcrypt.compare() on use; never store or return the plaintext after setup.
const BACKUP_CODES = {
  alice: ['VAULT-A1B2', 'VAULT-C3D4', 'VAULT-E5F6', 'VAULT-G7H8',
          'VAULT-I9J0', 'VAULT-K1L2', 'VAULT-M3N4', 'VAULT-O5P6'],
  admin: ['VAULT-Q7R8', 'VAULT-S9T0', 'VAULT-U1V2', 'VAULT-W3X4',
          'VAULT-Y5Z6', 'VAULT-AA11', 'VAULT-BB22', 'VAULT-CC33'],
};
// Set<"username:code"> — survives server restart only in demo; production: persist to DB
const usedBackupCodes = new Set();

app.post('/api/backup-code', (req, res) => {
  const { pendingToken, backupCode } = req.body;
  const pending = pendingSessions.get(pendingToken);
  if (!pending) return res.status(401).json({ error: 'No pending session — log in again' });

  const { username } = pending;
  const codes = BACKUP_CODES[username] || [];
  const normalised = (backupCode || '').trim().toUpperCase();
  const key = `${username}:${normalised}`;

  if (!codes.includes(normalised)) {
    return res.status(401).json({ error: 'Invalid backup code' });
  }
  // ✅ PROTECTED: Each backup code is single-use
  if (usedBackupCodes.has(key)) {
    return res.status(401).json({ error: 'Backup code already used' });
  }
  usedBackupCodes.add(key);

  pendingSessions.delete(pendingToken);
  const sessionToken = crypto.randomBytes(32).toString('hex');
  completedSessions.set(sessionToken, {
    username,
    fullName: USERS.find(u => u.username === username).fullName,
    role: USERS.find(u => u.username === username).role,
  });

  const remaining = codes.filter(c => !usedBackupCodes.has(`${username}:${c}`)).length;
  res.json({
    token: sessionToken,
    warning: `Backup code used. ${remaining} backup codes remaining. Re-enroll your authenticator app as soon as possible.`,
  });
});
```

### Protected routes

```js
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ username: req.user.username, fullName: req.user.fullName, role: req.user.role });
});

app.get('/api/vault', requireAuth, (req, res) => {
  res.json([
    { id: 1, site: 'github.com',     username: 'alice@dev.io', passwordPreview: '••••••••' },
    { id: 2, site: 'aws.amazon.com', username: 'alice',         passwordPreview: '••••••••' },
    { id: 3, site: 'stripe.com',     username: 'alice@dev.io', passwordPreview: '••••••••' },
  ]);
});

app.post('/api/logout', requireAuth, (req, res) => {
  completedSessions.delete(req.token);
  res.json({ message: 'Logged out' });
});
```

### UI — same two-phase flow as port 3070 with additions

Same static HTML + client JS pattern as port 3070. Key differences:

1. **Backup code link:** Below the "Verify" button, add `<a href="#" id="btn-show-backup">Lost your device? Use a backup code</a>`. On click, show a second input asking for `VAULT-XXXX` format backup code. Submit calls `POST /api/backup-code`.

2. **Backup codes panel on dashboard** (alice, after login): Show remaining backup codes list. In the panel heading, note: "Store these somewhere safe. Each code works once only." Show alice's unused backup codes from the `BACKUP_CODES` constant (demo convenience).

3. **Green banner on dashboard:**
   ```
   ✅ HARDENED MFA: window:1 (±30 s only). Replay prevention active. 5-attempt lockout.
   Try submitting the same code twice — the second attempt is rejected.
   ```

4. **Show lockout feedback:** If `/api/verify-totp` returns 429, show: `🔒 Account locked — try again in Xs`. Display a countdown that decrements every second.

5. **Lockout countdown JS:**
   ```js
   var lockoutInterval;
   function startLockoutCountdown(seconds) {
     var remaining = seconds;
     showResult('totp-result', 'failure', '🔒 Too many attempts. Locked for ' + remaining + 's');
     clearInterval(lockoutInterval);
     lockoutInterval = setInterval(function() {
       remaining--;
       if (remaining <= 0) {
         clearInterval(lockoutInterval);
         showResult('totp-result', 'info', 'Lockout expired — try again');
       } else {
         showResult('totp-result', 'failure', '🔒 Too many attempts. Locked for ' + remaining + 's');
       }
     }, 1000);
   }
   ```

   In the verify click handler, when response is 429:
   ```js
   // Extract seconds from error message or default to 300
   var match = d.error.match(/(\d+)s/);
   var secs = match ? parseInt(match[1]) : 300;
   startLockoutCountdown(secs);
   ```

**Login input CSS** — same as port 3070 with purple accent (`#7c3aed`).

---

## Shared `package.json` at `mfa-totp/`

```json
{
  "name": "mfa-totp-demo",
  "version": "1.0.0",
  "scripts": {
    "vulnerable": "node vulnerable-server.js",
    "guide":      "node guide-server.js",
    "secure":     "node secure-server.js"
  },
  "dependencies": {
    "express":   "^4.18.2",
    "cors":      "^2.8.5",
    "speakeasy": "^2.0.0",
    "qrcode":    "^1.5.3"
  }
}
```

---

## README at `mfa-totp/README.md`

### How It Works

```
Two-phase MFA login:

  Phase 1 (password):
    POST /api/login { username, password }
    → { mfaRequired: true, pendingToken }      ← short-lived, no data access

  Phase 2 (TOTP):
    POST /api/verify-totp { pendingToken, code }
    → { token }                                ← full session token

  Protected route:
    GET /api/vault
    Authorization: Bearer <token>
    → vault items

  Vulnerable (3070): window:10, no replay tracking, no rate limit
  Hardened  (3072): window:1,  replay Set,          5-attempt lockout, backup codes
```

### TOTP Secret

Alice's pre-seeded secret: `JBSWY3DPEHPK3PXP` (base32)

Scan to use a real authenticator:
```
otpauth://totp/SecureVault:alice?secret=JBSWY3DPEHPK3PXP&issuer=SecureVault
```

Or use the demo helper on each page — it shows the current valid code without an authenticator app.

### Run the demo

```bash
cd auth-concepts/mfa-totp
npm install
npm run vulnerable  # terminal 1 → localhost:3070
npm run guide       # terminal 2 → localhost:3071
npm run secure      # terminal 3 → localhost:3072
```

### Walkthrough

1. Open **localhost:3071** — guide page. Read the TOTP Math section and compute a live code.
2. Open **localhost:3070** — log in as alice / pass1234 → enter the code shown in the demo helper.
3. On the dashboard, click "Verify again with same code" — it succeeds (replay attack!).
4. Open **localhost:3072** — log in the same way. Try submitting the same code twice — second attempt is rejected: "Code already used."
5. Try wrong codes 5 times on :3072 → account locks out for 5 minutes.
6. Use a backup code from the panel to recover access.
7. Log in as bob / qwerty123 on either server — bob has no MFA, goes straight to dashboard.

### Key Concepts

**TOTP is computed, not transmitted:** Both the client app and the server independently compute the same code from the shared secret and the current time step. During normal login, the raw secret never crosses the network.

**The window parameter is clock skew tolerance:** Phones and servers don't share a millisecond-perfect clock. `window:1` allows the adjacent time steps (±30 s) as valid. `window:10` allows ±5 minutes — far more than clock skew requires, and it gives attackers more time to replay captured codes.

**Replay attacks are subtle:** Without used-code tracking, submitting a valid code twice in the same 30-second window works. The server has no way to distinguish the first use from the second. The fix is a Set keyed on `(username, timeStep, code)`.

**Backup codes need to be hashed:** In this demo, backup codes are stored as plaintext for readability. Production: generate codes with `crypto.randomBytes`, hash each with `bcrypt.hash()`, store the hashes. On use, `bcrypt.compare(submitted, hash)` — then mark as used. The plaintext code is never stored.

---

## Key technical notes for Cursor

1. **`speakeasy.totp.verify` returns a boolean, not an object.** Call it as: `const valid = speakeasy.totp.verify({ secret, encoding: 'base32', token: code, window: N });`. The `token` field is a string (the 6-digit code), not a number — always pass a string.

2. **`qrcode` npm vs browser QR libraries.** The server uses the `qrcode` npm package in Node.js: `const QRCode = require('qrcode'); const dataUrl = await QRCode.toDataURL(otpauthUrl);`. This returns a PNG data URL that can go directly into an `<img src="">`.

3. **The two-phase session design prevents password-only access.** After `POST /api/login` the server returns a `pendingToken`, not a real session token. `pendingToken` grants access only to `POST /api/verify-totp`. Only after TOTP verification is a `sessionToken` issued that works with `requireAuth`. Never skip this — issuing a full token after password alone defeats MFA entirely.

4. **Demo helper (`GET /api/current-totp`) returns the live code.** This is intentional for demo UX — users without an authenticator app can still follow the flow. Add a clear `⚠️ DEMO ONLY` comment in the code and a visible warning label on the UI. Never add this endpoint to any production guide.

5. **`usedCodes` cleanup:** The `setInterval` that clears old time-step entries runs every 2 minutes. Without it, the Map grows forever. In production, store used codes in Redis with a TTL equal to the window size (90 seconds for `window:1`).

6. **Bob has `mfaEnabled: false`.** This is intentional — it demonstrates that MFA is per-user and that accounts without MFA complete login after password alone. The dashboard for bob shows an "Enable MFA" prompt in amber.

7. **6-digit code input formatting.** The TOTP input field should accept digits only and auto-format as 3+3 (e.g., "482 915") for readability. Strip spaces before sending to the server: `code.replace(/\s/g, '')`.

8. **Pending session expiry.** The pending session expires after 5 minutes (set at Phase 1). Check `pending.expiresAt` at the start of `POST /api/verify-totp` on the hardened server. On expiry, delete the pending entry and return 401 — force the user to log in again.
