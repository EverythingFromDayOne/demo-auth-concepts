/*
 * Terminal 2: cd auth-concepts/jwt-bearer && npm run guide
 * JWT & Bearer Lab — concept guide (port 3059)
 */

const express = require('express');

const app = express();
const PORT = 3059;

const GUIDE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>JWT &amp; Bearer Lab</title>
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
      background: #dc2626;
      color: #fff;
      border-color: #dc2626;
    }
    .target-switcher .btn-protected.active {
      background: #ef4444;
      color: #fff;
      border-color: #ef4444;
    }
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
    .section-title {
      font-size: 0.95rem;
      color: #94a3b8;
      margin-bottom: 1rem;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .flow-box p { max-width: 640px; }
    .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 0.75rem; }
    @media (max-width: 768px) { .grid-3 { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <h1>🪙 JWT &amp; Bearer Token Authentication — How It Works</h1>
  <p class="subtitle">Stateless tokens carry signed claims — no session database lookup required.</p>

  <div class="flow-box">
    <div class="section-title">JSON Web Token — Three Parts</div>

    <!-- Token with colored parts — wraps naturally -->
    <div style="font-family:'Courier New',monospace;font-size:0.72rem;word-break:break-all;line-height:1.6;margin-bottom:0.75rem">
      <span style="color:#f87171">eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9</span><span style="color:#475569">.</span><span style="color:#a78bfa">eyJzdWIiOjEsInVzZXJuYW1lIjoiYWxpY2UiLCJyb2xlIjoidXNlciIsImlhdCI6MTcxODUxMjAwMH0</span><span style="color:#475569">.</span><span style="color:#60a5fa">xK9zPqr4mN2vL8tY3wB6Qf1hUjSdEcMaIoRkPlWn</span>
    </div>

    <!-- Three-column labels -->
    <div style="display:grid;grid-template-columns:1fr 1.6fr 1.2fr;gap:0.5rem;border-top:1px solid #1a3a1a;padding-top:0.75rem;font-family:'Courier New',monospace;font-size:0.75rem">
      <div>
        <div style="color:#f87171;margin-bottom:0.3rem">HEADER</div>
        <div style="color:#4a5568">base64url({</div>
        <div style="color:#4a5568">&nbsp;&nbsp;alg, typ</div>
        <div style="color:#4a5568">})</div>
      </div>
      <div>
        <div style="color:#a78bfa;margin-bottom:0.3rem">PAYLOAD</div>
        <div style="color:#4a5568">base64url({</div>
        <div style="color:#4a5568">&nbsp;&nbsp;sub, username,</div>
        <div style="color:#4a5568">&nbsp;&nbsp;role, iat, exp</div>
        <div style="color:#4a5568">})</div>
      </div>
      <div>
        <div style="color:#60a5fa;margin-bottom:0.3rem">SIGNATURE</div>
        <div style="color:#4a5568">HMAC-SHA256(</div>
        <div style="color:#4a5568">&nbsp;&nbsp;header + "." +</div>
        <div style="color:#4a5568">&nbsp;&nbsp;payload, secret</div>
        <div style="color:#4a5568">)</div>
      </div>
    </div>

    <!-- Decoded values -->
    <pre style="font-size:0.75rem;line-height:1.7;color:#cbd5e1;border-top:1px solid #1a3a1a;margin-top:0.75rem;padding-top:0.75rem;white-space:pre-wrap">Decoded HEADER:   { "alg": "HS256", "typ": "JWT" }
Decoded PAYLOAD:  { "sub": 1, "username": "alice", "role": "user",
                    "iat": 1718512000, "exp": 1718598400 }
SIGNATURE:        Proves header+payload were not tampered with.
                  Server recomputes SHA256(header.payload) with its secret
                  and checks it matches — no DB lookup needed.</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">🔍 Paste any JWT — decode it</div>
    <textarea class="field" id="jwt-input" rows="3" style="width:100%;resize:vertical;font-size:0.75rem"
      placeholder="Paste a JWT here (e.g., from port 3058 login)"></textarea>
    <button class="demo-btn" id="btn-decode-jwt" style="margin-top:0.5rem">Decode JWT</button>
    <div class="grid-3" style="margin-top:0.75rem">
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
  </div>

  <div class="flow-box">
    <div class="section-title">JWT vs Session — Key Differences</div>
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
  </div>

  <div class="flow-box">
    <div class="section-title">Registered JWT Claims (RFC 7519)</div>
    <table style="width:100%;border-collapse:collapse;font-size:0.82rem;margin-top:0.5rem">
      <tr style="color:#64748b;border-bottom:1px solid #1a3a1a">
        <th style="text-align:left;padding:0.5rem">Claim</th>
        <th style="text-align:left;padding:0.5rem">Name</th>
        <th style="text-align:left;padding:0.5rem">Example</th>
      </tr>
      <tr style="border-bottom:1px solid #0d1f0d">
        <td style="padding:0.5rem;color:#4ade80">sub</td>
        <td style="padding:0.5rem;color:#94a3b8">Subject</td>
        <td style="padding:0.5rem;color:#94a3b8">User ID: 1</td>
      </tr>
      <tr style="border-bottom:1px solid #0d1f0d">
        <td style="padding:0.5rem;color:#4ade80">iss</td>
        <td style="padding:0.5rem;color:#94a3b8">Issuer</td>
        <td style="padding:0.5rem;color:#94a3b8">"https://auth.myapp.com"</td>
      </tr>
      <tr style="border-bottom:1px solid #0d1f0d">
        <td style="padding:0.5rem;color:#4ade80">aud</td>
        <td style="padding:0.5rem;color:#94a3b8">Audience</td>
        <td style="padding:0.5rem;color:#94a3b8">"https://api.myapp.com"</td>
      </tr>
      <tr style="border-bottom:1px solid #0d1f0d">
        <td style="padding:0.5rem;color:#4ade80">exp</td>
        <td style="padding:0.5rem;color:#94a3b8">Expiration time</td>
        <td style="padding:0.5rem;color:#94a3b8">Unix timestamp</td>
      </tr>
      <tr style="border-bottom:1px solid #0d1f0d">
        <td style="padding:0.5rem;color:#4ade80">iat</td>
        <td style="padding:0.5rem;color:#94a3b8">Issued at</td>
        <td style="padding:0.5rem;color:#94a3b8">Unix timestamp</td>
      </tr>
      <tr>
        <td style="padding:0.5rem;color:#4ade80">jti</td>
        <td style="padding:0.5rem;color:#94a3b8">JWT ID</td>
        <td style="padding:0.5rem;color:#94a3b8">Unique token identifier</td>
      </tr>
    </table>
  </div>

  <div class="flow-box">
    <div class="section-title">How to Send a Bearer Token</div>
    <pre style="color:#cbd5e1;font-size:0.78rem;line-height:1.6">Correct:
  Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...

Wrong (don't do this):
  Authorization: eyJhbGciOiJIUzI1NiJ9...     ← missing "Bearer " prefix
  Authorization: JWT eyJhbGciOiJIUzI1NiJ9... ← wrong scheme
  ?token=eyJhbGciOiJIUzI1NiJ9...             ← URL param, ends up in logs

The "Bearer" scheme is defined in RFC 6750.
Bearer = "I bear (possess) this token, grant me access."</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">🧪 Test the JWT Against Port 3058</div>
    <p style="font-size:0.82rem;color:#94a3b8;margin-bottom:0.75rem;max-width:640px">
      Tokens from port 3060 use a different secret and will fail here — login at :3058 first.
    </p>
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
  </div>

  <div class="target-switcher">
    <button type="button" class="btn-vulnerable" id="btn-weak">Weak JWT (3058)</button>
    <button type="button" class="btn-protected" id="btn-strong">Strong JWT (3060)</button>
  </div>

  <script>
    function showResult(id, type, msg) {
      var el = document.getElementById(id);
      el.className = 'result-banner ' + type;
      el.textContent = msg;
      el.style.display = 'block';
    }

    function b64urlDecode(str) {
      try { return JSON.parse(atob(str.replace(/-/g, '+').replace(/_/g, '/'))); }
      catch (e) { return { raw: str }; }
    }

    document.getElementById('btn-decode-jwt').addEventListener('click', function () {
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
      document.getElementById('out-sig').textContent = parts[2] + '\\n\\n(Cannot verify without the server secret)';

      var notes = [];
      if (payload.exp) notes.push('Expires: ' + new Date(payload.exp * 1000).toLocaleString());
      if (payload.iat) notes.push('Issued: ' + new Date(payload.iat * 1000).toLocaleString());
      if (payload.role) notes.push('Role claim: ' + payload.role);
      showResult('decode-note', 'info', 'ℹ ' + notes.join(' | '));
    });

    async function callWithToken(endpoint) {
      var token = document.getElementById('live-token').value.trim();
      if (!token) {
        showResult('live-result', 'failure', '✗ Paste a JWT token above first (login at localhost:3058)');
        return;
      }
      try {
        var res = await fetch('http://localhost:3058' + endpoint, {
          headers: { 'Authorization': 'Bearer ' + token }
        });
        var data = await res.json();
        document.getElementById('live-output').textContent = JSON.stringify(data, null, 2);
        if (res.ok) {
          showResult('live-result', 'success', '✓ ' + res.status + ' — server verified the JWT signature, no DB lookup needed');
        } else {
          showResult('live-result', 'failure', '✗ ' + res.status + ' — ' + data.error);
        }
      } catch (e) {
        showResult('live-result', 'failure', '✗ ' + e.message + ' — is port 3058 running?');
        document.getElementById('live-output').textContent = '';
      }
    }

    document.getElementById('btn-test-me').addEventListener('click', function () { callWithToken('/api/me'); });
    document.getElementById('btn-test-tasks').addEventListener('click', function () { callWithToken('/api/tasks'); });
    document.getElementById('btn-test-admin').addEventListener('click', function () { callWithToken('/api/admin/users'); });

    document.getElementById('btn-weak').addEventListener('click', function () { window.open('http://localhost:3058'); });
    document.getElementById('btn-strong').addEventListener('click', function () { window.open('http://localhost:3060'); });
  </script>
</body>
</html>`;

app.get('/', function (req, res) {
  res.send(GUIDE_HTML);
});

app.listen(PORT, function () {
  console.log('JWT & Bearer Lab running at http://localhost:' + PORT);
});
