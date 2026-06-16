/*
 * Terminal 2: cd auth-concepts/access-refresh && npm run guide
 * Token Lifecycle Lab — concept guide (port 3062)
 */

const express = require('express');

const app = express();
const PORT = 3062;

const GUIDE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Token Lifecycle Lab</title>
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
  <h1>🔄 Access Tokens + Refresh Tokens — How They Work</h1>
  <p class="subtitle">Short-lived access tokens for API calls. Long-lived refresh tokens to renew them — with rotation on the secure path.</p>

  <div class="flow-box">
    <div class="section-title">The Problem With Long-Lived Access Tokens</div>
    <pre style="color:#cbd5e1;font-size:0.78rem;line-height:1.6">Option A: Long-lived access token (24h or more)
  ✓ Simpler — one token does everything
  ✗ If stolen: attacker has 24h of unchecked access
  ✗ No way to add claims granularly (e.g. step-up auth)

Option B: Short access token (15 min) + long refresh token (7–30 days)
  ✓ Stolen access token expires in 15 min
  ✓ Refresh token can be stored securely (httpOnly cookie or secure storage)
  ✓ Can revoke all refresh tokens on logout or password change
  ✗ More complex — client must handle 401 → refresh → retry</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">Token Lifecycle</div>
    <pre style="color:#00ff41;font-size:0.72rem;line-height:1.5">1. LOGIN
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
      │   Authorization: Bearer &lt;access&gt;  │
      │                                   │ jwt.verify(access, secret) → ok → serve response
      │←── 200 + data ────────────────────┤

3. ACCESS TOKEN EXPIRED
      ├── GET /api/projects ────────────→ │
      │   Authorization: Bearer &lt;access&gt;  │
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
      │   Authorization: Bearer &lt;new&gt;     │
      │←── 200 + data ────────────────────┤

4. LOGOUT
      ├── POST /api/logout ─────────────→ │
      │   { refreshToken }                │ DB: delete refreshToken row
      │←── 200 ────────────────────────── │
      │
      Future /api/refresh calls → 401 (token not in DB)</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">🔄 Refresh Token Rotation — Why It Matters</div>
    <pre style="color:#cbd5e1;font-size:0.78rem;line-height:1.6;margin-bottom:1rem">WITHOUT rotation (port 3061):
  refreshToken = "abc123" → issues access token → "abc123" still valid forever
  Stolen "abc123" → attacker generates access tokens indefinitely

WITH rotation (port 3063):
  refreshToken = "abc123" → server issues:
    new accessToken
    new refreshToken = "xyz789"
    deletes "abc123" from DB
  Stolen "abc123" → used by attacker → reuse detected → revoke ALL tokens for that user

This is called Refresh Token Rotation with Reuse Detection.</pre>
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
  </div>

  <div class="flow-box">
    <div class="section-title">Token Storage Trade-offs</div>
    <pre style="color:#cbd5e1;font-size:0.78rem;line-height:1.6">ACCESS TOKEN:
  ✅ In-memory variable (JS) — safest: cleared on page close, not accessible to other tabs
  ⚠ localStorage — persistent, but readable by any XSS script
  ⚠ sessionStorage — tab-scoped, cleared on tab close, but still XSS-readable

REFRESH TOKEN:
  ✅ httpOnly cookie — browser sends automatically, JS cannot read, safe from XSS
     (set Secure + SameSite=Strict for CSRF protection)
  ⚠ localStorage — readable by XSS, do not use for high-value refresh tokens
  ✅ Secure native storage (mobile: iOS Keychain / Android Keystore)</pre>
  </div>

  <div class="flow-box">
    <strong>🧪 Live Token Demo — Port 3061 (vulnerable)</strong>
    <p style="font-size:0.82rem;color:#94a3b8;margin:0.75rem 0;max-width:640px">
      After refresh, the OLD refresh token is still accepted — that is the vulnerability.
    </p>
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

  <div class="target-switcher">
    <button type="button" class="btn-vulnerable" id="btn-vuln">Vulnerable Refresh (3061)</button>
    <button type="button" class="btn-protected" id="btn-strong">Hardened Refresh (3063)</button>
  </div>

  <script>
    function showResult(id, type, msg) {
      var el = document.getElementById(id);
      el.className = 'result-banner ' + type;
      el.textContent = msg;
      el.style.display = 'block';
    }

  // ⚠️ DEMO ONLY: refresh token in JS memory so both tokens are visible on screen.
  // Production: access → memory, refresh → httpOnly cookie.
    var liveAccessToken = null;
    var liveRefreshToken = null;
    var savedRefreshToken = null;

    document.getElementById('btn-live-login').addEventListener('click', async function () {
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
        liveAccessToken = data.accessToken;
        liveRefreshToken = data.refreshToken;
        savedRefreshToken = data.refreshToken;
        document.getElementById('access-token-out').textContent = data.accessToken;
        document.getElementById('refresh-token-out').textContent = data.refreshToken +
          '\\n\\n⚠ This refresh token never expires and is never rotated (port 3061 — vulnerable)';
        showResult('live-result', 'success', '✓ Logged in. Access token expires in 15 min. Refresh token: permanent.');
      } catch (e) {
        showResult('live-result', 'failure', '✗ ' + e.message + ' — is port 3061 running?');
      }
    });

    document.getElementById('btn-live-api').addEventListener('click', async function () {
      if (!liveAccessToken) { showResult('live-result', 'failure', '✗ Login first'); return; }
      try {
        var res = await fetch('http://localhost:3061/api/projects', {
          headers: { 'Authorization': 'Bearer ' + liveAccessToken }
        });
        var data = await res.json();
        document.getElementById('api-out').textContent = JSON.stringify(data, null, 2);
        if (res.ok) {
          showResult('live-result', 'success', '✓ 200 — access token valid');
        } else {
          showResult('live-result', 'failure', '✗ ' + res.status + ' — ' + data.error + ' → use refresh token');
        }
      } catch (e) { showResult('live-result', 'failure', '✗ ' + e.message); }
    });

    document.getElementById('btn-live-refresh').addEventListener('click', async function () {
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
          document.getElementById('access-token-out').textContent = data.accessToken;
          document.getElementById('refresh-token-out').textContent = liveRefreshToken +
            '\\n\\n⚠ OLD refresh token still valid — port 3061 does NOT rotate it';
          document.getElementById('api-out').textContent =
            JSON.stringify(data, null, 2) +
            '\\n\\n--- Try reusing the ORIGINAL refresh token ---';
          showResult('live-result', 'info', 'ℹ New access token issued. OLD refresh token still valid (no rotation).');
          if (savedRefreshToken && savedRefreshToken !== liveRefreshToken) {
            var res2 = await fetch('http://localhost:3061/api/refresh', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ refreshToken: savedRefreshToken })
            });
            if (res2.ok) {
              document.getElementById('api-out').textContent +=
                '\\n\\n⚠ PROOF: Original refresh token STILL works after rotation attempt!';
            }
          }
        } else {
          showResult('live-result', 'failure', '✗ ' + data.error);
        }
      } catch (e) { showResult('live-result', 'failure', '✗ ' + e.message); }
    });

    document.getElementById('btn-vuln').addEventListener('click', function () {
      window.open('http://localhost:3061');
    });
    document.getElementById('btn-strong').addEventListener('click', function () {
      window.open('http://localhost:3063');
    });
  </script>
</body>
</html>`;

app.get('/', function (req, res) {
  res.send(GUIDE_HTML);
});

app.listen(PORT, function () {
  console.log('Token Lifecycle Lab running at http://localhost:' + PORT);
});
