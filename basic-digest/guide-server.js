/*
 * Terminal 2: cd auth-concepts/basic-digest && npm run guide
 * Basic & Digest Auth Lab — concept guide (port 3050)
 */

const express = require('express');

const app = express();
const PORT = 3050;

// Verbatim <style> from DASHBOARD_HTML in demo-attacked/reverse-tabnabbing/attacker-server.js
const GUIDE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Basic &amp; Digest Auth Lab</title>
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
    .flow-box p { max-width: 640px; }
    .section-title {
      font-size: 0.95rem;
      color: #94a3b8;
      margin-bottom: 1rem;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
  </style>
</head>
<body>
  <h1>🔐 Basic &amp; Digest Auth — How It Works</h1>
  <p class="subtitle">HTTP Basic sends credentials on every request. Digest uses MD5 hashes. Both are superseded by session tokens.</p>

  <div class="flow-box">
    <div class="section-title">How HTTP Basic Auth Works</div>
    <pre style="color:#00ff41;font-size:0.78rem;line-height:1.6;margin-top:0.5rem">Browser                          Server (3049)
   │                                  │
   ├─── GET / ──────────────────────→ │
   │                                  │
   │ ←── 401 WWW-Authenticate: Basic ─┤
   │                                  │
   │  [Browser shows login dialog]    │
   │                                  │
   ├─── GET / ──────────────────────→ │
   │  Authorization: Basic           │
   │  YWxpY2U6cGFzczEyMzQ=          │ ← base64("alice:pass1234")
   │                                  │
   │ ←── 200 OK ─────────────────────┤
   │                                  │
   │ (EVERY subsequent request also   │
   │  sends the Authorization header) │</pre>
    <p style="margin-top:1rem;color:#94a3b8;font-size:0.85rem;max-width:640px">
      // ⚠️ VULNERABILITY: Base64 is encoding, not encryption. atob("YWxpY2U6cGFzczEyMzQ=") instantly reveals alice:pass1234.
    </p>
  </div>

  <div class="flow-box">
    <div class="section-title">🔓 Decode any Basic Auth header</div>
    <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;margin-bottom:0.75rem">
      <input class="field" id="b64-input" style="flex:1"
        placeholder="Paste Authorization header value or base64 string"
        value="YWxpY2U6cGFzczEyMzQ=">
      <button class="demo-btn" id="btn-decode">Decode</button>
    </div>
    <pre class="decoded-box" id="decode-output" style="min-height:50px">Click Decode</pre>
    <div style="margin-top:1rem">
      <strong>Encode your own:</strong>
      <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;margin-top:0.5rem">
        <input class="field" id="enc-user" placeholder="username" value="alice" style="width:120px">
        <span style="color:#64748b">:</span>
        <input class="field" id="enc-pass" placeholder="password" value="pass1234" style="width:140px">
        <button class="demo-btn" id="btn-encode">Encode →</button>
        <span id="enc-result" style="color:#fbbf24;font-family:monospace;font-size:0.85rem"></span>
      </div>
      <p id="enc-error" style="color:#fca5a5;font-size:0.82rem;margin-top:0.5rem;display:none"></p>
    </div>
  </div>

  <div class="flow-box">
    <div class="section-title">📡 Intercept Credentials from Port 3049</div>
    <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;margin-bottom:0.75rem">
      <input class="field" id="int-user" value="alice" style="width:100px">
      <span style="color:#64748b">:</span>
      <input class="field" id="int-pass" value="pass1234" style="width:120px">
      <button class="demo-btn" id="btn-intercept">Send request → :3049 + show header</button>
    </div>
    <div class="result-banner" id="intercept-result"></div>
    <pre class="decoded-box" id="intercept-output" style="min-height:80px">–</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">Digest Auth — MD5 Challenge-Response</div>
    <pre style="color:#00ff41;font-size:0.78rem;line-height:1.6;margin-top:0.5rem">Browser                          Server
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
   │ ←── 200 OK ─────────────────────┤</pre>
    <pre style="color:#cbd5e1;font-size:0.78rem;line-height:1.6;margin-top:1rem">Basic Auth:        Authorization: Basic YWxpY2U6cGFzczEyMzQ=
                   → Anyone can decode: alice:pass1234

Digest Auth:       Authorization: Digest response="d7a8f3c9..."
                   → Server verifies the hash, password never sent
                   → BUT: uses MD5 — offline-crackable if nonce is captured
                   → Still no forward secrecy, deprecated in most contexts</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">Why Sessions/Tokens Are Better</div>
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
    <p style="margin-top:1rem;color:#94a3b8;font-size:0.85rem;max-width:640px">
      // ✅ PROTECTED: Session tokens on port 3051 send credentials once at login, then an opaque Bearer token that can be revoked.
    </p>
  </div>

  <div class="target-switcher">
    <button type="button" class="btn-vulnerable" id="btn-basic">Basic Auth (3049)</button>
    <button type="button" class="btn-protected" id="btn-session">Session Auth (3051)</button>
  </div>

  <script>
    function showResult(id, type, msg) {
      var el = document.getElementById(id);
      el.className = 'result-banner ' + type;
      el.textContent = msg;
      el.style.display = 'block';
    }

    document.getElementById('btn-decode').addEventListener('click', function () {
      var input = document.getElementById('b64-input').value.trim();
      if (input.startsWith('Basic ')) input = input.slice(6);
      try {
        var decoded = atob(input);
        var colonIdx = decoded.indexOf(':');
        var username = decoded.substring(0, colonIdx);
        var password = decoded.substring(colonIdx + 1);
        document.getElementById('decode-output').textContent =
          'Decoded: "' + decoded + '"\\n\\nUsername: ' + username + '\\nPassword: ' + password +
          '\\n\\n→ atob("' + input + '") → "' + decoded + '"' +
          '\\n→ Zero tools required. Any browser console can do this.';
      } catch (e) {
        document.getElementById('decode-output').textContent = 'Invalid base64: ' + e.message;
      }
    });

    document.getElementById('btn-encode').addEventListener('click', function () {
      var u = document.getElementById('enc-user').value;
      var p = document.getElementById('enc-pass').value;
      var errEl = document.getElementById('enc-error');
      errEl.style.display = 'none';
      try {
        var encoded = btoa(u + ':' + p);
        document.getElementById('enc-result').textContent = 'Basic ' + encoded;
      } catch (e) {
        document.getElementById('enc-result').textContent = '';
        errEl.textContent = 'btoa() only supports Latin-1 characters: ' + e.message;
        errEl.style.display = 'block';
      }
    });
    document.getElementById('btn-encode').click();

    document.getElementById('btn-intercept').addEventListener('click', async function () {
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
          'Request sent with:\\n  Authorization: ' + header +
          '\\n\\nBase64 decoded:\\n  "' + atob(encoded) + '"' +
          '\\n\\nServer responded:\\n' + JSON.stringify(data, null, 2) +
          '\\n\\n⚠ This Authorization header is sent with EVERY request to :3049.\\n' +
          'Every API call, every page load. Always visible in network logs.';

        showResult('intercept-result', 'success', '✓ Request succeeded — credentials in header as shown below');
      } catch (e) {
        showResult('intercept-result', 'failure', '✗ ' + e.message + ' — is port 3049 running?');
      }
    });

    document.getElementById('btn-basic').addEventListener('click', function () {
      window.open('http://localhost:3049');
    });
    document.getElementById('btn-session').addEventListener('click', function () {
      window.open('http://localhost:3051');
    });
  </script>
</body>
</html>`;

app.get('/', function (req, res) {
  res.send(GUIDE_HTML);
});

app.listen(PORT, function () {
  console.log('Basic & Digest Auth Lab running at http://localhost:' + PORT);
});
