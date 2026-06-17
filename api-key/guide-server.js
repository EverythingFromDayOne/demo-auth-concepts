/*
 * Terminal 2: cd auth-concepts/api-key && npm run guide
 * API Key Auth Lab — concept guide (port 3056)
 */

const express = require('express');

const app = express();
const PORT = 3056;

app.use(express.json());

// Verbatim <style> from DASHBOARD_HTML in demo-attacked/reverse-tabnabbing/attacker-server.js
const GUIDE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>API Key Auth Lab</title>
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
  <h1>🔑 API Key Authentication — How It Works</h1>
  <p class="subtitle">API keys authenticate programmatic access. Where you put the key determines who can see it.</p>

  <div class="flow-box">
    <div class="section-title">API Key Auth Flow</div>
    <pre style="color:#00ff41;font-size:0.78rem;line-height:1.6;margin-top:0.5rem">Client (app/script)              DataPipe API (3055)
       │                                │
       ├── GET /api/weather?api_key=sk_ →│
       │                                │ API_KEYS.get(key) → { owner, scopes }
       │←── 200 { temperature: 32, ... }┤
       │                                │
       │   Server access log writes:    │
       │   GET /api/weather?api_key=sk_live_alice_a3f9b2c1...
       │                     ↑
       │               KEY IN LOG — visible to anyone with log access</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">⚠️ API Key in URL — Exposure Vectors</div>
    <div class="credentials-panel">
      <table style="width:100%;border-collapse:collapse;font-size:0.82rem">
        <tr style="color:#64748b;border-bottom:1px solid #1a3a1a">
          <th style="text-align:left;padding:0.5rem">#</th>
          <th style="text-align:left;padding:0.5rem">Where</th>
          <th style="text-align:left;padding:0.5rem">How the key gets there</th>
        </tr>
        <tr style="border-bottom:1px solid #0d1f0d">
          <td style="padding:0.5rem;color:#fbbf24">1</td>
          <td style="padding:0.5rem;color:#94a3b8">Server access logs</td>
          <td style="padding:0.5rem;color:#94a3b8">Every web server logs the full URL with query params</td>
        </tr>
        <tr style="border-bottom:1px solid #0d1f0d">
          <td style="padding:0.5rem;color:#fbbf24">2</td>
          <td style="padding:0.5rem;color:#94a3b8">Browser history</td>
          <td style="padding:0.5rem;color:#94a3b8">URL bar entries include query params — synced across devices</td>
        </tr>
        <tr style="border-bottom:1px solid #0d1f0d">
          <td style="padding:0.5rem;color:#fbbf24">3</td>
          <td style="padding:0.5rem;color:#94a3b8">Referer header</td>
          <td style="padding:0.5rem;color:#94a3b8">Browser sends Referer: https://app.com/page?api_key=sk_... to third-party scripts</td>
        </tr>
        <tr style="border-bottom:1px solid #0d1f0d">
          <td style="padding:0.5rem;color:#fbbf24">4</td>
          <td style="padding:0.5rem;color:#94a3b8">CDN / proxy logs</td>
          <td style="padding:0.5rem;color:#94a3b8">Cloudflare, nginx, Fastly all log full request URLs</td>
        </tr>
        <tr>
          <td style="padding:0.5rem;color:#fbbf24">5</td>
          <td style="padding:0.5rem;color:#94a3b8">Shared URLs</td>
          <td style="padding:0.5rem;color:#94a3b8">Developer copies URL from browser bar — key is visible</td>
        </tr>
      </table>
    </div>
  </div>

  <div class="flow-box">
    <div class="section-title">📡 Watch the Key Appear in Logs</div>
    <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;margin-bottom:0.75rem">
      <input class="field" id="demo-key" value="sk_test_demo_c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0" style="flex:1;font-size:0.75rem">
      <button class="demo-btn" id="btn-make-request">Call /api/weather with URL key</button>
    </div>
    <div class="result-banner" id="leak-result"></div>
    <button class="demo-btn" id="btn-check-logs" style="margin-top:0.75rem">📋 Check Server Logs → :3055/api/logs</button>
    <pre class="decoded-box" id="log-output" style="min-height:80px">Make a request first, then check logs</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">✅ Authorization Header (Port 3057)</div>
    <pre style="color:#cbd5e1;font-size:0.78rem;line-height:1.6;margin-bottom:1rem">VULNERABLE:   GET /api/weather?api_key=sk_live_alice_a3f9b2c1...
              ↑ Appears in logs, history, Referer

SECURE:       GET /api/weather
              Authorization: Bearer sk_live_alice_a3f9b2c1...
              ↑ HTTP headers are NOT logged by most servers by default
              ↑ NOT sent in Referer header
              ↑ NOT stored in browser history
              ↑ Still visible in packet captures (need HTTPS to protect from that)</pre>
    <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;margin-bottom:0.75rem">
      <input class="field" id="header-key" value="sk_test_demo_c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0" style="flex:1;font-size:0.75rem">
      <button class="demo-btn" id="btn-header-request">Call /api/weather with Authorization header</button>
    </div>
    <div class="result-banner" id="header-result"></div>
    <pre class="decoded-box" id="header-output" style="min-height:60px">–</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">API Key Security Checklist</div>
    <div class="credentials-panel">
      <table style="width:100%;border-collapse:collapse;font-size:0.82rem">
        <tr style="border-bottom:1px solid #1a3a1a"><td style="padding:0.4rem 0.6rem;color:#4ade80">✅</td><td style="padding:0.4rem 0.6rem;color:#94a3b8">Send key in Authorization: Bearer header, never in URL</td></tr>
        <tr style="border-bottom:1px solid #1a3a1a"><td style="padding:0.4rem 0.6rem;color:#4ade80">✅</td><td style="padding:0.4rem 0.6rem;color:#94a3b8">Scope keys — separate keys for read vs write, per service</td></tr>
        <tr style="border-bottom:1px solid #1a3a1a"><td style="padding:0.4rem 0.6rem;color:#4ade80">✅</td><td style="padding:0.4rem 0.6rem;color:#94a3b8">Rotate keys periodically and on suspected compromise</td></tr>
        <tr style="border-bottom:1px solid #1a3a1a"><td style="padding:0.4rem 0.6rem;color:#4ade80">✅</td><td style="padding:0.4rem 0.6rem;color:#94a3b8">Hash keys at rest (store SHA-256 of key, not the key itself)</td></tr>
        <tr style="border-bottom:1px solid #1a3a1a"><td style="padding:0.4rem 0.6rem;color:#4ade80">✅</td><td style="padding:0.4rem 0.6rem;color:#94a3b8">Rate limit per key — detect abuse before it becomes a breach</td></tr>
        <tr><td style="padding:0.4rem 0.6rem;color:#fca5a5">❌</td><td style="padding:0.4rem 0.6rem;color:#94a3b8">Never embed API keys in frontend code or public repositories</td></tr>
      </table>
    </div>
  </div>

  <div class="target-switcher">
    <button type="button" class="btn-vulnerable" id="btn-url">URL key (3055)</button>
    <button type="button" class="btn-protected" id="btn-header">Header key (3057)</button>
  </div>

  <script>
    function showResult(id, type, msg) {
      var el = document.getElementById(id);
      el.className = 'result-banner ' + type;
      el.textContent = msg;
      el.style.display = 'block';
    }

    document.getElementById('btn-make-request').addEventListener('click', async function () {
      var key = document.getElementById('demo-key').value.trim();
      var url = 'http://localhost:3055/api/weather?api_key=' + encodeURIComponent(key);
      try {
        var res = await fetch(url);
        var data = await res.json();
        showResult('leak-result', res.ok ? 'success' : 'failure',
          (res.ok ? '✓ Response received. ' : '✗ ') +
          'Full URL sent: ' + url + '\\n(Check logs below — key is in the log)');
      } catch (e) {
        showResult('leak-result', 'failure', '✗ ' + e.message + ' — is port 3055 running?');
      }
    });

    document.getElementById('btn-check-logs').addEventListener('click', async function () {
      try {
        var res = await fetch('http://localhost:3055/api/logs');
        var data = await res.json();
        document.getElementById('log-output').textContent =
          data.note + '\\n\\n' + data.log.map(function (l) {
            return '[' + l.time + '] ' + l.method + ' ' + l.url;
          }).join('\\n');
      } catch (e) {
        document.getElementById('log-output').textContent = '✗ ' + e.message + ' — is port 3055 running?';
      }
    });

    document.getElementById('btn-header-request').addEventListener('click', async function () {
      var key = document.getElementById('header-key').value.trim();
      try {
        var res = await fetch('http://localhost:3057/api/weather', {
          headers: { 'Authorization': 'Bearer ' + key }
        });
        var data = await res.json();
        document.getElementById('header-output').textContent = JSON.stringify(data, null, 2);
        showResult('header-result', res.ok ? 'success' : 'failure',
          res.ok ? '✓ Response received — check :3057 logs, the key is NOT in the URL' : '✗ ' + data.error);
      } catch (e) {
        showResult('header-result', 'failure', '✗ ' + e.message + ' — is port 3057 running?');
      }
    });

    document.getElementById('btn-url').addEventListener('click', function () {
      window.open('http://localhost:3055');
    });
    document.getElementById('btn-header').addEventListener('click', function () {
      window.open('http://localhost:3057');
    });
  </script>
</body>
</html>`;

app.get('/', function (req, res) {
  res.send(GUIDE_HTML);
});

app.listen(PORT, function () {
  console.log('API Key Auth Lab running at http://localhost:' + PORT);
});
