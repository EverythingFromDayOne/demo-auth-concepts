/*
 * Terminal 2: cd auth-concepts/oauth2-oidc && npm run guide
 * OAuth2 & OIDC Lab (port 3068)
 */

const express = require('express');

const app = express();
const PORT = 3068;

const GUIDE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OAuth2 & OIDC Lab</title>
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
    .target-switcher .btn-protected {
      background: #dc2626;
      color: #fff;
      border-color: #dc2626;
    }
    .flow-box { max-width: 900px; }
    .decoded-box {
      background: #0a0a0a;
      border: 1px solid #1a3a1a;
      border-radius: 4px;
      padding: 1rem;
      font-family: 'Courier New', monospace;
      font-size: 0.85rem;
      white-space: pre-wrap;
      word-break: break-all;
      color: #00ff41;
      min-height: 3rem;
      margin-top: 0.5rem;
    }
    .result-banner {
      padding: 0.6rem 1rem;
      border-radius: 4px;
      font-size: 0.85rem;
      margin-top: 0.5rem;
      display: none;
    }
    .result-banner.success { background: #052e16; border: 1px solid #16a34a; color: #4ade80; }
    .result-banner.failure { background: #450a0a; border: 1px solid #dc2626; color: #fca5a5; }
    .result-banner.info    { background: #0c1a2e; border: 1px solid #1e40af; color: #93c5fd; }
    input.field, textarea.token-input {
      background: #111;
      border: 1px solid #1a3a1a;
      color: #00ff41;
      font-family: 'Courier New', monospace;
      padding: 0.5rem 0.75rem;
      border-radius: 4px;
      width: 100%;
      box-sizing: border-box;
      outline: none;
      font-size: 0.9rem;
    }
    textarea.token-input { resize: vertical; min-height: 5rem; }
    input.field:focus, textarea.token-input:focus { border-color: #00ff41; }
    .flow-box pre { color: #00ff41; font-size: 0.78rem; line-height: 1.6; }
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
  <h1>🔐 OAuth2 & OpenID Connect — How They Work</h1>
  <p class="subtitle">Authorization (OAuth2) plus identity (OIDC) — with CSRF and PKCE protections on the hardened path.</p>

  <div class="flow-box">
    <div class="section-title">OAuth2 vs OpenID Connect — One Question Each</div>
    <pre>OAuth2 answers:        "Can application X access resource Y on behalf of user Z?"
                       → Issues ACCESS TOKEN
                       → User approves specific scopes (read:repos, write:calendar)

OpenID Connect adds:   "Who is the user?"
                       → Issues ID TOKEN (a JWT with user identity claims)
                       → Built on top of OAuth2 (uses the same flow)
                       → Adds the 'openid' scope + /userinfo endpoint

Think of it as:
  OAuth2 = authorization (permission to do things)
  OIDC   = authentication (who you are) built on OAuth2</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">Authorization Code Flow — Step by Step</div>
    <pre style="color:#cbd5e1">ACTORS:
  User        — wants to connect GitBucket to ConnectApp
  ConnectApp  — the OAuth2 client (our app, wants access)
  GrantID     — the authorization server (owns the user account)
  GitBucket   — the resource server (has the repos)

1. ConnectApp initiates the flow
   ConnectApp                     GrantID (Auth Server)
       │                                 │
       ├── Redirect user to ────────────→│
       │   /auth/authorize               │
       │   ?client_id=connectapp         │
       │   &redirect_uri=.../callback    │
       │   &scope=read:repos+openid      │
       │   &response_type=code           │
       │   &state=abc123  ← CSRF token   │

2. User logs in and approves
       │                                 │ Show login + consent screen
       │←── User approves ──────────────┤
       │                                 │ Issue authorization code
       │←── 302 .../callback ───────────┤
       │    ?code=xyz789                 │
       │    &state=abc123  ← echoed back │

3. ConnectApp verifies state and exchanges code
       │ Verify: state === 'abc123' (what we sent)  ← CSRF check
       │
       ├── POST /auth/token ───────────→ │
       │   { code, client_secret, ... }   │
       │                                 │ Verify code + client_secret
       │←── { access_token, id_token } ──┤

4. ConnectApp uses access_token to call GitBucket API
   ConnectApp                        GitBucket (Resource Server)
       │                                 │
       ├── GET /api/repos ─────────────→ │
       │   Authorization: Bearer &lt;token&gt; │
       │←── 200 + repos ────────────────┤</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">⚠ Attack: Missing state Parameter — CSRF on OAuth Callback</div>
    <pre style="color:#cbd5e1">Setup:
  Victim is logged in to ConnectApp.
  ConnectApp has a /connect endpoint that starts a new OAuth flow.

Attack (port 3067 — no state):

  1. Attacker starts an OAuth flow at GrantID and captures authorization code
  2. Attacker tricks victim into loading:
     /callback?code=ATTACKER_CODE
  3. Victim's browser loads that URL on ConnectApp
  4. ConnectApp exchanges ATTACKER_CODE for tokens
     → victim's ConnectApp account linked to ATTACKER'S GitBucket account</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">✅ Fix: state Parameter + PKCE</div>
    <pre style="color:#cbd5e1">// CLIENT — generate state + PKCE on /connect
const state = crypto.randomBytes(16).toString('hex');
const codeVerifier = crypto.randomBytes(32).toString('base64url');
const codeChallenge = crypto.createHash('sha256')
  .update(codeVerifier).digest('base64url');

pendingFlows.set(state, { codeVerifier });

// CALLBACK — verify state, send code_verifier at token exchange
if (!pendingFlows.has(state)) {
  return res.status(400).send('Invalid state — possible CSRF');
}

PKCE (RFC 7636):
  code_verifier  = random secret (client only)
  code_challenge = base64url(SHA256(code_verifier))
  Sent with /authorize: ?code_challenge=...&code_challenge_method=S256
  Sent with /token:     body includes code_verifier
  Auth server verifies: SHA256(code_verifier) == code_challenge</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">OIDC Identity Token (id_token)</div>
    <pre style="color:#cbd5e1">The id_token is a JWT issued alongside access_token when 'openid' scope is requested.

Standard OIDC claims:
  sub   → Unique user ID at the issuer
  iss   → Token issuer
  aud   → Intended audience (client_id)
  exp   → Expiry
  email → User's email (if 'email' scope approved)
  name  → Display name

Difference:
  access_token → call APIs on the user's behalf (GitBucket)
  id_token     → proves to YOUR app who the user is (ConnectApp only)

Rule: NEVER send id_token to your own API endpoints — use access_token for API calls.</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">🔬 Interactive Labs</div>

    <h2 style="margin-bottom:0.5rem;font-size:1rem">PKCE Demo — Generate code_verifier + code_challenge</h2>
    <p style="color:#94a3b8;font-size:0.85rem;margin-bottom:0.75rem;max-width:640px">The challenge goes with /authorize; the verifier is sent only at token exchange.</p>
    <button class="demo-btn" id="btn-gen-pkce">Generate PKCE pair</button>
    <div style="margin-top:1rem;color:#888;font-size:0.82rem">code_verifier (keep secret):</div>
    <div class="decoded-box" id="pkce-verifier">—</div>
    <div style="margin-top:0.75rem;color:#888;font-size:0.82rem">code_challenge = base64url(SHA-256(verifier)):</div>
    <div class="decoded-box" id="pkce-challenge">—</div>
    <div style="margin-top:0.75rem;color:#888;font-size:0.82rem">Verification math:</div>
    <div class="decoded-box" id="pkce-math">—</div>
    <div class="result-banner" id="pkce-result"></div>
  </div>

  <div class="flow-box">
    <h2 style="margin-bottom:0.5rem;font-size:1rem">id_token Decoder — Inspect OIDC Claims</h2>
    <p style="color:#94a3b8;font-size:0.85rem;margin-bottom:0.75rem;max-width:640px">Paste an id_token from port 3067 or 3069 after completing the OAuth flow.</p>
    <textarea class="token-input" id="id-token-input" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."></textarea>
    <button class="demo-btn" id="btn-decode-id-token" style="margin-top:0.5rem">Decode id_token</button>
    <div style="margin-top:0.75rem;color:#888;font-size:0.82rem">Header:</div>
    <div class="decoded-box" id="id-token-header">—</div>
    <div style="margin-top:0.75rem;color:#888;font-size:0.82rem">Payload (OIDC claims):</div>
    <div class="decoded-box" id="id-token-payload">—</div>
    <div class="result-banner" id="id-token-result"></div>
  </div>

  <div class="flow-box">
    <h2 style="margin-bottom:0.5rem;font-size:1rem">State Parameter Demo — CSRF Token</h2>
    <p style="color:#94a3b8;font-size:0.85rem;margin-bottom:0.75rem;max-width:640px">Random nonce stored server-side and verified on callback.</p>
    <button class="demo-btn" id="btn-gen-state">Generate state value</button>
    <div class="decoded-box" id="state-out" style="margin-top:0.75rem">—</div>
  </div>

  <div class="target-switcher">
    <button class="btn-vulnerable" id="btn-vuln">Vulnerable OAuth (3067)</button>
    <button class="btn-protected" id="btn-strong">Hardened OAuth (3069)</button>
  </div>

  <script>
    function showResult(id, type, msg) {
      var el = document.getElementById(id);
      if (!el) return;
      el.className = 'result-banner ' + type;
      el.textContent = msg;
      el.style.display = 'block';
    }

    document.getElementById('btn-gen-pkce').addEventListener('click', async function() {
      try {
        var verifierBytes = new Uint8Array(32);
        crypto.getRandomValues(verifierBytes);
        var verifier = btoa(String.fromCharCode.apply(null, verifierBytes))
          .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '');
        var msgBuffer = new TextEncoder().encode(verifier);
        var hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        var hashArray = new Uint8Array(hashBuffer);
        var challenge = btoa(String.fromCharCode.apply(null, hashArray))
          .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '');
        document.getElementById('pkce-verifier').textContent = verifier;
        document.getElementById('pkce-challenge').textContent = challenge;
        document.getElementById('pkce-math').textContent =
          'SHA256("' + verifier.substring(0, 12) + '...") → base64url → "' + challenge + '"';
        showResult('pkce-result', 'success',
          '✓ PKCE pair generated — verifier ' + verifier.length + ' chars, challenge ' + challenge.length + ' chars');
      } catch (e) {
        showResult('pkce-result', 'failure', '✗ ' + e.message);
      }
    });

    function b64urlDecode(str) {
      try {
        var padded = str.replace(/-/g, '+').replace(/_/g, '/');
        while (padded.length % 4) padded += '=';
        return JSON.parse(atob(padded));
      } catch (e) {
        return { raw: str, error: 'could not decode' };
      }
    }

    document.getElementById('btn-decode-id-token').addEventListener('click', function() {
      var token = document.getElementById('id-token-input').value.trim();
      if (!token) { showResult('id-token-result', 'failure', '✗ Paste an id_token first'); return; }
      var parts = token.split('.');
      if (parts.length !== 3) {
        showResult('id-token-result', 'failure', '✗ Not a valid JWT — expected 3 parts');
        return;
      }
      var header = b64urlDecode(parts[0]);
      var payload = b64urlDecode(parts[1]);
      document.getElementById('id-token-header').textContent = JSON.stringify(header, null, 2);
      document.getElementById('id-token-payload').textContent = JSON.stringify(payload, null, 2);
      var claims = [];
      if (payload.sub) claims.push('sub: ' + payload.sub);
      if (payload.iss) claims.push('iss: ' + payload.iss);
      if (payload.aud) claims.push('aud: ' + payload.aud);
      if (payload.email) claims.push('email: ' + payload.email);
      if (payload.name) claims.push('name: ' + payload.name);
      if (payload.exp) claims.push('exp: ' + new Date(payload.exp * 1000).toISOString());
      showResult('id-token-result', 'success',
        '✓ OIDC claims — ' + (claims.length ? claims.join(' | ') : 'no standard claims found'));
    });

    document.getElementById('btn-gen-state').addEventListener('click', function() {
      var stateBytes = new Uint8Array(16);
      crypto.getRandomValues(stateBytes);
      var state = Array.from(stateBytes).map(function(b) {
        return b.toString(16).padStart(2, '0');
      }).join('');
      document.getElementById('state-out').textContent =
        state + '\\n\\n' +
        'Added to pendingFlows Map on port 3069:\\n' +
        '  pendingFlows.set("' + state + '", { codeVerifier: "...", createdAt: ' + Date.now() + ' })\\n\\n' +
        'Sent with /authorize:\\n' +
        '  ...&state=' + state + '&code_challenge=...\\n\\n' +
        'Callback verifies:\\n' +
        '  pendingFlows.has(req.query.state) → must match exactly, then deleted';
    });

    document.getElementById('btn-vuln').addEventListener('click', function() {
      window.open('http://localhost:3067');
    });
    document.getElementById('btn-strong').addEventListener('click', function() {
      window.open('http://localhost:3069');
    });
  </script>
</body>
</html>`;

app.get('/', function (req, res) {
  res.send(GUIDE_HTML);
});

app.listen(PORT, function () {
  console.log('OAuth2 & OIDC Lab running at http://localhost:' + PORT);
});
