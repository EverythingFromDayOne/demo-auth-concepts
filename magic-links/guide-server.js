/*
 * Terminal 2: cd auth-concepts/magic-links && npm run guide
 * Magic Links & Passwordless Lab (port 3077)
 */

const express = require('express');

const app = express();
const PORT = 3077;

const GUIDE_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Magic Links Lab</title>
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
    .section-title {
      font-size: 0.95rem;
      color: #94a3b8;
      margin-bottom: 1rem;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .flow-box pre { color: #00ff41; font-size: 0.78rem; line-height: 1.6; }
    .flow-box p { max-width: 640px; }
  </style>
</head>
<body>
  <h1>🔗 Magic Links — How Passwordless Auth Works</h1>
  <p class="subtitle">One-time email links replace passwords. The token in the link IS the credential.</p>

  <div class="flow-box">
    <div class="section-title">What Magic Links Replace</div>
    <pre>Traditional login:
  [email]    → alice@example.com
  [password] → •••••••••

Magic link login:
  [email]    → alice@example.com
              ↓
  "We sent you a link — check your email"
              ↓
  alice@example.com inbox:
  "Click here to sign in to Inkwell → https://inkwell.io/auth/verify?token=a3f9b..."
              ↓
  Click → authenticated, no password typed

The token is the credential. It must be:
  • Cryptographically random (unpredictable)
  • Short-lived (expires in minutes)
  • Single-use (invalidated after first click)
  • Rate-limited to send (one email can't be spammed)</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">Token Lifecycle</div>
    <pre style="color:#cbd5e1">  Browser                      Server (3076/3078)               Email
     │                               │                            │
     │  POST /api/auth/send-link     │                            │
     │  { email: "alice@..." } ─────→│                            │
     │                               │ 1. generateToken()         │
     │                               │ 2. magicTokens.set(token,  │
     │                               │    { email, expiresAt })   │
     │                               │ 3. send email ────────────→│
     │←── { message: "Check email" } │                            │
     │                               │                            │
     │  (alice opens email)          │                            │
     │←──────────────────────────────────────────────────────────→│
     │  clicks: GET /auth/verify?token=a3f9b...                   │
     │───────────────────────────────→│                            │
     │                               │ 4. magicTokens.get(token)  │
     │                               │ 5. check expiry            │
     │                               │ 6. DELETE token (single use)
     │                               │ 7. create session          │
     │←── 302 /dashboard             │                            │
     │    Set-Cookie: iw_session=... │                            │
     │                               │                            │
     │  GET /dashboard               │                            │
     │───────────────────────────────→│                            │
     │←── 200 dashboard HTML ────────│                            │</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">⚠️ Attack: Predictable Token (Port 3076)</div>
    <pre style="color:#cbd5e1">Port 3076 uses Math.random() to generate tokens.

Math.random() in Node.js / V8 uses xorshift128+ — a 128-bit state PRNG.
It is fast and well-distributed, but NOT suitable for security tokens because:

  1. The state can be recovered from ~3 consecutive outputs
  2. Once recovered, ALL past and future outputs can be computed
  3. An attacker who registers their own accounts (gets 3+ tokens) can compute
     the token that will be issued to the next user — before that user clicks it

Example: if these tokens were observed:
  "k7m2p9"  →  "3r8xn1"  →  "9h4jw6"
  ↓ run state recovery algorithm ↓
  Next token for victim@example.com: "2f5qt8"
  Attacker authenticates as victim.</pre>
    <div style="margin-top:1rem">
      <button class="demo-btn" id="btn-compare-entropy">Compare token entropy</button>
      <pre class="decoded-box" id="entropy-output" style="min-height:120px;margin-top:0.5rem">Click to compare</pre>
    </div>
  </div>

  <div class="flow-box">
    <div class="section-title">⚠️ Attack: Captured Link Used Days Later</div>
    <pre style="color:#cbd5e1">Where magic links leak:
  • Email is forwarded to a work account → IT department sees the link
  • Email is indexed by Google Workspace search → link stored in Google's index
  • Referer header: if the /auth/verify page loads ANY external resource
    (analytics, fonts, images), the full URL including token is sent as Referer
  • Proxy logs: corporate proxies log all URLs accessed by employees
  • Browser history: stored locally, potentially synced across devices

On port 3076: tokens have no expiry — a leaked link from 3 months ago still works.

On port 3078: tokens expire after 15 minutes.
After expiry, the link returns "This link has expired" and the token is deleted.

The Referer risk specifically: after verifying, redirect immediately to a clean URL.
Port 3078's /auth/verify does:
  1. Validate token → delete token → create session → 302 /dashboard
The token URL is accessed once by the user's browser, then never appears again.
Also: &lt;meta name="referrer" content="no-referrer"&gt; on the dashboard ensures
the dashboard doesn't leak anything if it has external resources.</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">⚠️ Attack: Replay — Same Link Works Multiple Times (Port 3076)</div>
    <div style="margin-top:1rem">
      <button class="demo-btn" id="btn-replay-test">Request link + replay on :3076</button>
      <div class="result-banner" id="replay-result"></div>
      <pre class="decoded-box" id="replay-output" style="min-height:100px;margin-top:0.5rem">–</pre>
    </div>
  </div>

  <div class="flow-box">
    <div class="section-title">⚠️ Attack: Inbox Spam (Port 3076)</div>
    <pre style="color:#cbd5e1">POST /api/auth/send-link accepts unlimited requests per email address.

An attacker can:
  1. POST { email: "victim@company.com" } → 1,000 times per minute
  2. Victim's inbox is flooded with "Your Inkwell sign-in link" emails
  3. Victim cannot find legitimate emails — denial of service against their inbox
  4. If emails have a click-tracking pixel, the attacker also learns whether
     the victim opened each email (timing side-channel)

Additionally: many email providers count outbound volume.
Sending 1,000 emails in a minute from a domain triggers spam classification
and can get the sender domain blacklisted — affecting ALL users.

Port 3078 limit: 3 magic link emails per email address per hour.
The 4th request in the same hour returns the same 200 response
(no error message — to prevent confirming that the email exists).</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">⚠️ Attack: Which Emails Have Accounts? (Bonus Vulnerability)</div>
    <pre style="color:#cbd5e1">Some implementations return different responses based on whether the email is registered:

  POST { email: "alice@example.com" }
  → 200 { message: "Magic link sent!" }

  POST { email: "unknown@nothere.com" }
  → 404 { error: "No account found for this email" }

Result: an attacker can enumerate which emails are registered by watching the response.
They can then launch targeted phishing or credential-stuffing against those accounts.

The fix: return the SAME response regardless of whether the email exists.

  POST { email: "alice@example.com" }
  → 200 { message: "If that email is registered, a link has been sent." }

  POST { email: "unknown@nothere.com" }
  → 200 { message: "If that email is registered, a link has been sent." }

Internally the server knows — it just doesn't tell the client.
Port 3078 uses this phrasing for all responses including rate-limited ones.</pre>
  </div>

  <div class="flow-box">
    <div class="section-title">When Magic Links Make Sense</div>
    <table style="width:100%;border-collapse:collapse;font-size:0.82rem;margin-top:0.5rem">
      <tr style="color:#64748b;border-bottom:1px solid #1a3a1a">
        <th style="text-align:left;padding:0.5rem">Property</th>
        <th>Password</th>
        <th>Magic Link</th>
        <th>Passkey</th>
      </tr>
      <tr style="border-bottom:1px solid #0d1f0d">
        <td style="padding:0.5rem;color:#94a3b8">Nothing to remember</td>
        <td style="text-align:center;color:#fca5a5">No</td>
        <td style="text-align:center;color:#4ade80">Yes</td>
        <td style="text-align:center;color:#4ade80">Yes</td>
      </tr>
      <tr style="border-bottom:1px solid #0d1f0d">
        <td style="padding:0.5rem;color:#94a3b8">Works offline</td>
        <td style="text-align:center;color:#4ade80">Yes</td>
        <td style="text-align:center;color:#fca5a5">No (needs email)</td>
        <td style="text-align:center;color:#4ade80">Yes</td>
      </tr>
      <tr style="border-bottom:1px solid #0d1f0d">
        <td style="padding:0.5rem;color:#94a3b8">Phishing-resistant</td>
        <td style="text-align:center;color:#fca5a5">No</td>
        <td style="text-align:center;color:#fbbf24">Partial (email can be phished)</td>
        <td style="text-align:center;color:#4ade80">Yes (origin-bound)</td>
      </tr>
      <tr style="border-bottom:1px solid #0d1f0d">
        <td style="padding:0.5rem;color:#94a3b8">Password breach risk</td>
        <td style="text-align:center;color:#fca5a5">Yes</td>
        <td style="text-align:center;color:#4ade80">No (no passwords)</td>
        <td style="text-align:center;color:#4ade80">No (no passwords)</td>
      </tr>
      <tr style="border-bottom:1px solid #0d1f0d">
        <td style="padding:0.5rem;color:#94a3b8">Requires email access</td>
        <td style="text-align:center;color:#4ade80">No</td>
        <td style="text-align:center;color:#fca5a5">Yes (email = factor)</td>
        <td style="text-align:center;color:#4ade80">No</td>
      </tr>
      <tr>
        <td style="padding:0.5rem;color:#94a3b8">Best for</td>
        <td style="text-align:center;color:#94a3b8">Any app, high-freq users</td>
        <td style="text-align:center;color:#94a3b8">Low-freq, email-first apps</td>
        <td style="text-align:center;color:#94a3b8">High-security, modern browsers</td>
      </tr>
    </table>
  </div>

  <div class="target-switcher">
    <button class="btn-vulnerable" id="btn-vuln">Weak Magic Links (3076)</button>
    <button class="btn-protected" id="btn-secure">Hardened Magic Links (3078)</button>
  </div>

  <script>
    function showResult(id, type, msg) {
      var el = document.getElementById(id);
      el.className = 'result-banner ' + type;
      el.textContent = msg;
      el.style.display = 'block';
    }

    document.getElementById('btn-compare-entropy').addEventListener('click', function() {
      function weakToken() {
        return Math.random().toString(36).slice(2) +
               Math.random().toString(36).slice(2) +
               Math.random().toString(36).slice(2);
      }

      function strongTokenSimulated() {
        var arr = new Uint8Array(32);
        crypto.getRandomValues(arr);
        return Array.from(arr).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
      }

      var weak1 = weakToken();
      var weak2 = weakToken();
      var weak3 = weakToken();
      var strong = strongTokenSimulated();

      document.getElementById('entropy-output').textContent =
        'Weak (Math.random × 3):\\n' +
        '  Token 1: ' + weak1 + '  (' + weak1.length + ' chars, ~63 bits apparent)\\n' +
        '  Token 2: ' + weak2 + '\\n' +
        '  Token 3: ' + weak3 + '\\n' +
        '  Weakness: V8 xorshift128+ state is recoverable from observed outputs.\\n\\n' +
        'Strong (crypto.getRandomValues / Node crypto.randomBytes):\\n' +
        '  Token:   ' + strong + '  (' + strong.length + ' hex chars = 256 bits)\\n' +
        '  Each bit is independent. No state recovery possible.\\n' +
        '  Brute force at 10 billion guesses/sec: ' +
        '2^256 / 10^10 / 3.15×10^7 ≈ 3.7×10^59 years';
    });

    document.getElementById('btn-replay-test').addEventListener('click', async function() {
      var out = document.getElementById('replay-output');
      try {
        var r1 = await fetch('http://localhost:3076/api/auth/send-link', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: 'alice@example.com' }),
        });
        var d1 = await r1.json();
        var link = d1.demoLink;
        out.textContent = 'Step 1: requested magic link\\n  → ' + link + '\\n\\n';

        var token = new URL(link).searchParams.get('token');

        var v1 = await fetch('http://localhost:3076/auth/verify?token=' + token, {
          redirect: 'manual',
        });
        out.textContent += 'Step 2: first verify → HTTP ' + v1.status + ' ' + (v1.status === 302 ? '(redirect to dashboard ✓)' : '') + '\\n';

        var v2 = await fetch('http://localhost:3076/auth/verify?token=' + token, {
          redirect: 'manual',
        });
        out.textContent += 'Step 3: replay same token → HTTP ' + v2.status + ' ' + (v2.status === 302 ? '(redirect to dashboard ✓ — REPLAY WORKED!)' : '(rejected ✓)') + '\\n\\n';

        var replayed = v2.status === 302;
        showResult('replay-result', replayed ? 'failure' : 'success',
          replayed
            ? '⚠ Replay succeeded on :3076 — same token accepted twice'
            : '✓ Replay blocked — token was invalidated after first use');
      } catch (e) {
        showResult('replay-result', 'failure', '✗ ' + e.message + ' — is :3076 running?');
      }
    });

    document.getElementById('btn-vuln').addEventListener('click', function() {
      window.open('http://localhost:3076');
    });
    document.getElementById('btn-secure').addEventListener('click', function() {
      window.open('http://localhost:3078');
    });
  </script>
</body>
</html>`;

app.get('/', function (req, res) {
  res.send(GUIDE_HTML);
});

app.listen(PORT, function () {
  console.log('Magic Links & Passwordless Lab running at http://localhost:' + PORT);
});
