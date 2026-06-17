/*
 * Passkeys & WebAuthn Lab - port 3074
 */
const express = require('express');
const app = express();
const PORT = 3074;

const HTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Passkeys & WebAuthn Lab</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Courier New', Courier, monospace; background: #0a0a0a; color: #00ff41; min-height: 100vh; padding: 2rem; }
h1 { font-size: 1.4rem; margin-bottom: 0.5rem; text-shadow: 0 0 8px rgba(0, 255, 65, 0.4); }
.subtitle { color: #4ade80; margin-bottom: 2rem; font-size: 0.9rem; }
.flow-box { background: #111; border: 1px solid #1a3a1a; border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; line-height: 1.9; font-size: 0.9rem; max-width: 720px; }
.flow-box strong { color: #facc15; }
.demo-btn { background: #1e293b; color: #e2e8f0; border: 1px solid #334155; padding: 0.55rem 1rem; border-radius: 6px; font-size: 0.8rem; font-weight: 600; cursor: pointer; font-family: 'Courier New', Courier, monospace; }
.demo-btn:hover { background: #334155; }
.target-switcher { position: fixed; bottom: 1rem; left: 1rem; display: flex; gap: 0.5rem; z-index: 9999; }
.target-switcher button { padding: 0.4rem 0.85rem; border-radius: 6px; font-size: 0.8rem; font-weight: 600; cursor: pointer; border: 1px solid; }
.target-switcher .btn-vulnerable { background: #1e293b; color: #fff; border-color: #334155; }
.target-switcher .btn-protected { background: #dc2626; color: #fff; border-color: #dc2626; }
.flow-box { max-width: 900px; }
input.field { background: #111; border: 1px solid #1a3a1a; color: #00ff41; font-family: 'Courier New', Courier, monospace; font-size: 0.82rem; padding: 0.4rem 0.6rem; border-radius: 4px; }
.result-banner { padding: 0.6rem 1rem; border-radius: 4px; font-size: 0.82rem; margin-top: 0.75rem; display: none; }
.result-banner.success { background: #052e16; border: 1px solid #16a34a; color: #4ade80; }
.result-banner.failure { background: #450a0a; border: 1px solid #dc2626; color: #fca5a5; }
.result-banner.info    { background: #0c1a2e; border: 1px solid #1e40af; color: #93c5fd; }
pre.decoded-box { background: #0a0a0a; border: 1px solid #1a3a1a; border-radius: 4px; padding: 0.75rem; font-size: 0.78rem; color: #cbd5e1; white-space: pre-wrap; word-break: break-all; margin-top: 0.5rem; }
</style></head><body>
<h1>🔑 Passkeys & WebAuthn — How It Works</h1>
<p class="subtitle">Passwordless sign-in with origin-bound public key cryptography.</p>

<div class="flow-box"><strong>Why Passwords Keep Failing</strong>
<pre>Passwords can be:
  ✗ Phished
  ✗ Breached
  ✗ Reused
  ✗ Stolen in transit

Passkeys fix all four:
  ✓ Phishing-resistant (origin-bound)
  ✓ Server stores public key only
  ✓ Unique per site
  ✓ Challenge-response signatures, not reusable secrets</pre></div>

<div class="flow-box"><strong>Registration Flow (one-time setup)</strong>
<pre>User -> Browser -> Server /api/register/begin
     <- challenge options
Browser creates key pair on authenticator
User verifies (biometric/PIN)
Browser -> /api/register/complete
Server stores credentialID + publicKey + counter</pre>
<strong>Authentication Flow (every sign-in)</strong>
<pre>Browser -> /api/auth/begin (fresh challenge)
User verifies and signs challenge
Browser -> /api/auth/complete
Server verifies signature + challenge + counter
Server issues session token</pre></div>

<div class="flow-box"><strong>Terms You Need to Know</strong>
<pre>RP (Relying Party): your site (rpID = localhost)
Challenge: random nonce per operation
UP: user presence (touch)
UV: user verification (biometric/PIN)
Counter: monotonic value for clone detection
Credential ID: stable handle for the key pair</pre></div>

<div class="flow-box"><strong>🔬 Browser WebAuthn Support Check</strong>
<button class="demo-btn" id="btn-check-webauthn">Check WebAuthn support</button>
<pre class="decoded-box" id="webauthn-check" style="min-height:60px">Click to check</pre></div>

<div class="flow-box"><strong>⚠️ Attack: User Presence ≠ User Verification (Port 3073)</strong>
<pre>Port 3073 uses userVerification: 'discouraged'.
That means biometric/PIN prompt may not happen.
With access to an unlocked device, an attacker may authenticate.</pre></div>

<div class="flow-box"><strong>⚠️ Attack: Counter Bypass / Clone Blindness (Port 3073)</strong>
<pre>If server never updates stored counter, cloned credentials are harder to detect.
Hardened server persists newCounter after each successful authentication.</pre></div>

<div class="flow-box"><strong>Password vs TOTP vs Passkey</strong>
<table style="width:100%;border-collapse:collapse;font-size:0.82rem;margin-top:0.5rem">
  <tr style="color:#64748b;border-bottom:1px solid #1a3a1a"><th style="text-align:left;padding:0.5rem">Property</th><th>Password</th><th>Password+TOTP</th><th>Passkey</th></tr>
  <tr style="border-bottom:1px solid #0d1f0d"><td style="padding:0.5rem;color:#94a3b8">Phishing-resistant</td><td style="text-align:center;color:#fca5a5">No</td><td style="text-align:center;color:#fbbf24">Partial</td><td style="text-align:center;color:#4ade80">Yes</td></tr>
  <tr style="border-bottom:1px solid #0d1f0d"><td style="padding:0.5rem;color:#94a3b8">Replay resistance</td><td style="text-align:center;color:#fca5a5">No</td><td style="text-align:center;color:#fbbf24">Windowed</td><td style="text-align:center;color:#4ade80">Challenge-based</td></tr>
  <tr><td style="padding:0.5rem;color:#94a3b8">User friction</td><td style="text-align:center;color:#94a3b8">Type secret</td><td style="text-align:center;color:#94a3b8">Type + code</td><td style="text-align:center;color:#4ade80">Touch/Face</td></tr>
</table></div>

<div class="target-switcher">
  <button class="btn-vulnerable" id="btn-vuln">Weak WebAuthn (3073)</button>
  <button class="btn-protected" id="btn-secure">Hardened WebAuthn (3075)</button>
</div>

<script>
function showResult(id,type,msg){var el=document.getElementById(id);el.className='result-banner '+type;el.textContent=msg;el.style.display='block';}
document.getElementById('btn-check-webauthn').addEventListener('click', async function() {
  var out = document.getElementById('webauthn-check');
  if (!window.PublicKeyCredential) {
    out.textContent = '✗ PublicKeyCredential API not available in this browser';
    return;
  }
  var platformAvail = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  out.textContent = '✓ WebAuthn API available\\n' +
    (platformAvail
      ? '✓ Platform authenticator available (Touch ID / Face ID / Windows Hello)'
      : '✗ Platform authenticator not available; hardware key may still work');
});
document.getElementById('btn-vuln').addEventListener('click', function(){ window.open('http://localhost:3073'); });
document.getElementById('btn-secure').addEventListener('click', function(){ window.open('http://localhost:3075'); });
</script></body></html>`;

app.get('/', (_req, res) => res.send(HTML));
app.listen(PORT, () => console.log(`Passkeys & WebAuthn Lab running at http://localhost:${PORT}`));
