/*
 * MFA & TOTP Lab - port 3071
 */
const express = require('express');
const app = express();
const PORT = 3071;

const GUIDE_HTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MFA & TOTP Lab</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Courier New', Courier, monospace;
  background: #0a0a0a;
  color: #00ff41;
  min-height: 100vh;
  padding: 2rem;
}
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
<h1>🔐 MFA & TOTP — How It Works</h1>
<p class="subtitle">Time-based one-time codes add a second factor on top of passwords.</p>

<div class="flow-box"><strong>What Makes MFA Different</strong>
<pre>Factor 1 - Something you KNOW:   password, PIN
Factor 2 - Something you HAVE:   authenticator app, hardware key, SMS
Factor 3 - Something you ARE:    fingerprint, face ID

TOTP uses factor 1 + factor 2.
An attacker who steals your password still cannot log in
without physical access to your device.</pre></div>

<div class="flow-box"><strong>How TOTP Codes Are Generated (RFC 6238)</strong>
<pre>Shared Secret (base32)
  + Current Time (Unix timestamp ÷ 30 = time step T)
        │
        ▼
   HMAC-SHA1(secret, T)
        ▼
   Dynamic Truncation
        ▼
   mod 1,000,000 -> 6-digit code

Time step changes every 30 seconds.</pre>
<div style="margin-top:1rem">
  <strong>Secret (base32):</strong>
  <input class="field" id="demo-secret" value="JBSWY3DPEHPK3PXP" style="width:200px;margin:0 0.5rem">
  <button class="demo-btn" id="btn-compute">Compute current code</button>
  <pre class="decoded-box" id="compute-output" style="min-height:80px">Click to compute</pre>
</div></div>

<div class="flow-box"><strong>📱 Scan to Follow Along</strong>
<p style="max-width:640px">Scan with Google Authenticator, Authy, or 1Password:</p>
<div id="qr-container" style="margin:1rem 0">Loading QR code...</div>
<pre class="decoded-box" id="otpauth-display"></pre></div>

<div class="flow-box"><strong>⚠️ Attack: Replay Attack (Port 3070)</strong>
<pre>The same TOTP code remains valid for a short window.
If the server does not track used codes, replay is accepted.</pre>
<div style="display:flex;gap:0.5rem;flex-wrap:wrap;align-items:center;margin-bottom:0.75rem">
  <input class="field" id="replay-user" value="alice" style="width:80px">
  <input class="field" id="replay-pass" value="pass1234" style="width:100px">
  <button class="demo-btn" id="btn-replay">Login + replay same code</button>
</div>
<div class="result-banner" id="replay-result"></div>
<pre class="decoded-box" id="replay-output" style="min-height:100px">-</pre></div>

<div class="flow-box"><strong>⚠️ Attack: Wide Acceptance Window (Port 3070)</strong>
<pre>window:10 means ±10 steps around current time step.
10 × 30 seconds = ±5 minutes.
This enables many simultaneously valid codes and easier replay.

Hardened server uses window:1 (±30 seconds).</pre></div>

<div class="flow-box"><strong>✅ What Port 3072 Does Differently</strong>
<table style="width:100%;border-collapse:collapse;font-size:0.82rem;margin-top:0.5rem">
  <tr style="color:#64748b;border-bottom:1px solid #1a3a1a"><th style="text-align:left;padding:0.5rem">Property</th><th>3070</th><th>3072</th></tr>
  <tr style="border-bottom:1px solid #0d1f0d"><td style="padding:0.5rem;color:#94a3b8">Window</td><td style="text-align:center;color:#fca5a5">±5 min</td><td style="text-align:center;color:#4ade80">±30 s</td></tr>
  <tr style="border-bottom:1px solid #0d1f0d"><td style="padding:0.5rem;color:#94a3b8">Replay prevention</td><td style="text-align:center;color:#fca5a5">None</td><td style="text-align:center;color:#4ade80">Used-code set</td></tr>
  <tr style="border-bottom:1px solid #0d1f0d"><td style="padding:0.5rem;color:#94a3b8">Rate limiting</td><td style="text-align:center;color:#fca5a5">None</td><td style="text-align:center;color:#4ade80">5 tries -> lockout</td></tr>
  <tr><td style="padding:0.5rem;color:#94a3b8">Recovery</td><td style="text-align:center;color:#fca5a5">None</td><td style="text-align:center;color:#4ade80">Backup codes</td></tr>
</table></div>

<div class="target-switcher">
  <button class="btn-vulnerable" id="btn-vuln">Weak TOTP (3070)</button>
  <button class="btn-protected" id="btn-secure">Hardened TOTP (3072)</button>
</div>

<script>
function showResult(id,type,msg){var el=document.getElementById(id);el.className='result-banner '+type;el.textContent=msg;el.style.display='block';}

document.getElementById('btn-compute').addEventListener('click', async function() {
  try {
    var r = await fetch('http://localhost:3070/api/current-totp?username=alice');
    var d = await r.json();
    var T = Math.floor(Date.now() / 1000 / 30);
    document.getElementById('compute-output').textContent =
      'Time step T = ' + T + '\\n\\n' +
      'HMAC-SHA1(secret, T) -> truncated -> mod 1,000,000\\n\\n' +
      'Current code for alice: ' + d.code + '\\n' +
      'Valid for: ' + d.secondsRemaining + ' more seconds';
  } catch(e) {
    document.getElementById('compute-output').textContent = 'Could not reach :3070 — ' + e.message;
  }
});
document.getElementById('btn-compute').click();

(async function() {
  try {
    var r = await fetch('http://localhost:3070/api/totp-qr?username=alice');
    var d = await r.json();
    document.getElementById('qr-container').innerHTML =
      '<img src="' + d.qrDataUrl + '" style="width:180px;height:180px;border:2px solid #1a3a1a;border-radius:4px">';
    document.getElementById('otpauth-display').textContent =
      'otpauth URL: ' + d.otpauthUrl + '\\n\\nManual entry secret: ' + d.secret;
  } catch(e) {
    document.getElementById('qr-container').textContent = 'Could not load QR — is :3070 running?';
  }
})();

document.getElementById('btn-replay').addEventListener('click', async function() {
  var username = document.getElementById('replay-user').value;
  var password = document.getElementById('replay-pass').value;
  var out = document.getElementById('replay-output');
  try {
    var r1 = await fetch('http://localhost:3070/api/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username, password }) });
    var d1 = await r1.json();
    if (!d1.mfaRequired) { out.textContent = 'User has no MFA — try alice'; return; }
    var r2 = await fetch('http://localhost:3070/api/current-totp?username=' + username);
    var d2 = await r2.json();
    var code = d2.code;
    out.textContent = 'Step 1: pending token issued\\nStep 2: current code = ' + code + '\\n';
    var r3 = await fetch('http://localhost:3070/api/verify-totp', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ pendingToken: d1.pendingToken, code }) });
    var d3 = await r3.json();
    out.textContent += 'Step 3: first submit -> ' + (r3.ok ? 'SUCCESS' : ('FAIL: ' + d3.error)) + '\\n';
    var r4 = await fetch('http://localhost:3070/api/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username, password }) });
    var d4 = await r4.json();
    var r5 = await fetch('http://localhost:3070/api/verify-totp', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ pendingToken: d4.pendingToken, code }) });
    out.textContent += 'Step 4: replay submit -> ' + (r5.ok ? 'SUCCESS (replay worked)' : 'Blocked');
    showResult('replay-result', r5.ok ? 'failure' : 'success', r5.ok ? '⚠ Replay accepted on :3070' : '✓ Replay blocked');
  } catch(e) {
    showResult('replay-result', 'failure', '✗ ' + e.message + ' — is :3070 running?');
  }
});

document.getElementById('btn-vuln').addEventListener('click', function() { window.open('http://localhost:3070'); });
document.getElementById('btn-secure').addEventListener('click', function() { window.open('http://localhost:3072'); });
</script>
</body></html>`;

app.get('/', (_req, res) => res.send(GUIDE_HTML));
app.listen(PORT, () => console.log(`MFA & TOTP Lab running at http://localhost:${PORT}`));
