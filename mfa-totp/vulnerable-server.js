/*
 * SecureVault (weak TOTP) - port 3070
 */
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const app = express();
const PORT = 3070;

app.use(cors({ origin: 'http://localhost:3071' }));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ⚠️ DEMO ONLY: plaintext secrets.
const USERS = [
  { username: 'alice', password: 'pass1234', fullName: 'Alice Chen', role: 'user', mfaEnabled: true, totpSecret: 'JBSWY3DPEHPK3PXP' },
  { username: 'bob', password: 'qwerty123', fullName: 'Bob Martinez', role: 'user', mfaEnabled: false, totpSecret: null },
  { username: 'admin', password: 'admin456', fullName: 'Admin User', role: 'admin', mfaEnabled: true, totpSecret: 'JBSWY3DPEHPK3PXP' },
];

const pendingSessions = new Map();
const completedSessions = new Map();

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const session = completedSessions.get(token);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });
  req.user = session;
  req.token = token;
  next();
}

// ⚠️ DEMO ONLY: expose current code
app.get('/api/current-totp', (req, res) => {
  const { username } = req.query;
  const user = USERS.find((u) => u.username === username);
  if (!user || !user.mfaEnabled) return res.status(404).json({ error: 'MFA not enabled for this user' });
  const code = speakeasy.totp({ secret: user.totpSecret, encoding: 'base32' });
  const secondsRemaining = 30 - (Math.floor(Date.now() / 1000) % 30);
  res.json({ code, secondsRemaining, note: 'DEMO ONLY — production servers never expose current TOTP codes' });
});

app.get('/api/totp-qr', async (req, res) => {
  const { username } = req.query;
  const user = USERS.find((u) => u.username === username);
  if (!user || !user.mfaEnabled) return res.status(404).json({ error: 'MFA not enabled' });
  const otpauthUrl = `otpauth://totp/SecureVault:${username}?secret=${user.totpSecret}&issuer=SecureVault`;
  const qrDataUrl = await QRCode.toDataURL(otpauthUrl);
  // ⚠️ DEMO ONLY: returning secret
  res.json({ qrDataUrl, otpauthUrl, secret: user.totpSecret });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = USERS.find((u) => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  if (!user.mfaEnabled) {
    const token = crypto.randomBytes(32).toString('hex');
    completedSessions.set(token, { username: user.username, fullName: user.fullName, role: user.role });
    return res.json({ token, mfaRequired: false });
  }

  const pendingToken = crypto.randomBytes(16).toString('hex');
  pendingSessions.set(pendingToken, { username: user.username, expiresAt: Date.now() + 5 * 60 * 1000 });
  res.json({ mfaRequired: true, pendingToken });
});

app.post('/api/verify-totp', (req, res) => {
  const { pendingToken, code } = req.body;
  const pending = pendingSessions.get(pendingToken);
  if (!pending) return res.status(401).json({ error: 'No pending session — log in again' });
  const user = USERS.find((u) => u.username === pending.username);

  // ⚠️ VULNERABILITY: wide window and no replay/rate-limit.
  const valid = speakeasy.totp.verify({
    secret: user.totpSecret,
    encoding: 'base32',
    token: String(code || ''),
    window: 10,
  });

  if (!valid) return res.status(401).json({ error: 'Invalid TOTP code' });

  pendingSessions.delete(pendingToken);
  const token = crypto.randomBytes(32).toString('hex');
  completedSessions.set(token, { username: user.username, fullName: user.fullName, role: user.role });
  res.json({ token });
});

// ⚠️ VULNERABILITY: secret exposure
app.get('/api/debug/totp-secret', (req, res) => {
  const { username } = req.query;
  const user = USERS.find((u) => u.username === username);
  if (!user || !user.mfaEnabled) return res.status(404).json({ error: 'User not found or MFA disabled' });
  res.json({
    username,
    totpSecret: user.totpSecret,
    otpauthUrl: `otpauth://totp/SecureVault:${username}?secret=${user.totpSecret}&issuer=SecureVault`,
  });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ username: req.user.username, fullName: req.user.fullName, role: req.user.role });
});

app.get('/api/vault', requireAuth, (req, res) => {
  res.json([
    { id: 1, site: 'github.com', username: 'alice@dev.io', passwordPreview: '••••••••' },
    { id: 2, site: 'aws.amazon.com', username: 'alice', passwordPreview: '••••••••' },
    { id: 3, site: 'stripe.com', username: 'alice@dev.io', passwordPreview: '••••••••' },
  ]);
});

app.post('/api/logout', requireAuth, (req, res) => {
  completedSessions.delete(req.token);
  res.json({ message: 'Logged out' });
});

const HTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SecureVault - Weak TOTP</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8fafc;color:#0f172a}
.top{background:#1e293b;color:#fff;padding:1rem 1.25rem;display:flex;justify-content:space-between;align-items:center}.top b{color:#a78bfa}
.wrap{max-width:980px;margin:0 auto;padding:1.25rem}.card{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:1rem;margin-bottom:1rem}
.login-input{width:100%;padding:.6rem .75rem;border:1px solid #cbd5e1;border-radius:6px;font-size:.95rem;color:#0f172a;background:#fff;outline:none;box-sizing:border-box;font-family:inherit}
.login-input:focus{border-color:#7c3aed;box-shadow:0 0 0 3px rgba(124,58,237,.15)} .btn{padding:.6rem .9rem;border:0;border-radius:6px;background:#7c3aed;color:#fff;cursor:pointer}
.btn.secondary{background:#334155}.result{display:none;margin-top:.6rem;padding:.55rem .75rem;border-radius:6px;font-size:.84rem}.result.failure{background:#fee2e2;color:#991b1b;border:1px solid #fca5a5}.result.success{background:#dcfce7;color:#166534;border:1px solid #86efac}.result.info{background:#dbeafe;color:#1e3a8a;border:1px solid #93c5fd}
pre{background:#0f172a;color:#cbd5e1;padding:.75rem;border-radius:8px;white-space:pre-wrap;min-height:70px} table{width:100%;border-collapse:collapse}th,td{padding:.6rem;border-bottom:1px solid #e2e8f0;text-align:left}
</style></head><body>
<div class="top"><div><b>SecureVault</b> - Store and access your passwords securely</div><button id="btn-logout" class="btn secondary" style="display:none">Logout</button></div>
<div class="wrap">
<div id="dashboard" class="card" style="display:none"><div style="background:#fef3c7;border:1px solid #d97706;color:#78350f;padding:.7rem;border-radius:8px;font-size:.84rem;margin-bottom:.8rem">
⚠️ WEAK MFA: TOTP window is ±5 minutes (window:10). Same code accepted multiple times. No rate limit on /api/verify-totp.
</div><h3>Your vault</h3><table><thead><tr><th>Site</th><th>Username</th><th>Password</th></tr></thead><tbody id="vault"></tbody></table></div>
<div id="phase1" class="card"><h3>Phase 1 - Password</h3><input id="username" class="login-input" value="alice" placeholder="username"><div style="height:.6rem"></div><input id="password" type="password" class="login-input" value="pass1234" placeholder="password"><div style="height:.8rem"></div><button id="btn-login" class="btn">Continue</button><div id="login-result" class="result"></div></div>
<div id="phase2" class="card" style="display:none"><h3>Phase 2 - Authenticator code</h3><input id="totp-code" class="login-input" placeholder="123456"><div style="height:.8rem"></div><button id="btn-verify" class="btn">Verify</button><div id="totp-result" class="result"></div>
<div id="totp-helper" style="margin-top:.75rem;padding:.6rem;background:#fef3c7;border:1px solid #d97706;border-radius:6px;font-size:.82rem;color:#78350f">⚠️ Demo helper: current code for <strong id="helper-username"></strong>: <strong id="helper-code" style="font-family:monospace;font-size:1.1rem;letter-spacing:.15em">------</strong> <span id="helper-timer" style="margin-left:.5rem;color:#92400e"></span><br><small>In production, only your authenticator app knows this code.</small></div>
</div></div>
<script>
let pendingToken=null,currentUsername=null,helperInterval=null,authToken=localStorage.getItem('svToken')||null;
function showResult(id,type,msg){const e=document.getElementById(id);e.className='result '+type;e.textContent=msg;e.style.display='block'}
function hidePanels(){document.getElementById('phase1').style.display='none';document.getElementById('phase2').style.display='none';document.getElementById('dashboard').style.display='none';document.getElementById('btn-logout').style.display='none'}
function showLogin(){hidePanels();document.getElementById('phase1').style.display='block';if(helperInterval) clearInterval(helperInterval)}
async function loadDashboard(){if(!authToken){showLogin();return;}const r=await fetch('/api/vault',{headers:{Authorization:'Bearer '+authToken}});if(!r.ok){localStorage.removeItem('svToken');authToken=null;showLogin();return;}const d=await r.json();hidePanels();document.getElementById('dashboard').style.display='block';document.getElementById('btn-logout').style.display='block';document.getElementById('vault').innerHTML=d.map(x=>'<tr><td>'+x.site+'</td><td>'+x.username+'</td><td>'+x.passwordPreview+'</td></tr>').join('')}
function startHelperRefresh(username){document.getElementById('helper-username').textContent=username;if(helperInterval) clearInterval(helperInterval);helperInterval=setInterval(async()=>{try{const r=await fetch('/api/current-totp?username='+encodeURIComponent(username));const d=await r.json();document.getElementById('helper-code').textContent=d.code;document.getElementById('helper-timer').textContent='('+d.secondsRemaining+'s)';}catch(e){}},1000)}
document.getElementById('totp-code').addEventListener('input',function(){this.value=this.value.replace(/\\D/g,'').slice(0,6)});
document.getElementById('btn-login').addEventListener('click',async function(){try{const username=document.getElementById('username').value;const password=document.getElementById('password').value;const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});const d=await r.json();if(!r.ok)return showResult('login-result','failure','✗ '+d.error);if(d.mfaRequired){pendingToken=d.pendingToken;currentUsername=username;document.getElementById('phase1').style.display='none';document.getElementById('phase2').style.display='block';startHelperRefresh(username);showResult('totp-result','info','Password accepted — enter your 6-digit authenticator code')}else{authToken=d.token;localStorage.setItem('svToken',authToken);loadDashboard()}}catch(e){showResult('login-result','failure','✗ Network error — is the server running?')}});
document.getElementById('btn-verify').addEventListener('click',async function(){const code=document.getElementById('totp-code').value.replace(/\\s/g,'');try{const r=await fetch('/api/verify-totp',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pendingToken,code})});const d=await r.json();if(!r.ok)return showResult('totp-result','failure','✗ '+d.error);if(helperInterval) clearInterval(helperInterval);authToken=d.token;localStorage.setItem('svToken',authToken);loadDashboard()}catch(e){showResult('totp-result','failure','✗ '+e.message)}});
document.getElementById('btn-logout').addEventListener('click',async()=>{if(authToken){await fetch('/api/logout',{method:'POST',headers:{Authorization:'Bearer '+authToken}}).catch(()=>{})}localStorage.removeItem('svToken');authToken=null;showLogin()});
loadDashboard();
</script></body></html>`;

app.get('/', (_req, res) => res.send(HTML));

app.listen(PORT, () => {
  console.log(`SecureVault (weak TOTP) running at http://localhost:${PORT}`);
});
