/*
 * SecureVault (hardened TOTP) - port 3072
 */
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const app = express();
const PORT = 3072;

app.use(cors({ origin: 'http://localhost:3071' }));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const USERS = [
  { username: 'alice', password: 'pass1234', fullName: 'Alice Chen', role: 'user', mfaEnabled: true, totpSecret: 'JBSWY3DPEHPK3PXP' },
  { username: 'bob', password: 'qwerty123', fullName: 'Bob Martinez', role: 'user', mfaEnabled: false, totpSecret: null },
  { username: 'admin', password: 'admin456', fullName: 'Admin User', role: 'admin', mfaEnabled: true, totpSecret: 'JBSWY3DPEHPK3PXP' },
];

const pendingSessions = new Map();
const completedSessions = new Map();

// ✅ PROTECTED: failure lockout
const failedAttempts = new Map();

// ✅ PROTECTED: replay prevention
const usedCodes = new Map();
setInterval(() => {
  const cutoff = Math.floor(Date.now() / 30000) - 4;
  for (const key of usedCodes.keys()) {
    const step = parseInt(key.split(':')[1], 10);
    if (step < cutoff) usedCodes.delete(key);
  }
}, 2 * 60 * 1000);

// ✅ PROTECTED: single-use backup codes
const BACKUP_CODES = {
  alice: ['VAULT-A1B2', 'VAULT-C3D4', 'VAULT-E5F6', 'VAULT-G7H8', 'VAULT-I9J0', 'VAULT-K1L2', 'VAULT-M3N4', 'VAULT-O5P6'],
  admin: ['VAULT-Q7R8', 'VAULT-S9T0', 'VAULT-U1V2', 'VAULT-W3X4', 'VAULT-Y5Z6', 'VAULT-AA11', 'VAULT-BB22', 'VAULT-CC33'],
};
const usedBackupCodes = new Set();

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const session = completedSessions.get(token);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });
  req.user = session;
  req.token = token;
  next();
}

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
  // ⚠️ DEMO ONLY
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
  if (Date.now() > pending.expiresAt) {
    pendingSessions.delete(pendingToken);
    return res.status(401).json({ error: 'Session expired — log in again' });
  }
  const username = pending.username;
  const user = USERS.find((u) => u.username === username);

  const attempts = failedAttempts.get(username) || { count: 0, lockedUntil: 0 };
  if (Date.now() < attempts.lockedUntil) {
    const remaining = Math.ceil((attempts.lockedUntil - Date.now()) / 1000);
    return res.status(429).json({ error: `Too many attempts. Try again in ${remaining}s` });
  }

  const valid = speakeasy.totp.verify({
    secret: user.totpSecret,
    encoding: 'base32',
    token: String(code || ''),
    window: 1,
  });

  if (!valid) {
    attempts.count++;
    if (attempts.count >= 5) {
      attempts.count = 0;
      attempts.lockedUntil = Date.now() + 5 * 60 * 1000;
      failedAttempts.set(username, attempts);
      return res.status(429).json({ error: 'Too many failed attempts. Account locked for 5 minutes.' });
    }
    failedAttempts.set(username, attempts);
    return res.status(401).json({ error: 'Invalid TOTP code', attemptsRemaining: 5 - attempts.count });
  }

  const timeStep = Math.floor(Date.now() / 30000);
  const codeKey = `${username}:${timeStep}`;
  if (!usedCodes.has(codeKey)) usedCodes.set(codeKey, new Set());
  if (usedCodes.get(codeKey).has(String(code))) {
    return res.status(401).json({ error: 'Code already used — wait for the next code' });
  }
  usedCodes.get(codeKey).add(String(code));

  failedAttempts.delete(username);
  pendingSessions.delete(pendingToken);
  const token = crypto.randomBytes(32).toString('hex');
  completedSessions.set(token, { username: user.username, fullName: user.fullName, role: user.role });
  res.json({ token });
});

app.post('/api/backup-code', (req, res) => {
  const { pendingToken, backupCode } = req.body;
  const pending = pendingSessions.get(pendingToken);
  if (!pending) return res.status(401).json({ error: 'No pending session — log in again' });
  const username = pending.username;
  const codes = BACKUP_CODES[username] || [];
  const normalized = String(backupCode || '').trim().toUpperCase();
  const key = `${username}:${normalized}`;

  if (!codes.includes(normalized)) return res.status(401).json({ error: 'Invalid backup code' });
  if (usedBackupCodes.has(key)) return res.status(401).json({ error: 'Backup code already used' });

  usedBackupCodes.add(key);
  pendingSessions.delete(pendingToken);
  const user = USERS.find((u) => u.username === username);
  const token = crypto.randomBytes(32).toString('hex');
  completedSessions.set(token, { username: user.username, fullName: user.fullName, role: user.role });
  const remaining = codes.filter((c) => !usedBackupCodes.has(`${username}:${c}`)).length;
  res.json({ token, warning: `Backup code used. ${remaining} backup codes remaining. Re-enroll your authenticator app as soon as possible.` });
});

app.get('/api/backup-codes', requireAuth, (req, res) => {
  const username = req.user.username;
  const codes = BACKUP_CODES[username] || [];
  const remaining = codes.filter((c) => !usedBackupCodes.has(`${username}:${c}`));
  res.json({ codes: remaining });
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

const HTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SecureVault - Hardened TOTP</title>
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
<div id="dashboard" class="card" style="display:none"><div style="background:#dcfce7;border:1px solid #16a34a;color:#166534;padding:.7rem;border-radius:8px;font-size:.84rem;margin-bottom:.8rem">
✅ HARDENED MFA: window:1 (±30 s only). Replay prevention active. 5-attempt lockout.
</div><h3>Your vault</h3><table><thead><tr><th>Site</th><th>Username</th><th>Password</th></tr></thead><tbody id="vault"></tbody></table>
<div id="backup-panel" style="margin-top:1rem"><h4>Backup codes (single use)</h4><pre id="backup-codes"></pre></div>
</div>
<div id="phase1" class="card"><h3>Phase 1 - Password</h3><input id="username" class="login-input" value="alice" placeholder="username"><div style="height:.6rem"></div><input id="password" type="password" class="login-input" value="pass1234" placeholder="password"><div style="height:.8rem"></div><button id="btn-login" class="btn">Continue</button><div id="login-result" class="result"></div></div>
<div id="phase2" class="card" style="display:none"><h3>Phase 2 - Authenticator code</h3><input id="totp-code" class="login-input" placeholder="123456"><div style="height:.8rem"></div><button id="btn-verify" class="btn">Verify</button> <a href="#" id="btn-show-backup">Lost your device? Use a backup code</a><div id="totp-result" class="result"></div>
<div id="backup-entry" style="display:none;margin-top:.7rem"><input id="backup-code" class="login-input" placeholder="VAULT-XXXX"><button id="btn-backup" class="btn">Use backup code</button></div>
<div id="totp-helper" style="margin-top:.75rem;padding:.6rem;background:#fef3c7;border:1px solid #d97706;border-radius:6px;font-size:.82rem;color:#78350f">⚠️ Demo helper: current code for <strong id="helper-username"></strong>: <strong id="helper-code" style="font-family:monospace;font-size:1.1rem;letter-spacing:.15em">------</strong> <span id="helper-timer" style="margin-left:.5rem;color:#92400e"></span></div>
</div></div>
<script>
let pendingToken=null,currentUsername=null,helperInterval=null,lockoutInterval=null,authToken=localStorage.getItem('svToken')||null;
function showResult(id,type,msg){const e=document.getElementById(id);e.className='result '+type;e.textContent=msg;e.style.display='block'}
function startLockoutCountdown(seconds){let r=seconds;showResult('totp-result','failure','🔒 Too many attempts. Locked for '+r+'s');clearInterval(lockoutInterval);lockoutInterval=setInterval(()=>{r--;if(r<=0){clearInterval(lockoutInterval);showResult('totp-result','info','Lockout expired — try again')}else{showResult('totp-result','failure','🔒 Too many attempts. Locked for '+r+'s')}},1000)}
function hidePanels(){document.getElementById('phase1').style.display='none';document.getElementById('phase2').style.display='none';document.getElementById('dashboard').style.display='none';document.getElementById('btn-logout').style.display='none'}
function showLogin(){hidePanels();document.getElementById('phase1').style.display='block';if(helperInterval) clearInterval(helperInterval)}
async function loadDashboard(){if(!authToken){showLogin();return;}const r=await fetch('/api/vault',{headers:{Authorization:'Bearer '+authToken}});if(!r.ok){localStorage.removeItem('svToken');authToken=null;showLogin();return;}const d=await r.json();hidePanels();document.getElementById('dashboard').style.display='block';document.getElementById('btn-logout').style.display='block';document.getElementById('vault').innerHTML=d.map(x=>'<tr><td>'+x.site+'</td><td>'+x.username+'</td><td>'+x.passwordPreview+'</td></tr>').join('');const bc=await fetch('/api/backup-codes',{headers:{Authorization:'Bearer '+authToken}}).then(x=>x.json()).catch(()=>({codes:[]}));document.getElementById('backup-codes').textContent=(bc.codes||[]).length?(bc.codes||[]).join('\\n'):'No backup codes available for this account.'}
function startHelperRefresh(username){document.getElementById('helper-username').textContent=username;if(helperInterval) clearInterval(helperInterval);helperInterval=setInterval(async()=>{try{const r=await fetch('/api/current-totp?username='+encodeURIComponent(username));const d=await r.json();document.getElementById('helper-code').textContent=d.code;document.getElementById('helper-timer').textContent='('+d.secondsRemaining+'s)';}catch(e){}},1000)}
document.getElementById('totp-code').addEventListener('input',function(){const raw=this.value.replace(/\\D/g,'').slice(0,6);this.value=raw.length>3?raw.slice(0,3)+' '+raw.slice(3):raw});
document.getElementById('btn-show-backup').addEventListener('click',function(e){e.preventDefault();document.getElementById('backup-entry').style.display='block';});
document.getElementById('btn-login').addEventListener('click',async function(){try{const username=document.getElementById('username').value;const password=document.getElementById('password').value;const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});const d=await r.json();if(!r.ok)return showResult('login-result','failure','✗ '+d.error);if(d.mfaRequired){pendingToken=d.pendingToken;currentUsername=username;document.getElementById('phase1').style.display='none';document.getElementById('phase2').style.display='block';startHelperRefresh(username);showResult('totp-result','info','Password accepted — enter your 6-digit authenticator code')}else{authToken=d.token;localStorage.setItem('svToken',authToken);loadDashboard()}}catch(e){showResult('login-result','failure','✗ Network error — is the server running?')}});
document.getElementById('btn-verify').addEventListener('click',async function(){const code=document.getElementById('totp-code').value.replace(/\\s/g,'');try{const r=await fetch('/api/verify-totp',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pendingToken,code})});const d=await r.json();if(!r.ok){if(r.status===429){const m=(d.error||'').match(/(\\d+)s/);startLockoutCountdown(m?parseInt(m[1],10):300);return;}return showResult('totp-result','failure','✗ '+d.error);}if(helperInterval) clearInterval(helperInterval);authToken=d.token;localStorage.setItem('svToken',authToken);loadDashboard()}catch(e){showResult('totp-result','failure','✗ '+e.message)}});
document.getElementById('btn-backup').addEventListener('click',async function(){try{const backupCode=document.getElementById('backup-code').value;const r=await fetch('/api/backup-code',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pendingToken,backupCode})});const d=await r.json();if(!r.ok)return showResult('totp-result','failure','✗ '+d.error);if(helperInterval) clearInterval(helperInterval);authToken=d.token;localStorage.setItem('svToken',authToken);showResult('totp-result','info',d.warning||'Backup code accepted');loadDashboard()}catch(e){showResult('totp-result','failure','✗ '+e.message)}});
document.getElementById('btn-logout').addEventListener('click',async()=>{if(authToken){await fetch('/api/logout',{method:'POST',headers:{Authorization:'Bearer '+authToken}}).catch(()=>{})}localStorage.removeItem('svToken');authToken=null;showLogin()});
loadDashboard();
</script></body></html>`;

app.get('/', (_req, res) => res.send(HTML));

app.listen(PORT, () => {
  console.log(`SecureVault (hardened TOTP) running at http://localhost:${PORT}`);
});
