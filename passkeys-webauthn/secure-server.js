/*
 * CloudPortal (hardened WebAuthn) - port 3075
 */
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
const PORT = 3075;

app.use(cors({ origin: 'http://localhost:3074' }));
app.use(express.json());

const USERS = [
  { username: 'alice', password: 'pass1234', fullName: 'Alice Chen', role: 'user' },
  { username: 'bob', password: 'qwerty123', fullName: 'Bob Martinez', role: 'user' },
  { username: 'admin', password: 'admin456', fullName: 'Admin User', role: 'admin' },
];

const sessions = new Map();
const credentialStore = new Map();
const registrationChallenges = new Map();
const authChallenges = new Map();

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const session = sessions.get(token);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });
  req.user = session;
  req.token = token;
  next();
}

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = USERS.find((u) => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username: user.username, fullName: user.fullName, role: user.role });
  res.json({ token, hasPasskey: credentialStore.has(user.username) });
});

app.post('/api/logout', requireAuth, (req, res) => {
  sessions.delete(req.token);
  res.json({ message: 'Logged out' });
});

app.get('/api/me', requireAuth, (req, res) => {
  const cred = credentialStore.get(req.user.username);
  res.json({
    username: req.user.username,
    fullName: req.user.fullName,
    role: req.user.role,
    hasPasskey: !!cred,
    authenticatorCounter: cred ? cred.counter : 0,
  });
});

app.get('/api/resources', requireAuth, (req, res) => {
  res.json([
    { id: 'vm-001', name: 'prod-api-01', type: 'Compute Instance', region: 'us-east-1', status: 'running' },
    { id: 'db-002', name: 'primary-db', type: 'Database', region: 'us-east-1', status: 'running' },
    { id: 's3-003', name: 'assets-bucket', type: 'Object Storage', region: 'us-west-2', status: 'active' },
  ]);
});

app.get('/api/register/begin', requireAuth, async (req, res) => {
  const { username, fullName } = req.user;
  const existingCred = credentialStore.get(username);
  const excludeCredentials = existingCred
    ? [{ id: existingCred.credentialID, type: 'public-key', transports: existingCred.transports }]
    : [];

  const options = await generateRegistrationOptions({
    rpName: 'CloudPortal',
    rpID: 'localhost',
    // ✅ PROTECTED: opaque ID
    userID: Buffer.from(crypto.randomUUID()),
    userName: username,
    userDisplayName: fullName,
    attestationType: 'none',
    excludeCredentials,
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      residentKey: 'preferred',
      // ✅ PROTECTED: UV required
      userVerification: 'required',
    },
    timeout: 60000,
  });

  registrationChallenges.set(username, {
    challenge: options.challenge,
    expiresAt: Date.now() + 5 * 60 * 1000,
  });
  res.json(options);
});

app.post('/api/register/complete', requireAuth, async (req, res) => {
  const { username } = req.user;
  const stored = registrationChallenges.get(username);
  if (!stored) return res.status(400).json({ error: 'No pending registration' });
  if (Date.now() > stored.expiresAt) {
    registrationChallenges.delete(username);
    return res.status(400).json({ error: 'Registration challenge expired — start again' });
  }

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: stored.challenge,
      expectedOrigin: 'http://localhost:3075',
      expectedRPID: 'localhost',
      requireUserVerification: true,
    });
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  if (!verification.verified) return res.status(400).json({ error: 'Registration verification failed' });

  registrationChallenges.delete(username);
  const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
  credentialStore.set(username, {
    credentialID,
    credentialPublicKey,
    counter,
    transports: req.body.response?.transports || [],
  });
  res.json({ verified: true, credentialID: Buffer.from(credentialID).toString('base64url') });
});

app.post('/api/auth/begin', async (_req, res) => {
  const options = await generateAuthenticationOptions({
    rpID: 'localhost',
    userVerification: 'required',
    timeout: 60000,
  });

  const challengeKey = crypto.randomBytes(16).toString('hex');
  authChallenges.set(challengeKey, { challenge: options.challenge, expiresAt: Date.now() + 5 * 60 * 1000 });
  res.json({ ...options, challengeKey });
});

app.post('/api/auth/complete', async (req, res) => {
  const { challengeKey, ...assertionBody } = req.body;
  const stored = authChallenges.get(challengeKey);
  if (!stored) return res.status(400).json({ error: 'No pending authentication' });
  if (Date.now() > stored.expiresAt) {
    authChallenges.delete(challengeKey);
    return res.status(400).json({ error: 'Authentication challenge expired — try again' });
  }
  // ✅ PROTECTED: single-use challenge
  authChallenges.delete(challengeKey);

  let foundUsername = null;
  let cred = null;
  for (const [username, c] of credentialStore.entries()) {
    if (Buffer.from(c.credentialID).toString('base64url') === assertionBody.id) {
      foundUsername = username;
      cred = c;
      break;
    }
  }
  if (!cred) return res.status(400).json({ error: 'Credential not found — register a passkey first' });

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: assertionBody,
      expectedChallenge: stored.challenge,
      expectedOrigin: 'http://localhost:3075',
      expectedRPID: 'localhost',
      authenticator: {
        credentialID: cred.credentialID,
        credentialPublicKey: cred.credentialPublicKey,
        counter: cred.counter,
        transports: cred.transports,
      },
      requireUserVerification: true,
    });
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }
  if (!verification.verified) return res.status(400).json({ error: 'Authentication failed' });

  const prev = cred.counter;
  cred.counter = verification.authenticationInfo.newCounter;
  if (verification.authenticationInfo.newCounter > 0 && verification.authenticationInfo.newCounter <= prev) {
    console.warn(`[SECURITY] Counter anomaly for ${foundUsername}: ${prev} -> ${verification.authenticationInfo.newCounter}`);
  }

  const user = USERS.find((u) => u.username === foundUsername);
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username: user.username, fullName: user.fullName, role: user.role });
  res.json({ token, username: user.username, fullName: user.fullName, authenticatorCounter: cred.counter });
});

const HTML = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>CloudPortal Hardened WebAuthn</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8fafc;color:#0f172a}
.top{background:#0f172a;color:#fff;padding:1rem 1.25rem;display:flex;justify-content:space-between;align-items:center}
.wrap{max-width:1000px;margin:0 auto;padding:1rem}.card{background:#fff;border:1px solid #dbeafe;border-radius:10px;padding:1rem;margin-bottom:1rem}
.safe{background:#dcfce7;border:1px solid #16a34a;color:#166534;padding:.6rem;border-radius:6px;font-size:.84rem}
.login-input{width:100%;padding:.6rem .75rem;border:1px solid #cbd5e1;border-radius:6px;font-size:.95rem;color:#0f172a;background:#fff;outline:none;box-sizing:border-box;font-family:inherit}
.login-input:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.15)} .passkey-btn{width:100%;padding:.75rem;background:#3b82f6;color:#fff;border:none;border-radius:8px;font-size:1rem;font-weight:600;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:.5rem}.passkey-btn:hover{background:#2563eb}
.btn{padding:.6rem .9rem;border:0;border-radius:6px;background:#3b82f6;color:#fff;cursor:pointer}.btn.out{background:#334155}
.result{display:none;margin-top:.6rem;padding:.55rem .75rem;border-radius:6px;font-size:.84rem}.result.failure{background:#fee2e2;color:#991b1b;border:1px solid #fca5a5}.result.success{background:#dcfce7;color:#166534;border:1px solid #86efac}.result.info{background:#dbeafe;color:#1e3a8a;border:1px solid #93c5fd}
table{width:100%;border-collapse:collapse}th,td{padding:.6rem;border-bottom:1px solid #dbeafe;text-align:left}
</style></head><body>
<div class="top"><div><strong>CloudPortal</strong> — Manage your cloud resources</div><button id="btn-logout" class="btn out" style="display:none">Logout</button></div>
<div class="wrap">
<div id="login" class="card">
<div class="safe">✅ HARDENED WEBAUTHN: User verification required. Your biometric is always prompted. Challenge is single-use and expires in 5 minutes.</div>
<h3 style="margin:.8rem 0">Sign in with Passkey</h3>
<button id="btn-passkey-login" class="passkey-btn">🔑 Sign in with Passkey</button>
<div id="auth-result" class="result"></div>
<hr style="margin:1rem 0;border:0;border-top:1px solid #e2e8f0">
<h3 style="margin:.3rem 0 .7rem">Sign in with password</h3>
<input id="username" class="login-input" value="alice"><div style="height:.6rem"></div>
<input id="password" class="login-input" type="password" value="pass1234"><div style="height:.8rem"></div>
<button id="btn-login" class="btn">Continue</button><div id="login-result" class="result"></div>
</div>
<div id="dashboard" class="card" style="display:none">
<h3>Cloud Resources</h3>
<div id="passkey-panel"></div>
<table><thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Region</th><th>Status</th></tr></thead><tbody id="resources"></tbody></table>
</div>
</div>
<script>
function showResult(id,type,msg){const e=document.getElementById(id);e.className='result '+type;e.textContent=msg;e.style.display='block'}
function base64urlToBuffer(base64url){const base64=base64url.replace(/-/g,'+').replace(/_/g,'/');const padded=base64.padEnd(base64.length+(4-base64.length%4)%4,'=');const binary=atob(padded);const bytes=new Uint8Array(binary.length);for(let i=0;i<binary.length;i++)bytes[i]=binary.charCodeAt(i);return bytes.buffer}
function bufferToBase64url(buffer){const bytes=new Uint8Array(buffer);let binary='';for(let i=0;i<bytes.byteLength;i++)binary+=String.fromCharCode(bytes[i]);return btoa(binary).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=/g,'')}
function prepareRegistrationOptions(o){return {...o,challenge:base64urlToBuffer(o.challenge),user:{...o.user,id:base64urlToBuffer(o.user.id)},excludeCredentials:(o.excludeCredentials||[]).map(c=>({...c,id:base64urlToBuffer(c.id)}))}}
function prepareAuthOptions(o){return {...o,challenge:base64urlToBuffer(o.challenge),allowCredentials:(o.allowCredentials||[]).map(c=>({...c,id:base64urlToBuffer(c.id)}))}}
function serializeRegistrationCredential(c){return{id:c.id,rawId:bufferToBase64url(c.rawId),type:c.type,response:{clientDataJSON:bufferToBase64url(c.response.clientDataJSON),attestationObject:bufferToBase64url(c.response.attestationObject)}}}
function serializeAuthCredential(c){return{id:c.id,rawId:bufferToBase64url(c.rawId),type:c.type,response:{clientDataJSON:bufferToBase64url(c.response.clientDataJSON),authenticatorData:bufferToBase64url(c.response.authenticatorData),signature:bufferToBase64url(c.response.signature),userHandle:c.response.userHandle?bufferToBase64url(c.response.userHandle):null}}}
let token=localStorage.getItem('cpToken')||null;
if(!window.PublicKeyCredential){document.getElementById('btn-passkey-login').disabled=true;document.getElementById('btn-passkey-login').title='WebAuthn not supported';showResult('auth-result','info','ℹ️ WebAuthn not available — use password login below');}
async function loadDashboard(){if(!token){document.getElementById('login').style.display='block';document.getElementById('dashboard').style.display='none';document.getElementById('btn-logout').style.display='none';return;}const meRes=await fetch('/api/me',{headers:{Authorization:'Bearer '+token}});if(!meRes.ok){token=null;localStorage.removeItem('cpToken');return loadDashboard();}const me=await meRes.json();const rs=await fetch('/api/resources',{headers:{Authorization:'Bearer '+token}});const data=await rs.json();document.getElementById('resources').innerHTML=data.map(r=>'<tr><td>'+r.id+'</td><td>'+r.name+'</td><td>'+r.type+'</td><td>'+r.region+'</td><td>'+r.status+'</td></tr>').join('');document.getElementById('login').style.display='none';document.getElementById('dashboard').style.display='block';document.getElementById('btn-logout').style.display='block';document.getElementById('passkey-panel').innerHTML=me.hasPasskey?'<div style="background:#ecfdf5;border:1px solid #16a34a;color:#166534;padding:.6rem;border-radius:6px;font-size:.84rem;margin:.7rem 0">✅ Passkey active. Authenticator counter: <strong>'+me.authenticatorCounter+'</strong></div>':'<div style="background:#fef3c7;border:1px solid #d97706;color:#78350f;padding:.7rem;border-radius:6px;font-size:.84rem;margin:.7rem 0">🔑 Secure your account with a Passkey<br><button id="btn-register-passkey" class="btn" style="margin-top:.55rem">Register Passkey</button><div id="passkey-result" class="result"></div></div>';const regBtn=document.getElementById('btn-register-passkey');if(regBtn){regBtn.addEventListener('click',registerPasskey);}}
async function registerPasskey(){try{var optRes=await fetch('/api/register/begin',{headers:{Authorization:'Bearer '+token}});var serverOptions=await optRes.json();if(!optRes.ok)return showResult('passkey-result','failure','✗ '+serverOptions.error);let credential;try{credential=await navigator.credentials.create({publicKey:prepareRegistrationOptions(serverOptions)})}catch(e){if(e.name==='NotAllowedError')return showResult('passkey-result','failure','✗ Registration cancelled or timed out');return showResult('passkey-result','failure','✗ '+e.message)}var verRes=await fetch('/api/register/complete',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+token},body:JSON.stringify(serializeRegistrationCredential(credential))});var verData=await verRes.json();if(!verRes.ok)return showResult('passkey-result','failure','✗ '+verData.error);showResult('passkey-result','success','✅ Passkey registered!');setTimeout(loadDashboard,1200);}catch(e){showResult('passkey-result','failure','✗ '+e.message)}}
document.getElementById('btn-passkey-login').addEventListener('click',async function(){try{var optRes=await fetch('/api/auth/begin',{method:'POST',headers:{'Content-Type':'application/json'}});var serverOptions=await optRes.json();if(!optRes.ok)return showResult('auth-result','failure','✗ '+serverOptions.error);var challengeKey=serverOptions.challengeKey;let assertion;try{assertion=await navigator.credentials.get({publicKey:prepareAuthOptions(serverOptions)})}catch(e){if(e.name==='NotAllowedError')return showResult('auth-result','failure','✗ Authentication cancelled or timed out');return showResult('auth-result','failure','✗ '+e.message)}var authRes=await fetch('/api/auth/complete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({challengeKey,...serializeAuthCredential(assertion)})});var authData=await authRes.json();if(!authRes.ok)return showResult('auth-result','failure','✗ '+authData.error);token=authData.token;localStorage.setItem('cpToken',token);loadDashboard();}catch(e){showResult('auth-result','failure','✗ '+e.message)}});
document.getElementById('btn-login').addEventListener('click',async function(){try{const username=document.getElementById('username').value;const password=document.getElementById('password').value;const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});const d=await r.json();if(!r.ok)return showResult('login-result','failure','✗ '+d.error);token=d.token;localStorage.setItem('cpToken',token);loadDashboard()}catch(e){showResult('login-result','failure','✗ '+e.message)}});
document.getElementById('btn-logout').addEventListener('click',async()=>{if(token){await fetch('/api/logout',{method:'POST',headers:{Authorization:'Bearer '+token}}).catch(()=>{})}token=null;localStorage.removeItem('cpToken');loadDashboard()});
loadDashboard();
</script></body></html>`;

app.get('/', (_req, res) => res.send(HTML));

app.listen(PORT, () => {
  console.log(`CloudPortal (hardened WebAuthn) running at http://localhost:${PORT}`);
});
