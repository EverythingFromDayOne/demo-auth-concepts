/*
 * Terminal 3: cd auth-concepts/oauth2-oidc && npm run secure
 * ConnectApp + GrantID + GitBucket — state + PKCE (port 3069)
 */

const path = require('path');
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors');

const app = express();
const PORT = 3069;
const BASE = 'http://localhost:' + PORT;

app.use(cors({ origin: 'http://localhost:3068' }));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// ✅ PROTECTED: strong auth server secret
const AUTH_SECRET = crypto.randomBytes(64).toString('hex');

const CLIENTS = {
  connectapp: {
    name: 'ConnectApp',
    clientSecret: 'connectapp-secret',
    redirectUris: ['http://localhost:3069/callback'],
    scopes: ['read:repos', 'read:profile', 'openid', 'email'],
  },
};

const authCodes = new Map();
const accessTokens = new Map();
const sessions = new Map();
const pendingFlows = new Map();

const AUTH_USERS = [
  { id: 1, email: 'alice@example.com', password: 'pass1234', name: 'Alice Chen', avatar: 'AC' },
  { id: 2, email: 'bob@example.com', password: 'qwerty123', name: 'Bob Martinez', avatar: 'BM' },
];

const REPOS = [
  { id: 1, name: 'auth-concepts', description: 'Auth demo project', stars: 42, private: false },
  { id: 2, name: 'api-gateway', description: 'Custom API gateway', stars: 7, private: true },
];

const SCOPE_LABELS = {
  openid: 'Verify your identity',
  email: 'See your email address',
  'read:repos': 'Read access to your GitBucket repositories',
  'read:profile': 'See your profile information',
};

function getSid(req) {
  const raw = req.headers.cookie || '';
  const match = raw.match(/(?:^|;\s*)connect_session=([^;]+)/);
  return match ? match[1] : null;
}

function b64Decode(str) {
  try {
    return JSON.parse(Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());
  } catch (e) {
    return {};
  }
}

function AUTHORIZE_HTML(opts) {
  const scopes = (opts.requestedScopes || []).filter(Boolean);
  const scopeList = scopes.map(function (s) {
    return '<li style="margin-bottom:0.5rem"><code style="color:#a78bfa">' + s + '</code> — ' + (SCOPE_LABELS[s] || s) + '</li>';
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Authorize — GrantID</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #e2e8f0; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 2rem; }
.card { background: #16213e; border: 1px solid #334155; border-radius: 12px; padding: 2rem; width: 100%; max-width: 440px; }
.logo { font-size: 1.5rem; font-weight: 700; color: #7c3aed; margin-bottom: 0.25rem; }
.safe { background: #052e16; border: 1px solid #16a34a; color: #86efac; padding: 0.75rem; border-radius: 6px; font-size: 0.8rem; margin-bottom: 1rem; }
ul { margin: 0 0 1.5rem 1.25rem; font-size: 0.88rem; }
label { display: block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.35rem; }
.login-input { width: 100%; padding: 0.65rem; border: 1px solid #475569; border-radius: 6px; background: #0f172a; color: #e2e8f0; margin-bottom: 0.85rem; font-family: inherit; }
.btn { width: 100%; padding: 0.75rem; background: #7c3aed; color: #fff; border: none; border-radius: 6px; font-weight: 600; cursor: pointer; }
</style></head>
<body><div class="card">
<div class="logo">GrantID</div>
<h2 style="margin:1rem 0"><strong>${opts.clientName}</strong> wants to access your GitBucket account</h2>
<div class="safe">✅ state + PKCE verified on this hardened server</div>
<ul>${scopeList}</ul>
<form method="POST" action="/auth/approve">
<input type="hidden" name="client_id" value="${opts.clientId}">
<input type="hidden" name="redirect_uri" value="${opts.redirectUri}">
<input type="hidden" name="scope" value="${opts.scope}">
<input type="hidden" name="state" value="${opts.state}">
<input type="hidden" name="code_challenge" value="${opts.codeChallenge || ''}">
<input type="hidden" name="code_challenge_method" value="${opts.codeChallengeMethod || ''}">
<label>Email</label><input class="login-input" name="username" type="email" value="alice@example.com" required>
<label>Password</label><input class="login-input" name="password" type="password" value="pass1234" required>
<button class="btn" type="submit">Approve access</button>
</form></div></body></html>`;
}

app.get('/auth/authorize', function (req, res) {
  const clientId = req.query.client_id;
  const redirectUri = req.query.redirect_uri;
  const scope = req.query.scope || '';
  const responseType = req.query.response_type;
  const state = req.query.state || '';
  const codeChallenge = req.query.code_challenge || '';
  const codeChallengeMethod = req.query.code_challenge_method || '';
  const client = CLIENTS[clientId];

  if (!client) return res.status(400).send('Unknown client_id: ' + clientId);
  if (!client.redirectUris.includes(redirectUri)) return res.status(400).send('redirect_uri not registered');
  if (responseType !== 'code') return res.status(400).send('Only response_type=code supported');

  // ✅ PROTECTED: state required for hardened flow
  if (!state) return res.status(400).send('state parameter required');

  // SSR required: OAuth params injected into hidden form fields
  res.send(AUTHORIZE_HTML({
    clientName: client.name,
    scope: scope,
    requestedScopes: scope.split(' '),
    redirectUri: redirectUri,
    clientId: clientId,
    state: state,
    codeChallenge: codeChallenge,
    codeChallengeMethod: codeChallengeMethod,
  }));
});

app.post('/auth/approve', function (req, res) {
  const username = req.body.username;
  const password = req.body.password;
  const clientId = req.body.client_id;
  const redirectUri = req.body.redirect_uri;
  const scope = req.body.scope || '';
  const state = req.body.state || '';

  const user = AUTH_USERS.find(function (u) {
    return u.email === username && u.password === password;
  });

  if (!user) {
    return res.redirect(
      '/auth/authorize?error=access_denied&client_id=' + encodeURIComponent(clientId) +
      '&redirect_uri=' + encodeURIComponent(redirectUri) + '&scope=' + encodeURIComponent(scope) +
      '&state=' + encodeURIComponent(state) + '&response_type=code' +
      '&code_challenge=' + encodeURIComponent(req.body.code_challenge || '') +
      '&code_challenge_method=' + encodeURIComponent(req.body.code_challenge_method || '')
    );
  }

  const code = crypto.randomBytes(16).toString('hex');
  authCodes.set(code, {
    clientId: clientId,
    userId: user.id,
    scope: scope,
    redirectUri: redirectUri,
    codeChallenge: req.body.code_challenge || null,
    codeChallengeMethod: req.body.code_challenge_method || null,
    expiresAt: Date.now() + 60000,
  });

  const callbackUrl = redirectUri + '?code=' + code + '&state=' + encodeURIComponent(state);
  console.log('[Auth] Code issued (PKCE) for ' + user.email);
  res.redirect(callbackUrl);
});

app.post('/auth/token', function (req, res) {
  const grantType = req.body.grant_type;
  const code = req.body.code;
  const clientId = req.body.client_id;
  const clientSecret = req.body.client_secret;
  const codeVerifier = req.body.code_verifier;

  if (grantType !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  const client = CLIENTS[clientId];
  if (!client || client.clientSecret !== clientSecret) {
    return res.status(401).json({ error: 'invalid_client' });
  }

  const authCode = authCodes.get(code);
  if (!authCode || authCode.expiresAt < Date.now() || authCode.clientId !== clientId) {
    return res.status(400).json({ error: 'invalid_grant' });
  }

  // ✅ PROTECTED: PKCE verification
  if (authCode.codeChallenge) {
    if (!codeVerifier) {
      return res.status(400).json({ error: 'invalid_grant', detail: 'code_verifier required' });
    }
    const expected = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    if (expected !== authCode.codeChallenge) {
      return res.status(400).json({ error: 'invalid_grant', detail: 'code_verifier mismatch' });
    }
  }

  authCodes.delete(code);

  const user = AUTH_USERS.find(function (u) { return u.id === authCode.userId; });
  const scopes = authCode.scope.split(' ').filter(Boolean);

  const accessToken = crypto.randomBytes(32).toString('hex');
  accessTokens.set(accessToken, {
    userId: user.id,
    scope: authCode.scope,
    expiresAt: Date.now() + 3600000,
  });

  const response = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: authCode.scope,
  };

  if (scopes.includes('openid')) {
    response.id_token = jwt.sign({
      iss: BASE + '/auth',
      sub: String(user.id),
      aud: clientId,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      email: scopes.includes('email') ? user.email : undefined,
      name: user.name,
    }, AUTH_SECRET, { algorithm: 'HS256' });
  }

  res.json(response);
});

function requireAccessToken(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const stored = accessTokens.get(token);
  if (!stored || stored.expiresAt < Date.now()) {
    return res.status(401).json({ error: 'invalid_token' });
  }
  req.tokenInfo = stored;
  req.user = AUTH_USERS.find(function (u) { return u.id === stored.userId; });
  next();
}

app.get('/api/repos', requireAccessToken, function (req, res) {
  if (!req.tokenInfo.scope.includes('read:repos')) {
    return res.status(403).json({ error: 'insufficient_scope', required: 'read:repos' });
  }
  res.json(REPOS.map(function (r) { return { ...r, owner: req.user.email }; }));
});

app.get('/api/user/profile', requireAccessToken, function (req, res) {
  res.json({ id: req.user.id, email: req.user.email, name: req.user.name, avatar: req.user.avatar });
});

app.get('/', function (req, res) {
  if (sessions.get(getSid(req))) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ✅ PROTECTED: generate state + PKCE challenge
app.get('/connect', function (req, res) {
  const state = crypto.randomBytes(16).toString('hex');
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

  pendingFlows.set(state, { codeVerifier: codeVerifier, createdAt: Date.now() });

  const authUrl = BASE + '/auth/authorize?' +
    'client_id=connectapp&' +
    'redirect_uri=' + encodeURIComponent(BASE + '/callback') + '&' +
    'scope=read:repos+read:profile+openid+email&' +
    'response_type=code&' +
    'state=' + state + '&' +
    'code_challenge=' + codeChallenge + '&' +
    'code_challenge_method=S256';

  res.redirect(authUrl);
});

app.get('/callback', async function (req, res) {
  const code = req.query.code;
  const state = req.query.state;
  const pending = pendingFlows.get(state);

  // ✅ PROTECTED: verify state
  if (!pending) {
    return res.status(400).send(
      'Invalid or missing state parameter — possible CSRF attack. <a href="/">Start over</a>'
    );
  }
  pendingFlows.delete(state);

  if (!code) return res.status(400).send('No code received');

  try {
    const tokenRes = await fetch(BASE + '/auth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: BASE + '/callback',
        client_id: 'connectapp',
        client_secret: 'connectapp-secret',
        code_verifier: pending.codeVerifier,
      }),
    });
    const tokens = await tokenRes.json();
    if (!tokenRes.ok) return res.status(400).send('Token exchange failed: ' + JSON.stringify(tokens));

    const profileRes = await fetch(BASE + '/api/user/profile', {
      headers: { Authorization: 'Bearer ' + tokens.access_token },
    });
    const profile = await profileRes.json();

    const sid = crypto.randomBytes(32).toString('hex');
    sessions.set(sid, {
      profile: profile,
      accessToken: tokens.access_token,
      idToken: tokens.id_token,
    });
    res.setHeader('Set-Cookie', 'connect_session=' + sid + '; Path=/; HttpOnly; SameSite=Lax');
    res.redirect('/dashboard');
  } catch (err) {
    res.status(500).send('Callback failed: ' + err.message);
  }
});

app.get('/dashboard', function (req, res) {
  const session = sessions.get(getSid(req));
  if (!session) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/config', function (_req, res) {
  res.json({ mode: 'secure', port: PORT });
});

app.get('/api/me', async function (req, res) {
  const session = sessions.get(getSid(req));
  if (!session) return res.status(401).json({ error: 'Not authenticated' });

  const idClaims = session.idToken ? b64Decode(session.idToken.split('.')[1]) : {};
  const tokenInfo = accessTokens.get(session.accessToken);

  let repos = [];
  try {
    const reposRes = await fetch(BASE + '/api/repos', {
      headers: { Authorization: 'Bearer ' + session.accessToken },
    });
    if (reposRes.ok) repos = await reposRes.json();
  } catch (e) {}

  res.json({
    profile: session.profile,
    username: session.profile.email,
    email: session.profile.email,
    scope: tokenInfo ? tokenInfo.scope : '',
    accessToken: session.accessToken,
    accessTokenPreview: session.accessToken.substring(0, 8) + '...',
    idToken: session.idToken,
    idClaims: idClaims,
    repos: repos,
  });
});

app.post('/api/disconnect', function (req, res) {
  const sid = getSid(req);
  if (sid) sessions.delete(sid);
  res.setHeader('Set-Cookie', 'connect_session=; Path=/; Max-Age=0');
  res.json({ message: 'Disconnected — GitBucket access revoked from ConnectApp' });
});

app.listen(PORT, function () {
  console.log('ConnectApp + GrantID (hardened — state + PKCE) running at http://localhost:' + PORT);
});
