/*
 * Terminal 3: cd auth-concepts/magic-links && npm run secure
 * Inkwell — hardened magic links (port 3078)
 */

const express = require('express');
const crypto = require('crypto');

const app = express();
const PORT = 3078;

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const USER_PROFILES = {
  'alice@example.com': {
    name: 'Alice Chen',
    plan: 'Pro',
    posts: [
      { id: 1, title: 'Getting started with web security', status: 'published', views: 1240 },
      { id: 2, title: 'Why passwords keep failing us', status: 'published', views: 892 },
      { id: 3, title: 'A guide to passkeys', status: 'draft', views: 0 },
    ],
  },
  'bob@example.com': {
    name: 'Bob Martinez',
    plan: 'Free',
    posts: [
      { id: 4, title: 'My first post on Inkwell', status: 'published', views: 47 },
    ],
  },
};

function getProfile(email) {
  return USER_PROFILES[email] || {
    name: email.split('@')[0],
    plan: 'Free',
    posts: [],
  };
}

const sessions = new Map();

// ✅ PROTECTED: expiresAt enforced, single-use via delete on verify
const magicTokens = new Map();

setInterval(function () {
  const now = Date.now();
  for (const entry of magicTokens.entries()) {
    if (now > entry[1].expiresAt) magicTokens.delete(entry[0]);
  }
}, 10 * 60 * 1000);

const sendRateLimit = new Map();
const MAX_PER_HOUR = 3;
const WINDOW_MS = 60 * 60 * 1000;

function isRateLimited(email) {
  const now = Date.now();
  const state = sendRateLimit.get(email) || { count: 0, windowStart: now };

  if (now - state.windowStart > WINDOW_MS) {
    state.count = 0;
    state.windowStart = now;
  }

  if (state.count >= MAX_PER_HOUR) {
    sendRateLimit.set(email, state);
    return true;
  }

  state.count++;
  sendRateLimit.set(email, state);
  return false;
}

// ✅ PROTECTED: crypto.randomBytes(32) — 256 bits of CSPRNG entropy
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function requireAuth(req, res, next) {
  const raw = req.headers.cookie || '';
  const match = raw.match(/(?:^|;\s*)iw_session=([^;]+)/);
  const sid = match ? match[1] : null;
  const session = sid ? sessions.get(sid) : null;
  if (!session) return res.redirect('/?error=not_authenticated');
  req.session = session;
  req.sessionId = sid;
  next();
}

function DASHBOARD_HTML(email, profile) {
  const postsHtml = profile.posts.length === 0
    ? '<p style="color:#78716c">No posts yet. Start writing!</p>'
    : '<table style="width:100%;border-collapse:collapse;font-size:0.9rem">' +
      '<thead><tr style="border-bottom:2px solid #e7e5e4">' +
      '<th style="text-align:left;padding:0.6rem;color:#78716c">Title</th>' +
      '<th style="text-align:left;padding:0.6rem;color:#78716c">Status</th>' +
      '<th style="text-align:right;padding:0.6rem;color:#78716c">Views</th></tr></thead><tbody>' +
      profile.posts.map(function (p) {
        return '<tr style="border-bottom:1px solid #f5f5f4">' +
          '<td style="padding:0.75rem;color:#1c1917">' + p.title + '</td>' +
          '<td style="padding:0.75rem;color:#57534e">' + p.status + '</td>' +
          '<td style="padding:0.75rem;text-align:right;color:#78716c">' + p.views + '</td></tr>';
      }).join('') +
      '</tbody></table>';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="referrer" content="no-referrer">
  <title>Dashboard — Inkwell</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #fafaf9; color: #1c1917; min-height: 100vh; }
    .top-banner { background: #f0fdf4; border-bottom: 1px solid #16a34a; color: #15803d; padding: 0.65rem 1.5rem; font-size: 0.82rem; }
    header { background: #1c1917; color: #fafaf9; padding: 1rem 2rem; display: flex; align-items: center; gap: 1rem; }
    header .logo { font-size: 1.1rem; font-weight: 600; }
    header .plan { margin-left: auto; font-size: 0.8rem; color: #a8a29e; }
  </style>
</head>
<body>
  <div class="top-banner">
    ✅ HARDENED MAGIC LINKS: 256-bit token. Expires in 15 minutes. Single-use.
    Try clicking your magic link a second time — it will say "Link already used or expired."
  </div>
  <header>
    <span class="logo">Inkwell 🖊️ — ${profile.name || email}</span>
    <span class="plan">${profile.plan} plan · ${email}</span>
    <button id="btn-logout" style="background:#e7470a;color:#fff;border:none;padding:0.4rem 0.85rem;border-radius:6px;cursor:pointer;font-size:0.8rem;font-weight:600">Sign out</button>
  </header>
  <main style="max-width:900px;margin:2rem auto;padding:0 1.5rem">
    <h2 style="font-size:1.1rem;margin-bottom:1rem;color:#292524">Your posts</h2>
    ${postsHtml}
  </main>
  <script>
    document.getElementById('btn-logout').addEventListener('click', async function() {
      await fetch('/api/logout', { method: 'POST' });
      window.location.href = '/';
    });
  </script>
</body>
</html>`;
}

const LOGIN_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In — Inkwell</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #fafaf9; color: #1c1917; min-height: 100vh; }
    .safe-top { background: #f0fdf4; border-bottom: 2px solid #16a34a; color: #15803d; padding: 0.65rem 1.5rem; font-size: 0.82rem; text-align: center; }
    .login-input {
      width: 100%; padding: 0.7rem 0.85rem; border: 1.5px solid #d6d3d1;
      border-radius: 8px; font-size: 0.95rem; color: #1c1917;
      background: #fafaf9; outline: none; box-sizing: border-box; font-family: inherit;
      margin-bottom: 0.75rem; display: block;
    }
    .login-input:focus { border-color: #e7470a; box-shadow: 0 0 0 3px rgba(231,71,10,0.12); }
    .send-btn {
      width: 100%; padding: 0.75rem; background: #e7470a; color: #fff;
      border: none; border-radius: 8px; font-size: 1rem; font-weight: 600;
      cursor: pointer; transition: background 0.15s;
    }
    .send-btn:hover { background: #c53d08; }
    .send-btn:disabled { opacity: 0.6; cursor: not-allowed; }
    .result-banner { padding: 0.65rem 1rem; border-radius: 6px; font-size: 0.85rem; margin-top: 0.75rem; display: none; }
    .result-banner.success { background: #f0fdf4; border: 1px solid #86efac; color: #15803d; }
    .result-banner.failure { background: #fef2f2; border: 1px solid #fca5a5; color: #b91c1c; }
    .rate-note { font-size: 0.75rem; color: #78716c; margin-top: 1rem; line-height: 1.5; }
  </style>
</head>
<body>
  <div class="safe-top">
    ✅ HARDENED: 256-bit crypto.randomBytes token. 15-minute expiry. Single-use. Rate limited to 3/hour.
  </div>
  <div style="max-width:400px;margin:6rem auto;padding:2rem;background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,0.08)">
    <div style="text-align:center;margin-bottom:2rem">
      <div style="font-size:2rem">🖊️</div>
      <h1 style="margin:0.5rem 0 0.25rem;font-size:1.5rem;color:#1c1917">Inkwell</h1>
      <p style="color:#78716c;margin:0;font-size:0.9rem">Write, publish, share.</p>
    </div>
    <p style="color:#57534e;font-size:0.9rem;margin-bottom:1.25rem">
      Enter your email to receive a sign-in link. No password needed.
    </p>
    <input class="login-input" id="email-input" type="email" placeholder="you@example.com" autofocus>
    <button class="send-btn" id="btn-send">Send Magic Link</button>
    <div class="result-banner" id="send-result"></div>
    <div id="demo-link-panel" style="display:none;margin-top:1.5rem;padding:1rem;background:#f0fdf4;border:1px solid #16a34a;border-radius:8px;font-size:0.82rem;color:#15803d">
      <strong>⚠️ Demo mode:</strong> Your magic link (normally emailed):<br>
      <a id="demo-link-anchor" href="#" style="color:#166534;word-break:break-all;font-family:monospace;font-size:0.78rem"></a>
      <br>
      <span id="expiry-timer" style="font-size:0.75rem;color:#92400e;display:block;margin-top:0.5rem">⏱ Expires in <strong id="expiry-seconds">900</strong>s</span>
      <br>
      <button id="btn-open-link" style="background:#16a34a;color:#fff;border:none;padding:0.4rem 0.8rem;border-radius:4px;cursor:pointer;font-size:0.8rem">Open Link →</button>
      <button id="btn-open-link-again" style="margin-left:0.5rem;background:#15803d;color:#fff;border:none;padding:0.4rem 0.8rem;border-radius:4px;cursor:pointer;font-size:0.8rem">Open Again (replay test) →</button>
    </div>
    <p class="rate-note">Demo: after 3 sends per hour, further sends are silently dropped (same success message, no link).</p>
    <div id="error-banner" style="display:none;margin-top:1rem;padding:0.75rem;background:#fef2f2;border:1px solid #fca5a5;border-radius:6px;color:#b91c1c;font-size:0.85rem"></div>
  </div>
  <script>
    function showResult(id, type, msg) {
      var el = document.getElementById(id);
      el.className = 'result-banner ' + type;
      el.textContent = msg;
      el.style.display = 'block';
    }

    (function() {
      var params = new URLSearchParams(window.location.search);
      var error = params.get('error');
      if (error) {
        var messages = {
          invalid_token: 'This link is invalid or has already been used.',
          missing_token: 'No token found in this link.',
          not_authenticated: 'Please sign in to continue.',
          link_expired: 'This link has expired. Request a new one.',
        };
        var el = document.getElementById('error-banner');
        el.textContent = messages[error] || 'Something went wrong — try again.';
        el.style.display = 'block';
      }
    })();

    var currentDemoLink = null;
    var timerInterval = null;

    function startExpiryTimer() {
      var expirySeconds = 900;
      if (timerInterval) clearInterval(timerInterval);
      document.getElementById('expiry-seconds').textContent = expirySeconds;
      timerInterval = setInterval(function() {
        expirySeconds--;
        var el = document.getElementById('expiry-seconds');
        if (el) el.textContent = expirySeconds;
        if (expirySeconds <= 0) {
          clearInterval(timerInterval);
          showResult('send-result', 'failure', '⏱ Link expired — request a new one');
          document.getElementById('demo-link-panel').style.display = 'none';
        }
      }, 1000);
    }

    document.getElementById('btn-send').addEventListener('click', async function() {
      var email = document.getElementById('email-input').value.trim();
      if (!email) return;
      this.disabled = true;
      this.textContent = 'Sending...';
      try {
        var r = await fetch('/api/auth/send-link', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: email }),
        });
        var d = await r.json();
        if (!r.ok) {
          showResult('send-result', 'failure', '✗ ' + d.error);
        } else {
          showResult('send-result', 'success', '✅ ' + d.message);
          if (d.demoLink) {
            currentDemoLink = d.demoLink;
            document.getElementById('demo-link-anchor').href = d.demoLink;
            document.getElementById('demo-link-anchor').textContent = d.demoLink;
            document.getElementById('demo-link-panel').style.display = 'block';
            startExpiryTimer();
          } else {
            document.getElementById('demo-link-panel').style.display = 'none';
          }
        }
      } catch (e) {
        showResult('send-result', 'failure', '✗ Network error — is the server running?');
      }
      this.disabled = false;
      this.textContent = 'Send Magic Link';
    });

    document.getElementById('btn-open-link').addEventListener('click', function() {
      if (currentDemoLink) window.location.href = currentDemoLink;
    });

    document.getElementById('btn-open-link-again').addEventListener('click', function() {
      if (currentDemoLink) window.open(currentDemoLink, '_blank');
    });
  </script>
</body>
</html>`;

app.get('/', function (req, res) {
  res.send(LOGIN_HTML);
});

app.post('/api/auth/send-link', function (req, res) {
  const email = req.body.email;
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email address required' });
  }

  // ✅ PROTECTED: rate limited — same response when blocked (no enumeration)
  if (isRateLimited(email)) {
    return res.json({ message: 'If that email is registered, a link has been sent.' });
  }

  const token = generateToken();
  const expiresAt = Date.now() + 15 * 60 * 1000;
  magicTokens.set(token, { email: email, expiresAt: expiresAt, used: false });

  const magicLink = 'http://localhost:3078/auth/verify?token=' + token;
  console.log('[DEMO] Magic link for ' + email + ': ' + magicLink);

  res.json({
    message: 'If that email is registered, a link has been sent.',
    demoLink: magicLink,
    demoNote: 'DEMO ONLY — production never returns the link in the API response',
  });
});

app.get('/auth/verify', function (req, res) {
  const token = req.query.token;

  if (!token) return res.redirect('/?error=missing_token');

  const stored = magicTokens.get(token);

  if (!stored) {
    return res.redirect('/?error=invalid_token');
  }

  // ✅ PROTECTED: reject expired tokens
  if (Date.now() > stored.expiresAt) {
    magicTokens.delete(token);
    return res.redirect('/?error=link_expired');
  }

  // ✅ PROTECTED: delete token before creating session (single-use)
  magicTokens.delete(token);

  const sid = crypto.randomBytes(32).toString('hex');
  sessions.set(sid, { email: stored.email, createdAt: Date.now() });

  res.setHeader('Set-Cookie', 'iw_session=' + sid + '; Path=/; HttpOnly; SameSite=Lax');
  res.redirect('/dashboard');
});

app.get('/dashboard', requireAuth, function (req, res) {
  const profile = getProfile(req.session.email);
  res.send(DASHBOARD_HTML(req.session.email, profile));
});

app.get('/api/me', requireAuth, function (req, res) {
  res.json({ email: req.session.email, ...getProfile(req.session.email) });
});

app.post('/api/logout', requireAuth, function (req, res) {
  sessions.delete(req.sessionId);
  res.setHeader('Set-Cookie', 'iw_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax');
  res.json({ message: 'Logged out' });
});

app.listen(PORT, function () {
  console.log('Inkwell (hardened magic links) running at http://localhost:' + PORT);
});
