# Cursor Prompt: Magic Links Demo — Inkwell (Ports 3076–3078)

## Global UI Standard — applies to every server in this lab

| Server type | Theme |
|-------------|-------|
| Attacker server / Attack guide | Clone `DASHBOARD_HTML` from `demo-attacked/reverse-tabnabbing/attacker-server.js` — `#0a0a0a` bg, `#00ff41` text, `'Courier New'` font. Copy `<style>` verbatim. |
| Internal / target server | Muted corporate — `#1a1a2e` bg, `#e2e8f0` text |
| Victim servers | Realistic product UI matching their brand |

**Attacker/guide pages — non-negotiable rules:**
- Copy the `<style>` block from `DASHBOARD_HTML` in `demo-attacked/reverse-tabnabbing/attacker-server.js` **verbatim**. Never recreate or paraphrase it.
- Body layout: `padding: 2rem` on body. No `max-width` wrapper div. No centering.
- Panels: use `.flow-box` and `.credentials-panel` classes. Full-width. Only `<p>` text may use `max-width`.
- Navigation: **fixed bottom-left `target-switcher` only.**
- **After** the verbatim `<style>` block, always add this override: `.flow-box { max-width: 900px; }`

---

## Code Comment Standard — use throughout all three files

```
// ⚠️ VULNERABILITY: <what is wrong and why it matters>
// ✅ PROTECTED: <what was changed and why it is now safe>
```

No lorem ipsum anywhere. All copy must be realistic product language.

---

## Files to create

```
auth-concepts/magic-links/
├── vulnerable-server.js    # Inkwell — Weak Magic Links           — port 3076
├── guide-server.js         # Magic Links & Passwordless Lab       — port 3077
├── secure-server.js        # Inkwell — Hardened Magic Links       — port 3078
├── package.json
└── README.md
```

---

## Context

**Concept:** Magic Links — Passwordless Email Authentication
**App name:** Inkwell — a personal writing and publishing platform
**Tagline:** "Write, publish, share."
**Folder:** `auth-concepts/magic-links/`

Inkwell has no passwords. When a user wants to sign in, they enter their email and receive a one-time link. Clicking the link authenticates them — no password to remember, steal, or reuse. Under the hood, the server generates a random token, stores it with the user's email, and includes it in the link. On click, the server looks up the token, verifies it, issues a session cookie, and redirects to the dashboard.

**Why it matters:** The token IS the credential. Weak implementations create tokens with low entropy (guessable), skip expiry (tokens valid forever), allow multiple uses of the same link, or send links to any email without rate limiting (enabling inbox spam attacks). The secure implementation uses a 256-bit cryptographically random token, expires it in 15 minutes, invalidates it on first use, and rate-limits send requests.

---

## Port Layout

| Port | Role | App |
|------|------|-----|
| 3076 | Concept: Weak Magic Links | Inkwell (weak PRNG, no expiry, reusable tokens, no rate limit) |
| 3077 | Concept guide | Magic Links & Passwordless Lab (flow, entropy demo, attack walkthroughs) |
| 3078 | Improved: Hardened Magic Links | Inkwell (256-bit token, 15-min expiry, single-use, rate limited) |

---

## Shared across all three servers

### Email → user data

Magic link auth uses email as the primary identity — no passwords. Pre-seed data for known addresses; treat any valid email as a new account.

```js
// Known users: pre-seeded content visible on the dashboard
const USER_PROFILES = {
  'alice@example.com': {
    name: 'Alice Chen',
    plan: 'Pro',
    posts: [
      { id: 1, title: 'Getting started with web security',   status: 'published', views: 1240 },
      { id: 2, title: 'Why passwords keep failing us',       status: 'published', views: 892  },
      { id: 3, title: 'A guide to passkeys',                 status: 'draft',     views: 0    },
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
```

### Session store (cookie-based, shared pattern)

```js
const crypto = require('crypto');

// Map<sessionId, { email: string, createdAt: number }>
const sessions = new Map();

function requireAuth(req, res, next) {
  // Parse session cookie manually — no cookie-parser dependency needed
  const raw = req.headers.cookie || '';
  const match = raw.match(/(?:^|;\s*)iw_session=([^;]+)/);
  const sid = match ? match[1] : null;
  const session = sid ? sessions.get(sid) : null;
  if (!session) return res.redirect('/?error=not_authenticated');
  req.session = session;
  req.sessionId = sid;
  next();
}
```

---

## Port 3076 — Weak Magic Links

### File: `magic-links/vulnerable-server.js`

**Dependencies:** `express ^4.18.2`

```js
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
```

### Token generation — VULNERABLE

```js
// ⚠️ VULNERABILITY 1: Math.random() is NOT cryptographically secure.
// Its internal state can be predicted from a sequence of observed outputs.
// V8's Math.random() uses a 64-bit xorshift128+ algorithm — academic research
// has shown it can be reverse-engineered from ~3 consecutive outputs.
// An attacker who observes a few tokens (e.g. registers their own accounts)
// can compute future tokens and hijack pending magic links.
function generateToken() {
  return Math.random().toString(36).slice(2) +
         Math.random().toString(36).slice(2) +
         Math.random().toString(36).slice(2);
  // ~33 base-36 chars ≈ ~63 bits of *apparent* entropy — but PRNG state is predictable.
}
```

### Token store — VULNERABLE

```js
// Map<token, { email: string, createdAt: number }>
// ⚠️ VULNERABILITY 2: No expiresAt — token is valid until the server restarts.
// A magic link captured in email logs, Referer headers, or a forwarded email
// remains exploitable indefinitely.
// ⚠️ VULNERABILITY 3: No 'used' flag — each token can be clicked unlimited times.
const magicTokens = new Map();
```

### Send link endpoint — VULNERABLE

```js
app.post('/api/auth/send-link', (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email address required' });
  }

  // ⚠️ VULNERABILITY 4: No rate limiting.
  // An attacker can call this endpoint thousands of times with any email address,
  // flooding the victim's inbox with magic link emails and effectively running
  // an email spam / denial-of-service attack.

  // ⚠️ VULNERABILITY 5: Email enumeration — different response for unknown emails
  // could reveal whether an address has an account. (This server accepts any email,
  // which avoids enumeration — see guide Section 5 for the version that does not.)

  const token = generateToken();
  magicTokens.set(token, { email, createdAt: Date.now() });

  const magicLink = `http://localhost:3076/auth/verify?token=${token}`;
  console.log(`[DEMO] Magic link for ${email}: ${magicLink}`);

  // ⚠️ DEMO ONLY: returning the link in the API response so the demo works without email.
  // Production: send via email provider (SendGrid, Postmark, SES). Never return in API.
  res.json({
    message: 'Magic link sent! Check your email.',
    demoLink: magicLink,
    demoNote: 'DEMO ONLY — production never returns the link in the API response',
  });
});
```

### Verify endpoint — VULNERABLE

```js
app.get('/auth/verify', (req, res) => {
  const { token } = req.query;

  if (!token) return res.redirect('/?error=missing_token');

  const stored = magicTokens.get(token);

  if (!stored) {
    // Token not found — either never issued or server restarted
    return res.redirect('/?error=invalid_token');
  }

  // ⚠️ VULNERABILITY 2 (demonstrated): No expiry check.
  // This token will work tomorrow, next week, next year.

  // ⚠️ VULNERABILITY 3 (demonstrated): Token NOT deleted after use.
  // Clicking the same link 10 times creates 10 sessions.
  // An attacker who intercepts the link (email forward, proxy log, Referer header)
  // can authenticate even after the real user has already signed in.

  const sid = crypto.randomBytes(32).toString('hex');
  sessions.set(sid, { email: stored.email, createdAt: Date.now() });

  res.setHeader('Set-Cookie', `iw_session=${sid}; Path=/`);
  // ⚠️ VULNERABILITY 6: Missing HttpOnly and SameSite — session cookie is accessible
  // to JavaScript (XSS can read it) and sent on cross-site requests (CSRF risk).
  res.redirect('/dashboard');
});
```

### Debug endpoint — VULNERABLE

```js
// ⚠️ VULNERABILITY 7: All pending tokens exposed — an attacker who reaches this
// endpoint gets every outstanding magic link in plain text.
app.get('/api/debug/tokens', (req, res) => {
  const tokens = [];
  for (const [token, data] of magicTokens.entries()) {
    tokens.push({
      token,
      email: data.email,
      createdAt: new Date(data.createdAt).toISOString(),
      link: `http://localhost:3076/auth/verify?token=${token}`,
    });
  }
  res.json({ count: tokens.length, tokens });
});
```

### Protected routes

```js
app.get('/dashboard', requireAuth, (req, res) => {
  const profile = getProfile(req.session.email);
  res.send(DASHBOARD_HTML(req.session.email, profile));
  // DASHBOARD_HTML is an SSR function — embed email and profile data directly.
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ email: req.session.email, ...getProfile(req.session.email) });
});

app.post('/api/logout', requireAuth, (req, res) => {
  sessions.delete(req.sessionId);
  res.setHeader('Set-Cookie', 'iw_session=; Path=/; Max-Age=0');
  res.json({ message: 'Logged out' });
});
```

### UI design — Inkwell (clean editorial style)

**Colors:** `#fafaf9` background (warm white), `#1c1917` header, `#f5f5f4` sidebar, `#e7470a` accent (ember orange — writing/pen motif).

**Login page** (`GET /`):

Clean centered card. No username or password field — only email.

```html
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

  <!-- Demo link panel — shown after send -->
  <div id="demo-link-panel" style="display:none;margin-top:1.5rem;padding:1rem;background:#fef3c7;border:1px solid #d97706;border-radius:8px;font-size:0.82rem;color:#78350f">
    <strong>⚠️ Demo mode:</strong> Your magic link (normally emailed):<br>
    <a id="demo-link-anchor" href="#" style="color:#b45309;word-break:break-all;font-family:monospace;font-size:0.78rem"></a>
    <br><br>
    <button id="btn-open-link" style="background:#d97706;color:#fff;border:none;padding:0.4rem 0.8rem;border-radius:4px;cursor:pointer;font-size:0.8rem">Open Link →</button>
    <button id="btn-open-link-again" style="margin-left:0.5rem;background:#92400e;color:#fff;border:none;padding:0.4rem 0.8rem;border-radius:4px;cursor:pointer;font-size:0.8rem">Open Again (replay test) →</button>
  </div>

  <!-- Error display -->
  <div id="error-banner" style="display:none;margin-top:1rem;padding:0.75rem;background:#fef2f2;border:1px solid #fca5a5;border-radius:6px;color:#b91c1c;font-size:0.85rem"></div>
</div>
```

Show error messages from URL query params (`?error=invalid_token`, `?error=not_authenticated`):

```js
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
```

**Send link JS:**

```js
var currentDemoLink = null;

document.getElementById('btn-send').addEventListener('click', async function() {
  var email = document.getElementById('email-input').value.trim();
  if (!email) return;

  this.disabled = true;
  this.textContent = 'Sending...';

  try {
    var r = await fetch('/api/auth/send-link', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
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
  // Opens in new tab so the original tab can try again — demonstrates reuse
  if (currentDemoLink) window.open(currentDemoLink, '_blank');
});
```

**Amber warning banner** at top of login page:

```
⚠️ WEAK MAGIC LINKS: Tokens generated with Math.random() (predictable). No expiry.
Same link can be used multiple times. No rate limit on /api/auth/send-link.
```

**Dashboard** (`GET /dashboard`): SSR — `DASHBOARD_HTML(email, profile)` function.

```js
function DASHBOARD_HTML(email, profile) {
  return `<!DOCTYPE html>...
    <!-- Top bar -->
    <header>Inkwell 🖊️ — ${profile.name || email} <span style="margin-left:auto">[${profile.plan} plan]</span>
      <button id="btn-logout">Sign out</button>
    </header>

    <!-- Amber banner on vulnerable server -->
    <div style="...background:#fef3c7;border:1px solid #d97706...">
      ⚠️ WEAK: This session cookie has no HttpOnly or SameSite flags.
      Try clicking your magic link again in another tab — you'll get a second session.
    </div>

    <!-- Posts table -->
    <h2>Your posts</h2>
    ${profile.posts.length === 0
      ? '<p>No posts yet. Start writing!</p>'
      : `<table>...${profile.posts.map(p => `<tr><td>${p.title}</td><td>${p.status}</td><td>${p.views} views</td></tr>`).join('')}...</table>`
    }
  ...`;
}
```

**Dashboard logout JS:**
```js
document.getElementById('btn-logout').addEventListener('click', async function() {
  await fetch('/api/logout', { method: 'POST' });
  window.location.href = '/';
});
```

**Login input CSS:**
```css
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
.result-banner { padding: 0.65rem 1rem; border-radius: 6px; font-size: 0.85rem; margin-top: 0.75rem; display: none; }
.result-banner.success { background: #f0fdf4; border: 1px solid #86efac; color: #15803d; }
.result-banner.failure { background: #fef2f2; border: 1px solid #fca5a5; color: #b91c1c; }
```

```js
function showResult(id, type, msg) {
  var el = document.getElementById(id);
  el.className = 'result-banner ' + type;
  el.textContent = msg;
  el.style.display = 'block';
}
```

---

## Port 3077 — Concept Guide

### File: `magic-links/guide-server.js`

Open `demo-attacked/reverse-tabnabbing/attacker-server.js`. Find the `DASHBOARD_HTML` constant. Copy its entire `<style>` block **verbatim**. Paste it into this guide's HTML template.

### Page structure

**Title:** `🔗 Magic Links — How Passwordless Auth Works`

**Section 1 — No Passwords at All** (`.flow-box`)

Heading: `What Magic Links Replace`

```
Traditional login:
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
  • Rate-limited to send (one email can't be spammed)
```

Show in `<pre>` with `color:#00ff41`.

**Section 2 — Full Flow Diagram** (`.flow-box`)

Heading: `Token Lifecycle`

```
  Browser                      Server (3076/3078)               Email
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
     │←── 200 dashboard HTML ────────│                            │
```

Show in `<pre>`.

**Section 3 — Attack: Weak Token Entropy** (`.flow-box`)

Heading: `⚠️ Attack: Predictable Token (Port 3076)`

```
Port 3076 uses Math.random() to generate tokens.

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
  Attacker authenticates as victim.
```

Live entropy comparison widget:

```html
<div style="margin-top:1rem">
  <button class="demo-btn" id="btn-compare-entropy">Compare token entropy</button>
  <pre class="decoded-box" id="entropy-output" style="min-height:120px;margin-top:0.5rem">Click to compare</pre>
</div>
```

```js
document.getElementById('btn-compare-entropy').addEventListener('click', function() {
  // Simulate weak token (Math.random)
  function weakToken() {
    return Math.random().toString(36).slice(2) +
           Math.random().toString(36).slice(2) +
           Math.random().toString(36).slice(2);
  }

  // Strong token (simulated — real crypto.randomBytes is server-side only)
  // We'll show what 256 bits looks like by generating a plausible hex string
  function strongTokenSimulated() {
    var arr = new Uint8Array(32);
    crypto.getRandomValues(arr); // browser's CSPRNG
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  var weak1 = weakToken();
  var weak2 = weakToken();
  var weak3 = weakToken();
  var strong = strongTokenSimulated();

  document.getElementById('entropy-output').textContent =
    'Weak (Math.random × 3):\n' +
    '  Token 1: ' + weak1 + '  (' + weak1.length + ' chars, ~63 bits apparent)\n' +
    '  Token 2: ' + weak2 + '\n' +
    '  Token 3: ' + weak3 + '\n' +
    '  Weakness: V8 xorshift128+ state is recoverable from observed outputs.\n\n' +
    'Strong (crypto.getRandomValues / Node crypto.randomBytes):\n' +
    '  Token:   ' + strong + '  (' + strong.length + ' hex chars = 256 bits)\n' +
    '  Each bit is independent. No state recovery possible.\n' +
    '  Brute force at 10 billion guesses/sec: ' +
    '2^256 / 10^10 / 3.15×10^7 ≈ 3.7×10^59 years';
});
```

**Section 4 — Attack: Token Never Expires** (`.flow-box`)

Heading: `⚠️ Attack: Captured Link Used Days Later`

```
Where magic links leak:
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
Also: <meta name="referrer" content="no-referrer"> on the verify endpoint's redirect
target ensures the dashboard doesn't leak anything if it has external resources.
```

**Section 5 — Attack: Reusable Token** (`.flow-box`)

Heading: `⚠️ Attack: Replay — Same Link Works Multiple Times (Port 3076)`

Live replay demo:

```html
<div style="margin-top:1rem">
  <button class="demo-btn" id="btn-replay-test">Request link + replay on :3076</button>
  <div class="result-banner" id="replay-result"></div>
  <pre class="decoded-box" id="replay-output" style="min-height:100px;margin-top:0.5rem">–</pre>
</div>
```

```js
document.getElementById('btn-replay-test').addEventListener('click', async function() {
  var out = document.getElementById('replay-output');
  try {
    // Step 1: Request a magic link
    var r1 = await fetch('http://localhost:3076/api/auth/send-link', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'alice@example.com' }),
    });
    var d1 = await r1.json();
    var link = d1.demoLink;
    out.textContent = 'Step 1: requested magic link\n  → ' + link + '\n\n';

    // Step 2: Extract token and hit verify twice
    var token = new URL(link).searchParams.get('token');

    var v1 = await fetch('http://localhost:3076/auth/verify?token=' + token, {
      redirect: 'manual',
    });
    out.textContent += 'Step 2: first verify → HTTP ' + v1.status + ' ' + (v1.status === 302 ? '(redirect to dashboard ✓)' : '') + '\n';

    var v2 = await fetch('http://localhost:3076/auth/verify?token=' + token, {
      redirect: 'manual',
    });
    out.textContent += 'Step 3: replay same token → HTTP ' + v2.status + ' ' + (v2.status === 302 ? '(redirect to dashboard ✓ — REPLAY WORKED!)' : '(rejected ✓)') + '\n\n';

    var replayed = v2.status === 302;
    showResult('replay-result', replayed ? 'failure' : 'success',
      replayed
        ? '⚠ Replay succeeded on :3076 — same token accepted twice'
        : '✓ Replay blocked — token was invalidated after first use');
  } catch (e) {
    showResult('replay-result', 'failure', '✗ ' + e.message + ' — is :3076 running?');
  }
});
```

**Section 6 — Attack: No Rate Limit on Send** (`.flow-box`)

Heading: `⚠️ Attack: Inbox Spam (Port 3076)`

```
POST /api/auth/send-link accepts unlimited requests per email address.

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
(no error message — to prevent confirming that the email exists).
```

**Section 7 — Attack: Email Enumeration** (`.flow-box`)

Heading: `⚠️ Attack: Which Emails Have Accounts? (Bonus Vulnerability)`

```
Some implementations return different responses based on whether the email is registered:

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
Port 3078 uses this phrasing for all responses including rate-limited ones.
```

**Section 8 — Comparison: Password vs Magic Link** (`.flow-box`)

Heading: `When Magic Links Make Sense`

```html
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
```

**Navigation:** Fixed bottom-left `target-switcher`:
- `Weak Magic Links (3076)` → `window.open('http://localhost:3076')`
- `Hardened Magic Links (3078)` → `window.open('http://localhost:3078')`

**Helper CSS (append after verbatim style block):**
```css
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
```

```js
function showResult(id, type, msg) {
  var el = document.getElementById(id);
  el.className = 'result-banner ' + type;
  el.textContent = msg;
  el.style.display = 'block';
}
```

---

## Port 3078 — Hardened Magic Links

### File: `magic-links/secure-server.js`

**Dependencies:** `express ^4.18.2`

### Token generation — hardened

```js
// ✅ PROTECTED: crypto.randomBytes(32) — 256 bits of cryptographically secure randomness.
// The OS CSPRNG (e.g. /dev/urandom on Linux) is seeded from hardware entropy and
// cannot be predicted from observed outputs.
function generateToken() {
  return crypto.randomBytes(32).toString('hex'); // 64-char hex string
}
```

### Token store — hardened

```js
// Map<token, { email: string, expiresAt: number, used: boolean }>
// ✅ PROTECTED: expiresAt enforced on verify
// ✅ PROTECTED: used flag ensures single-use (token deleted on first valid use)
const magicTokens = new Map();

// Clean up expired tokens every 10 minutes to prevent unbounded Map growth
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of magicTokens.entries()) {
    if (now > data.expiresAt) magicTokens.delete(token);
  }
}, 10 * 60 * 1000);
```

### Rate limiting

```js
// ✅ PROTECTED: Maximum 3 magic link emails per address per hour.
// Map<email, { count: number, windowStart: number }>
const sendRateLimit = new Map();
const MAX_PER_HOUR = 3;
const WINDOW_MS = 60 * 60 * 1000; // 1 hour

function isRateLimited(email) {
  const now = Date.now();
  const state = sendRateLimit.get(email) || { count: 0, windowStart: now };

  if (now - state.windowStart > WINDOW_MS) {
    // Window expired — reset
    state.count = 0;
    state.windowStart = now;
  }

  if (state.count >= MAX_PER_HOUR) {
    sendRateLimit.set(email, state);
    return true; // rate limited
  }

  state.count++;
  sendRateLimit.set(email, state);
  return false;
}
```

### Send link endpoint — hardened

```js
app.post('/api/auth/send-link', (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Valid email address required' });
  }

  // ✅ PROTECTED: Rate limiting — 3 per hour per email
  if (isRateLimited(email)) {
    // ✅ PROTECTED: Same response as success — no email enumeration via rate-limit signal
    return res.json({ message: 'If that email is registered, a link has been sent.' });
  }

  const token = generateToken();
  const expiresAt = Date.now() + 15 * 60 * 1000; // ✅ PROTECTED: 15-minute expiry
  magicTokens.set(token, { email, expiresAt, used: false });

  const magicLink = `http://localhost:3078/auth/verify?token=${token}`;
  console.log(`[DEMO] Magic link for ${email}: ${magicLink}`);

  // ✅ PROTECTED: Ambiguous phrasing — does not confirm whether the email has an account
  res.json({
    message: 'If that email is registered, a link has been sent.',
    demoLink: magicLink, // ⚠️ DEMO ONLY
    demoNote: 'DEMO ONLY — production never returns the link in the API response',
  });
});
```

### Verify endpoint — hardened

```js
app.get('/auth/verify', (req, res) => {
  const { token } = req.query;

  if (!token) return res.redirect('/?error=missing_token');

  const stored = magicTokens.get(token);

  // ✅ PROTECTED: Invalid token (never issued or already deleted)
  if (!stored) {
    return res.redirect('/?error=invalid_token');
  }

  // ✅ PROTECTED: Expiry check — reject tokens older than 15 minutes
  if (Date.now() > stored.expiresAt) {
    magicTokens.delete(token); // clean up
    return res.redirect('/?error=link_expired');
  }

  // ✅ PROTECTED: Delete token BEFORE issuing session.
  // Deleting first means if the session creation fails, the token is already gone —
  // the user must request a new link. This prevents the token from being used
  // during a retry window even if something goes wrong after this point.
  magicTokens.delete(token);

  const sid = crypto.randomBytes(32).toString('hex');
  sessions.set(sid, { email: stored.email, createdAt: Date.now() });

  // ✅ PROTECTED: HttpOnly prevents JS access; SameSite=Lax prevents CSRF
  res.setHeader('Set-Cookie', `iw_session=${sid}; Path=/; HttpOnly; SameSite=Lax`);
  res.redirect('/dashboard');
});
```

### Dashboard — hardened (SSR, same function signature as port 3076)

```js
app.get('/dashboard', requireAuth, (req, res) => {
  const profile = getProfile(req.session.email);
  res.send(DASHBOARD_HTML(req.session.email, profile));
});
```

`DASHBOARD_HTML` on port 3078 shows a green banner instead of amber:

```
✅ HARDENED MAGIC LINKS: 256-bit token. Expires in 15 minutes. Single-use.
Try clicking your magic link a second time — it will say "Link already used or expired."
```

Also add `<meta name="referrer" content="no-referrer">` in the `<head>` of the dashboard HTML:
```html
<meta name="referrer" content="no-referrer">
<!-- ✅ Prevents the dashboard from leaking the URL of the referring page (the magic link)
     in Referer headers when it loads external resources. The link is gone by redirect
     but this provides defense-in-depth. -->
```

### Protected routes (same as port 3076)

```js
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ email: req.session.email, ...getProfile(req.session.email) });
});

app.post('/api/logout', requireAuth, (req, res) => {
  sessions.delete(req.sessionId);
  res.setHeader('Set-Cookie', 'iw_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax');
  res.json({ message: 'Logged out' });
});
```

### UI differences from port 3076

1. **Green banner** instead of amber on login page and dashboard.
2. **"Open Again (replay test)" button** still present — but clicking it on port 3078 shows: `/?error=invalid_token` (token already deleted).
3. **Rate limit feedback**: After 3 send attempts with the same email, the 4th shows the same success message — but no demo link appears (the server rate-limited silently). Add a note below the form: "Demo: after 3 sends per hour, further sends are silently dropped."
4. **Token timer**: Show expiry countdown on the demo link panel:
   ```html
   <span id="expiry-timer" style="font-size:0.75rem;color:#92400e">⏱ Expires in <strong id="expiry-seconds">900</strong>s</span>
   ```
   ```js
   var expirySeconds = 900; // 15 minutes
   var timerInterval = setInterval(function() {
     expirySeconds--;
     var el = document.getElementById('expiry-seconds');
     if (el) el.textContent = expirySeconds;
     if (expirySeconds <= 0) {
       clearInterval(timerInterval);
       showResult('send-result', 'failure', '⏱ Link expired — request a new one');
       document.getElementById('demo-link-panel').style.display = 'none';
     }
   }, 1000);
   ```

---

## Shared `package.json` at `magic-links/`

```json
{
  "name": "magic-links-demo",
  "version": "1.0.0",
  "scripts": {
    "vulnerable": "node vulnerable-server.js",
    "guide":      "node guide-server.js",
    "secure":     "node secure-server.js"
  },
  "dependencies": {
    "express": "^4.18.2"
  }
}
```

No external auth libraries needed — magic links are implemented with Node's built-in `crypto` module only.

---

## README at `magic-links/README.md`

### How It Works

```
Send link:
  POST /api/auth/send-link { email }
  → generateToken() + store { email, expiresAt }
  → "send" email (console.log in demo)
  → { message, demoLink }

Verify:
  GET /auth/verify?token=<token>
  → look up token
  → check expiry
  → DELETE token (single use)
  → create session cookie
  → 302 /dashboard

Dashboard:
  GET /dashboard  (session cookie required)
  → SSR HTML with user's posts

Vulnerable (3076): Math.random token, no expiry, reusable, no rate limit, no HttpOnly
Hardened  (3078): crypto.randomBytes, 15-min expiry, single-use, 3/hr rate limit, HttpOnly+SameSite
```

### Run the demo

```bash
cd auth-concepts/magic-links
npm install
npm run vulnerable  # terminal 1 → localhost:3076
npm run guide       # terminal 2 → localhost:3077
npm run secure      # terminal 3 → localhost:3078
```

### Walkthrough

1. Open **localhost:3077** — read the flow diagram and entropy comparison.
2. Open **localhost:3076** — enter `alice@example.com`, click "Send Magic Link". Click "Open Link →". Land on dashboard.
3. Click "Open Again (replay test)" — it works again. Same link, second session. That's the vulnerability.
4. Open **localhost:3078** — same flow. After clicking the link, click "Open Again" — redirected to `/?error=invalid_token`.
5. On :3078, send a magic link 4 times with the same email. The 4th shows the same success message but no demo link appears — rate limiting in effect.
6. Back on :3077, run the "Request link + replay on :3076" demo to see the HTTP status codes side-by-side.

### Key Concepts

**The token IS the credential:** There is no second factor. Whoever has the magic link token can authenticate. This means the token must be treated with the same care as a password — strong randomness, short lifetime, single-use.

**Email access = authentication:** Magic links transfer trust to email security. If someone can read the victim's email (shared inbox, email forwarding, mailbox breach), they can authenticate. This is why magic links are most appropriate for lower-stakes applications where password fatigue is more of a risk than targeted email attacks.

**Delete before issue:** The token is deleted from the store before the session is created. This prevents a race condition where two requests arrive simultaneously with the same token — only the first delete succeeds, the second sees an empty entry and fails. "Delete-then-create" is safer than "create-then-delete."

**Same response for all outcomes:** Rate-limited, unknown email, success — all return `{ message: "If that email is registered, a link has been sent." }`. This prevents attackers from using the endpoint to enumerate which email addresses have accounts.

---

## Key technical notes for Cursor

1. **No dependencies beyond Express.** `crypto` is a Node.js built-in — `require('crypto')` works without installing anything. Do not add `uuid`, `nanoid`, or any token-generation library — `crypto.randomBytes(32).toString('hex')` is the correct primitive.

2. **Session cookie parsed with regex, not `cookie-parser`.** Avoid adding `cookie-parser` as a dependency just for one cookie. Parse it manually: `const match = (req.headers.cookie || '').match(/(?:^|;\s*)iw_session=([^;]+)/); const sid = match ? match[1] : null;`. This is reliable and zero-dependency.

3. **`requireAuth` redirects, not JSON 401.** Unlike API-only servers, Inkwell renders full pages. When the session is missing, `requireAuth` redirects to `/?error=not_authenticated` rather than returning JSON. This handles direct URL access (browser navigation) gracefully.

4. **`/auth/verify` is a GET endpoint, not POST.** Email clients render magic links as clickable hyperlinks. The click is a GET request. Do not use POST for the verification endpoint — it would require a form submission and prevent direct link clicks from email.

5. **`res.redirect` after verify — not `res.send`.** The token is in the URL query string. After verifying, immediately redirect to `/dashboard` (a clean URL with no token). This removes the token from the browser's current URL, address bar, and history entry. Never render HTML at `/auth/verify?token=...` — that keeps the token in the URL while the page is open.

6. **`expiresAt` stored in the token Map, not as a timer.** Do not use `setTimeout(() => magicTokens.delete(token), 15 * 60 * 1000)`. If the server has many pending tokens, thousands of active timers waste memory. Instead, store `expiresAt: Date.now() + 15 * 60 * 1000` and check `Date.now() > stored.expiresAt` on verify. The `setInterval` cleanup handles eventual removal from the Map.

7. **Rate limit resets per window, not per server lifetime.** `sendRateLimit` tracks `{ count, windowStart }` per email. If `Date.now() - windowStart > WINDOW_MS`, reset `count = 0` and `windowStart = now`. This is a sliding-ish window — not exact, but correct for demo purposes.

8. **`DASHBOARD_HTML` is a function, not a string constant.** It accepts `(email, profile)` and returns a full HTML string. On both servers, `GET /dashboard` calls `res.send(DASHBOARD_HTML(req.session.email, getProfile(req.session.email)))`. The session provides the email; `getProfile()` provides the content.

9. **The demo link is shown on the page — this is intentional.** A real server would send the link via an email provider. Since the demo has no email provider, returning `demoLink` in the API response and displaying it on the page is the only way to make the flow testable. Mark it prominently as `⚠️ DEMO ONLY` in both the code comment and the UI. The secure server (`3078`) still returns `demoLink` — but with the expiry countdown showing clearly.

10. **`Math.random()` weakness is conceptual for most demo audiences.** The state recovery attack against V8's xorshift128+ requires observing many tokens and running offline computation — it cannot be demonstrated live in the browser in a few minutes. Explain the theory; the guide's entropy comparison widget illustrates the structural difference (PRNG vs CSPRNG) without attempting the actual attack.
