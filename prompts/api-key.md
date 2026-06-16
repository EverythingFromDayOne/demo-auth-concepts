# Cursor Prompt: API Key Authentication Demo — DataPipe (Ports 3055–3057)

## Global UI Standard

| Server type | Theme |
|-------------|-------|
| Guide server | Clone `DASHBOARD_HTML` from `demo-attacked/reverse-tabnabbing/attacker-server.js` — `#0a0a0a` bg, `#00ff41` text, `'Courier New'` font. Copy `<style>` verbatim. |
| Victim servers | Realistic product UI matching their brand |

**Guide pages:** Copy `<style>` verbatim. `padding: 2rem` body. No `max-width` wrapper. Use `.flow-box` / `.credentials-panel`. Fixed bottom-left `target-switcher` only.
- **After** the verbatim `<style>` block, always add this override: `.flow-box { max-width: 900px; }`

---

## Context

**Concept:** API Key Authentication  
**App name:** DataPipe — a weather and analytics data API  
**Tagline:** "Real-time data for your applications"  
**Folder:** `auth-concepts/api-key/`

DataPipe issues API keys to developers for programmatic access. The vulnerable version accepts the key as a URL query parameter (`?api_key=`). This causes the key to appear in server logs, browser history, Referer headers sent to third-party scripts, and anywhere URLs are shared. The protected version requires the key in the `Authorization` header, which is excluded from most logging and not forwarded in Referer.

---

## Code Comment Standard — use throughout all three files

```
// ⚠️ VULNERABILITY: <what is wrong and why it matters>
// ✅ PROTECTED: <what was changed and why it is now safe>
```

No lorem ipsum. All copy must be realistic product language.

---

## Files to create

```
auth-concepts/api-key/
├── apikey-url-server.js    # DataPipe — API key in URL query param   — port 3055
├── guide-server.js         # API Key Lab                             — port 3056
├── apikey-header-server.js # DataPipe — API key in Authorization hdr — port 3057
├── package.json
└── README.md
```

---

## Port Layout

| Port | Role | App |
|------|------|-----|
| 3055 | Concept: API Key in URL param (vulnerable) | DataPipe (`?api_key=sk_...`) |
| 3056 | Concept guide | API Key Auth Lab |
| 3057 | Improved: API Key in header | DataPipe (`Authorization: Bearer sk_...`) |

---

## Port 3055 — DataPipe (API Key in URL)

### File: `api-key/apikey-url-server.js`

**Dependencies:** `express ^4.18.2`, `cors ^2.8.5`

```js
const cors = require('cors');
app.use(cors({ origin: 'http://localhost:3056' }));
app.use(express.json());
```

### API key store

```js
// In a real system these would be in a database, hashed.
// For demo: plain keys with metadata.
const API_KEYS = new Map([
  ['sk_live_alice_a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5', {
    owner: 'alice', plan: 'pro', scopes: ['weather', 'analytics'], rateLimit: 1000
  }],
  ['sk_live_bob_b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9', {
    owner: 'bob', plan: 'free', scopes: ['weather'], rateLimit: 100
  }],
  ['sk_test_demo_c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0', {
    owner: 'demo', plan: 'free', scopes: ['weather'], rateLimit: 50
  }],
]);
```

### Vulnerable auth middleware (key in URL)

```js
// ⚠️ VULNERABLE: API key in URL query parameter
// → Appears in: server access logs, browser history, Referer headers, CDN logs
function apiKeyAuth(req, res, next) {
  const key = req.query.api_key; // ← reads from URL: ?api_key=sk_live_...

  if (!key) {
    return res.status(401).json({
      error: 'Missing API key',
      hint: 'Add ?api_key=sk_test_demo_c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0 to the URL'
    });
  }

  const keyInfo = API_KEYS.get(key);
  if (!keyInfo) return res.status(401).json({ error: 'Invalid API key' });

  req.apiKey = key;
  req.keyInfo = keyInfo;
  next();
}
```

### API endpoints

```js
// Weather endpoint
app.get('/api/weather', apiKeyAuth, (req, res) => {
  if (!req.keyInfo.scopes.includes('weather')) {
    return res.status(403).json({ error: 'API key does not have weather scope' });
  }
  res.json({
    location: 'Ho Chi Minh City',
    temperature: 32,
    unit: 'celsius',
    condition: 'Partly Cloudy',
    humidity: 78,
    wind_kph: 15,
    retrieved_with_key: req.apiKey, // ← shows the key was in the request
    warning: '⚠️ This key was sent in the URL — check your server logs'
  });
});

// Analytics endpoint
app.get('/api/analytics', apiKeyAuth, (req, res) => {
  if (!req.keyInfo.scopes.includes('analytics')) {
    return res.status(403).json({
      error: 'analytics scope required — upgrade to Pro plan',
      current_plan: req.keyInfo.plan
    });
  }
  res.json({
    pageviews_today: 14239,
    unique_visitors: 3817,
    bounce_rate: 0.42,
    top_pages: ['/docs', '/api', '/pricing'],
    key_owner: req.keyInfo.owner
  });
});

// Key info endpoint
app.get('/api/key-info', apiKeyAuth, (req, res) => {
  res.json({
    owner: req.keyInfo.owner,
    plan: req.keyInfo.plan,
    scopes: req.keyInfo.scopes,
    rate_limit: req.keyInfo.rateLimit,
    key_prefix: req.apiKey.substring(0, 12) + '...',
    key_in_url: true, // ← flagging the vulnerability
    warning: 'This key was passed as a URL parameter (?api_key=). See server logs.'
  });
});
```

### Server-side log simulation

On every request, log the full URL including the API key:
```js
app.use((req, res, next) => {
  // This simulates what access logs capture:
  console.log(`[ACCESS LOG] ${new Date().toISOString()} ${req.method} ${req.url}`);
  // ↑ If api_key is in the URL, it's in every log line.
  // Server logs, load balancer logs, CDN logs, analytics tools all capture this.
  next();
});
```

Add a `GET /api/logs` endpoint that returns the last 10 "simulated" log lines:
```js
const accessLog = [];
app.use((req, res, next) => {
  accessLog.push({ time: new Date().toISOString(), method: req.method, url: req.url });
  if (accessLog.length > 50) accessLog.shift();
  next();
});

app.get('/api/logs', (req, res) => {
  res.json({
    note: 'These are simulated server access logs. API keys in URLs appear here.',
    log: accessLog.slice(-10)
  });
});
```

### UI design — developer API portal

Colors: `#0f172a` dark background, `#1e293b` card, `#f1f5f9` text, `#10b981` accent (emerald).

Build a simple web UI that:
1. Has a "Try the API" form where the user pastes their API key
2. Shows the URL being constructed as they type: `http://localhost:3055/api/weather?api_key=sk_...`
3. Makes the request and shows the response
4. Shows the server log via `GET /api/logs`

The UI is a developer documentation / playground page — similar to Stripe's or OpenWeatherMap's API playground.

**Amber banner:**
```
⚠ VULNERABLE: API key is passed as a URL query parameter (?api_key=).
It appears in server access logs, browser history, and Referer headers.
```

Pre-filled demo key: `sk_test_demo_c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0`

Show the log viewer on the page so users can see their key appearing in logs in real time.

**`package.json` scripts:**
```json
{
  "scripts": { "start": "node apikey-url-server.js", "url": "node apikey-url-server.js" },
  "dependencies": { "express": "^4.18.2", "cors": "^2.8.5" }
}
```

---

## Port 3056 — API Key Concept Guide

### File: `api-key/guide-server.js`

Copy `<style>` from `DASHBOARD_HTML` verbatim.

**Title:** `🔑 API Key Authentication — How It Works`

**Section 1 — What is an API Key?** (`.flow-box`)

Heading: `API Key Auth Flow`

```
Client (app/script)              DataPipe API (3055)
       │                                │
       ├── GET /api/weather?api_key=sk_ →│
       │                                │ API_KEYS.get(key) → { owner, scopes }
       │←── 200 { temperature: 32, ... }┤
       │                                │
       │   Server access log writes:    │
       │   GET /api/weather?api_key=sk_live_alice_a3f9b2c1...
       │                     ↑
       │               KEY IN LOG — visible to anyone with log access
```

**Section 2 — Where Keys Leak** (`.flow-box`)

Heading: `⚠️ API Key in URL — Exposure Vectors`

Show 5 vectors as a list inside a `.credentials-panel`:

| # | Where | How the key gets there |
|---|-------|----------------------|
| 1 | Server access logs | Every web server logs the full URL with query params |
| 2 | Browser history | URL bar entries include query params — synced across devices |
| 3 | Referer header | When user navigates away, browser sends `Referer: https://app.com/page?api_key=sk_...` to third-party scripts |
| 4 | CDN / proxy logs | Cloudflare, nginx, Fastly all log full request URLs |
| 5 | Shared URLs | Developer copies URL from browser bar — key is visible |

**Section 3 — Live Leak Demo** (`.flow-box`)

Heading: `📡 Watch the Key Appear in Logs`

```html
<div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;margin-bottom:0.75rem">
  <input class="field" id="demo-key" value="sk_test_demo_c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0" style="flex:1;font-size:0.75rem">
  <button class="demo-btn" id="btn-make-request">Call /api/weather with URL key</button>
</div>
<div class="result-banner" id="leak-result"></div>
<button class="demo-btn" id="btn-check-logs" style="margin-top:0.75rem">📋 Check Server Logs → :3055/api/logs</button>
<pre class="decoded-box" id="log-output" style="min-height:80px">Make a request first, then check logs</pre>
```

```js
document.getElementById('btn-make-request').addEventListener('click', async function() {
  var key = document.getElementById('demo-key').value.trim();
  var url = 'http://localhost:3055/api/weather?api_key=' + encodeURIComponent(key);
  try {
    var res = await fetch(url);
    var data = await res.json();
    showResult('leak-result', res.ok ? 'success' : 'failure',
      (res.ok ? '✓ Response received. ' : '✗ ') +
      'Full URL sent: ' + url + '\n(Check logs below — key is in the log)');
  } catch(e) { showResult('leak-result', 'failure', '✗ ' + e.message); }
});

document.getElementById('btn-check-logs').addEventListener('click', async function() {
  try {
    var res = await fetch('http://localhost:3055/api/logs');
    var data = await res.json();
    document.getElementById('log-output').textContent =
      data.note + '\n\n' + data.log.map(function(l) {
        return '[' + l.time + '] ' + l.method + ' ' + l.url;
      }).join('\n');
  } catch(e) { document.getElementById('log-output').textContent = '✗ ' + e.message; }
});
```

**Section 4 — The Fix: Key in Header** (`.flow-box`)

Heading: `✅ Authorization Header (Port 3057)`

```
VULNERABLE:   GET /api/weather?api_key=sk_live_alice_a3f9b2c1...
              ↑ Appears in logs, history, Referer

SECURE:       GET /api/weather
              Authorization: Bearer sk_live_alice_a3f9b2c1...
              ↑ HTTP headers are NOT logged by most servers by default
              ↑ NOT sent in Referer header
              ↑ NOT stored in browser history
              ↑ Still visible in packet captures (need HTTPS to protect from that)
```

```html
<div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap;margin-bottom:0.75rem">
  <input class="field" id="header-key" value="sk_test_demo_c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0" style="flex:1;font-size:0.75rem">
  <button class="demo-btn" id="btn-header-request">Call /api/weather with Authorization header</button>
</div>
<div class="result-banner" id="header-result"></div>
<pre class="decoded-box" id="header-output" style="min-height:60px">–</pre>
```

```js
document.getElementById('btn-header-request').addEventListener('click', async function() {
  var key = document.getElementById('header-key').value.trim();
  try {
    var res = await fetch('http://localhost:3057/api/weather', {
      headers: { 'Authorization': 'Bearer ' + key }
    });
    var data = await res.json();
    document.getElementById('header-output').textContent = JSON.stringify(data, null, 2);
    showResult('header-result', res.ok ? 'success' : 'failure',
      res.ok ? '✓ Response received — check :3057 logs, the key is NOT in the URL' : '✗ ' + data.error);
  } catch(e) { showResult('header-result', 'failure', '✗ ' + e.message); }
});
```

**Section 5 — API Key Best Practices** (`.flow-box`)

Heading: `API Key Security Checklist`

```html
<div class="credentials-panel">
  <table style="width:100%;border-collapse:collapse;font-size:0.82rem">
    <tr style="border-bottom:1px solid #1a3a1a"><td style="padding:0.4rem 0.6rem;color:#4ade80">✅</td><td style="padding:0.4rem 0.6rem;color:#94a3b8">Send key in Authorization: Bearer header, never in URL</td></tr>
    <tr style="border-bottom:1px solid #1a3a1a"><td style="padding:0.4rem 0.6rem;color:#4ade80">✅</td><td style="padding:0.4rem 0.6rem;color:#94a3b8">Scope keys — separate keys for read vs write, per service</td></tr>
    <tr style="border-bottom:1px solid #1a3a1a"><td style="padding:0.4rem 0.6rem;color:#4ade80">✅</td><td style="padding:0.4rem 0.6rem;color:#94a3b8">Rotate keys periodically and on suspected compromise</td></tr>
    <tr style="border-bottom:1px solid #1a3a1a"><td style="padding:0.4rem 0.6rem;color:#4ade80">✅</td><td style="padding:0.4rem 0.6rem;color:#94a3b8">Hash keys at rest (store SHA-256 of key, not the key itself)</td></tr>
    <tr style="border-bottom:1px solid #1a3a1a"><td style="padding:0.4rem 0.6rem;color:#4ade80">✅</td><td style="padding:0.4rem 0.6rem;color:#94a3b8">Rate limit per key — detect abuse before it becomes a breach</td></tr>
    <tr><td style="padding:0.4rem 0.6rem;color:#fca5a5">❌</td><td style="padding:0.4rem 0.6rem;color:#94a3b8">Never embed API keys in frontend code or public repositories</td></tr>
  </table>
</div>
```

**Helper CSS (append inside `<style>` after the verbatim block):**

```css
/* Override default flow-box width from copied style */
.flow-box { max-width: 900px; }

.decoded-box {
  background: #0a0a0a; border: 1px solid #1a3a1a; border-radius: 4px;
  padding: 0.75rem; font-size: 0.78rem; color: #cbd5e1;
  white-space: pre-wrap; word-break: break-all; min-height: 60px; margin-top: 0.5rem;
}
.result-banner {
  padding: 0.6rem 1rem; border-radius: 4px; font-size: 0.82rem;
  margin-top: 0.75rem; display: none;
}
.result-banner.success { background: #052e16; border: 1px solid #16a34a; color: #4ade80; }
.result-banner.failure { background: #450a0a; border: 1px solid #dc2626; color: #fca5a5; }
.result-banner.info    { background: #0c1a2e; border: 1px solid #1e40af; color: #93c5fd; }
input.field {
  background: #111; border: 1px solid #1a3a1a; color: #00ff41;
  font-family: 'Courier New', Courier, monospace; font-size: 0.82rem;
  padding: 0.4rem 0.6rem; border-radius: 4px;
}
```

**`showResult` helper (add to `<script>`):**

```js
function showResult(id, type, msg) {
  var el = document.getElementById(id);
  el.className = 'result-banner ' + type;
  el.textContent = msg;
  el.style.display = 'block';
}
```

**Navigation:**
- `URL key (3055)` → `window.open('http://localhost:3055')`
- `Header key (3057)` → `window.open('http://localhost:3057')`

---

## Port 3057 — DataPipe (API Key in Authorization Header)

### File: `api-key/apikey-header-server.js`

Same endpoints as port 3055. **Only change: read the key from `Authorization: Bearer` header, not URL.**

```js
// ✅ Key in Authorization header — not in URL, not in logs, not in Referer
function apiKeyAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const key = auth.startsWith('Bearer ') ? auth.slice(7) : null;

  if (!key) {
    return res.status(401).json({
      error: 'Missing API key',
      hint: 'Set Authorization: Bearer sk_test_demo_... header'
    });
  }

  const keyInfo = API_KEYS.get(key);
  if (!keyInfo) return res.status(401).json({ error: 'Invalid API key' });

  req.apiKey = key;
  req.keyInfo = keyInfo;
  next();
}
```

The weather/analytics response on port 3057 should say:
```json
{
  "key_in_header": true,
  "note": "Key was received in Authorization header — not in URL, not in access logs"
}
```

The `/api/logs` endpoint on port 3057 shows log lines where the URL is just `/api/weather` — no key visible:
```
[2026-06-16T10:23:01Z] GET /api/weather     ← clean, no key
[2026-06-16T10:23:04Z] GET /api/analytics   ← clean, no key
```

**Green banner:**
```
✅ SECURE: API key is read from Authorization: Bearer header.
URL is clean — key does not appear in logs, browser history, or Referer.
```

---

## Shared `package.json` at `api-key/`

```json
{
  "name": "api-key-demo",
  "version": "1.0.0",
  "scripts": {
    "url":    "node apikey-url-server.js",
    "guide":  "node guide-server.js",
    "header": "node apikey-header-server.js"
  },
  "dependencies": { "express": "^4.18.2", "cors": "^2.8.5" }
}
```

---

## README at `api-key/README.md`

### How It Works

```
API Key Auth (secure):
  Request:  GET /api/weather
            Authorization: Bearer sk_live_alice_a3f9b2c1...
            ↑ Not in URL — not in logs, not in browser history

API Key Auth (vulnerable):
  Request:  GET /api/weather?api_key=sk_live_alice_a3f9b2c1...
                              ↑ In URL → in every log file
```

### The exposure vector

Server access log (port 3055):
```
GET /api/weather?api_key=sk_live_alice_a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5 HTTP/1.1
```
Anyone with access to the server logs, CDN logs, or proxy logs sees the API key.

### Run the demo

```bash
cd auth-concepts/api-key
npm install
npm run url     # terminal 1 → localhost:3055 (key in URL)
npm run guide   # terminal 2 → localhost:3056 (concept guide)
npm run header  # terminal 3 → localhost:3057 (key in header)
```

### Walkthrough

1. Open **localhost:3055** — enter the demo key, click a weather request
2. Click "Check Server Logs" — see the full key in the log
3. Open **localhost:3056** — decode/encode, make requests, compare logs
4. Compare with **localhost:3057** — logs show clean URLs, key never exposed

---

## Key technical notes for Cursor

1. **Access log middleware runs first.** On port 3055, log the full request URL in a middleware BEFORE the API key auth middleware — this ensures every request (including rejected ones) appears in the log, which is what happens in real server logs.

2. **`/api/logs` endpoint must be public (no auth).** The log viewer in the guide fetches from `http://localhost:3055/api/logs` cross-origin without an API key. This endpoint should return the access log array without requiring auth — it's for demo purposes only.

3. **CORS must be enabled on both 3055 and 3057** with `origin: 'http://localhost:3056'`. The guide's live demo buttons call those servers cross-origin.

4. **Rate limit counter is per-key, not per-IP.** The `API_KEYS` Map stores `rateLimit` (max requests per minute) and the middleware should maintain a simple counter Map: `requestCounts = new Map()`. Reset counts every 60 seconds with `setInterval`. If count exceeds limit, return `429 Too Many Requests`.

5. **The demo key `sk_test_demo_...` is pre-seeded.** Populate `API_KEYS` with at least 3 keys (alice, bob, demo) so the guide's demo buttons work without requiring the user to log in or create a key.

6. **Log lines must include the FULL URL.** Use `req.url` (includes query string, e.g. `/api/weather?api_key=sk_live_...`) not `req.path` (excludes query string). This is the entire point of the vulnerability demo.
