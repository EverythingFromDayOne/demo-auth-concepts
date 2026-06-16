/*
 * Terminal 1: cd auth-concepts/api-key && npm install && npm run url
 * DataPipe — API key in URL query param (port 3055)
 */

const express = require('express');
const cors = require('cors');

const app = express();
const PORT = 3055;

app.use(cors({ origin: 'http://localhost:3056' }));
app.use(express.json());

// In a real system these would be in a database, hashed.
// For demo: plain keys with metadata.
const API_KEYS = new Map([
  ['sk_live_alice_a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5', {
    owner: 'alice', plan: 'pro', scopes: ['weather', 'analytics'], rateLimit: 1000,
  }],
  ['sk_live_bob_b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9', {
    owner: 'bob', plan: 'free', scopes: ['weather'], rateLimit: 100,
  }],
  ['sk_test_demo_c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0', {
    owner: 'demo', plan: 'free', scopes: ['weather'], rateLimit: 50,
  }],
]);

const accessLog = [];
const requestCounts = new Map();

setInterval(function () {
  requestCounts.clear();
}, 60000);

// Access log runs first — captures full URL including api_key query param
app.use(function (req, res, next) {
  accessLog.push({ time: new Date().toISOString(), method: req.method, url: req.url });
  if (accessLog.length > 50) accessLog.shift();
  console.log('[ACCESS LOG] ' + new Date().toISOString() + ' ' + req.method + ' ' + req.url);
  next();
});

// ⚠️ VULNERABILITY: API key in URL query parameter
// → Appears in: server access logs, browser history, Referer headers, CDN logs
function apiKeyAuth(req, res, next) {
  const key = req.query.api_key;

  if (!key) {
    return res.status(401).json({
      error: 'Missing API key',
      hint: 'Add ?api_key=sk_test_demo_c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0 to the URL',
    });
  }

  const keyInfo = API_KEYS.get(key);
  if (!keyInfo) return res.status(401).json({ error: 'Invalid API key' });

  req.apiKey = key;
  req.keyInfo = keyInfo;
  next();
}

function rateLimit(req, res, next) {
  const count = (requestCounts.get(req.apiKey) || 0) + 1;
  requestCounts.set(req.apiKey, count);
  if (count > req.keyInfo.rateLimit) {
    return res.status(429).json({ error: 'Rate limit exceeded', limit: req.keyInfo.rateLimit });
  }
  next();
}

const PORTAL_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DataPipe API — Developer Playground</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0f172a;
      color: #f1f5f9;
      min-height: 100vh;
    }
    .banner {
      background: #422006;
      border-bottom: 2px solid #f59e0b;
      color: #fcd34d;
      padding: 0.65rem 1.5rem;
      font-size: 0.85rem;
      line-height: 1.5;
    }
    .header {
      background: #1e293b;
      border-bottom: 1px solid #334155;
      padding: 1.25rem 2rem;
    }
    .header h1 { font-size: 1.35rem; font-weight: 700; }
    .header h1 span { color: #10b981; }
    .tagline { font-size: 0.85rem; color: #94a3b8; margin-top: 0.25rem; }
    .container { max-width: 960px; margin: 0 auto; padding: 2rem 1.5rem; }
    .card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }
    .card h2 { font-size: 1rem; margin-bottom: 1rem; color: #e2e8f0; }
    label { display: block; font-size: 0.8rem; color: #94a3b8; margin-bottom: 0.4rem; }
    .api-input {
      width: 100%;
      padding: 0.6rem 0.75rem;
      background: #0f172a;
      border: 1px solid #475569;
      border-radius: 6px;
      color: #10b981;
      font-family: 'Courier New', Courier, monospace;
      font-size: 0.82rem;
      margin-bottom: 0.75rem;
    }
    .url-preview {
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 6px;
      padding: 0.75rem;
      font-family: 'Courier New', Courier, monospace;
      font-size: 0.78rem;
      color: #fbbf24;
      word-break: break-all;
      margin-bottom: 1rem;
      line-height: 1.5;
    }
    .btn-row { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1rem; }
    .btn {
      background: #10b981;
      color: #0f172a;
      border: none;
      padding: 0.5rem 1rem;
      border-radius: 6px;
      font-size: 0.85rem;
      font-weight: 600;
      cursor: pointer;
    }
    .btn:hover { background: #34d399; }
    .btn.secondary { background: #334155; color: #e2e8f0; }
    .btn.secondary:hover { background: #475569; }
    pre.response {
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 6px;
      padding: 1rem;
      font-size: 0.78rem;
      color: #cbd5e1;
      white-space: pre-wrap;
      word-break: break-all;
      min-height: 80px;
      font-family: 'Courier New', Courier, monospace;
    }
    .log-line { color: #f87171; }
  </style>
</head>
<body>
  <div class="banner">
    ⚠ VULNERABLE: API key is passed as a URL query parameter (?api_key=).
    It appears in server access logs, browser history, and Referer headers.
  </div>
  <header class="header">
    <h1>Data<span>Pipe</span></h1>
    <p class="tagline">Real-time data for your applications</p>
  </header>
  <div class="container">
    <div class="card">
      <h2>Try the API</h2>
      <label for="api-key">Your API Key</label>
      <input class="api-input" type="text" id="api-key"
        value="sk_test_demo_c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0"
        placeholder="sk_test_...">
      <label>Request URL (updates as you type)</label>
      <div class="url-preview" id="url-preview">http://localhost:3055/api/weather?api_key=...</div>
      <div class="btn-row">
        <button class="btn" id="btn-weather">GET /api/weather</button>
        <button class="btn" id="btn-analytics">GET /api/analytics</button>
        <button class="btn secondary" id="btn-key-info">GET /api/key-info</button>
      </div>
      <label>Response</label>
      <pre class="response" id="response-output">Click an endpoint to send a request</pre>
    </div>
    <div class="card">
      <h2>Server Access Logs</h2>
      <p style="font-size:0.85rem;color:#94a3b8;margin-bottom:0.75rem">
        Every request is logged with the full URL — including your API key in the query string.
      </p>
      <div class="btn-row">
        <button class="btn secondary" id="btn-refresh-logs">Refresh Logs</button>
      </div>
      <pre class="response" id="log-output">Make a request, then refresh logs</pre>
    </div>
  </div>
  <script>
    var base = 'http://localhost:3055';

    function getKey() {
      return document.getElementById('api-key').value.trim();
    }

    function updatePreview() {
      var key = getKey();
      document.getElementById('url-preview').textContent =
        base + '/api/weather?api_key=' + encodeURIComponent(key);
    }

    document.getElementById('api-key').addEventListener('input', updatePreview);
    updatePreview();

    function callEndpoint(path) {
      var key = getKey();
      var url = base + path + '?api_key=' + encodeURIComponent(key);
      fetch(url)
        .then(function (res) { return res.json().then(function (d) { return { ok: res.ok, data: d }; }); })
        .then(function (r) {
          document.getElementById('response-output').textContent = JSON.stringify(r.data, null, 2);
          refreshLogs();
        })
        .catch(function (e) {
          document.getElementById('response-output').textContent = 'Error: ' + e.message;
        });
    }

    document.getElementById('btn-weather').addEventListener('click', function () { callEndpoint('/api/weather'); });
    document.getElementById('btn-analytics').addEventListener('click', function () { callEndpoint('/api/analytics'); });
    document.getElementById('btn-key-info').addEventListener('click', function () { callEndpoint('/api/key-info'); });

    function refreshLogs() {
      fetch(base + '/api/logs')
        .then(function (res) { return res.json(); })
        .then(function (data) {
          document.getElementById('log-output').textContent =
            data.note + '\\n\\n' +
            data.log.map(function (l) {
              return '[' + l.time + '] ' + l.method + ' ' + l.url;
            }).join('\\n');
        });
    }

    document.getElementById('btn-refresh-logs').addEventListener('click', refreshLogs);
  </script>
</body>
</html>`;

app.get('/api/logs', function (req, res) {
  res.json({
    note: 'These are simulated server access logs. API keys in URLs appear here.',
    log: accessLog.slice(-10),
  });
});

app.get('/api/weather', apiKeyAuth, rateLimit, function (req, res) {
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
    retrieved_with_key: req.apiKey,
    warning: '⚠️ This key was sent in the URL — check your server logs',
  });
});

app.get('/api/analytics', apiKeyAuth, rateLimit, function (req, res) {
  if (!req.keyInfo.scopes.includes('analytics')) {
    return res.status(403).json({
      error: 'analytics scope required — upgrade to Pro plan',
      current_plan: req.keyInfo.plan,
    });
  }
  res.json({
    pageviews_today: 14239,
    unique_visitors: 3817,
    bounce_rate: 0.42,
    top_pages: ['/docs', '/api', '/pricing'],
    key_owner: req.keyInfo.owner,
  });
});

app.get('/api/key-info', apiKeyAuth, rateLimit, function (req, res) {
  res.json({
    owner: req.keyInfo.owner,
    plan: req.keyInfo.plan,
    scopes: req.keyInfo.scopes,
    rate_limit: req.keyInfo.rateLimit,
    key_prefix: req.apiKey.substring(0, 12) + '...',
    key_in_url: true,
    warning: 'This key was passed as a URL parameter (?api_key=). See server logs.',
  });
});

app.get('/', function (req, res) {
  res.send(PORTAL_HTML);
});

app.listen(PORT, function () {
  console.log('DataPipe (URL key) running at http://localhost:' + PORT);
});
