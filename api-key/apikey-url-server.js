/*
 * Terminal 1: cd auth-concepts/api-key && npm install && npm run url
 * DataPipe — API key in URL query param (port 3055)
 */

const path = require('path');
const express = require('express');
const cors = require('cors');

const app = express();
const PORT = 3055;

app.use(cors({ origin: 'http://localhost:3056' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

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

app.get('/api/config', function (_req, res) {
  res.json({ mode: 'vulnerable', port: PORT });
});

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

app.get('*', function (_req, res) {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, function () {
  console.log('DataPipe (URL key) running at http://localhost:' + PORT);
});
