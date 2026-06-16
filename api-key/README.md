# API Key Authentication — DataPipe Demo

DataPipe is a weather and analytics data API. This demo shows why passing API keys as URL query parameters is dangerous, and how the `Authorization: Bearer` header fixes the exposure.

## How It Works

```
API Key Auth (secure):
  Request:  GET /api/weather
            Authorization: Bearer sk_live_alice_a3f9b2c1...
            ↑ Not in URL — not in logs, not in browser history

API Key Auth (vulnerable):
  Request:  GET /api/weather?api_key=sk_live_alice_a3f9b2c1...
                              ↑ In URL → in every log file
```

## The exposure vector

Server access log (port 3055):

```
GET /api/weather?api_key=sk_live_alice_a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5 HTTP/1.1
```

Anyone with access to the server logs, CDN logs, or proxy logs sees the API key.

## Run the demo

```bash
cd auth-concepts/api-key
npm install
npm run url     # terminal 1 → localhost:3055 (key in URL)
npm run guide   # terminal 2 → localhost:3056 (concept guide)
npm run header  # terminal 3 → localhost:3057 (key in header)
```

## Walkthrough

1. Open **localhost:3055** — enter the demo key, click a weather request
2. Click "Refresh Logs" — see the full key in the access log
3. Open **localhost:3056** — make requests, compare URL vs header approaches
4. Open **localhost:3057** — logs show clean URLs (`/api/weather`), key never in the path

## Ports

| Port | Server | Role |
|------|--------|------|
| 3055 | `apikey-url-server.js` | Vulnerable — `?api_key=sk_...` in URL |
| 3056 | `guide-server.js` | Concept guide — exposure vectors + live demo |
| 3057 | `apikey-header-server.js` | Secure — `Authorization: Bearer sk_...` |

## Demo API keys

| Key | Owner | Scopes |
|-----|-------|--------|
| `sk_test_demo_c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0` | demo | weather |
| `sk_live_bob_b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9` | bob | weather |
| `sk_live_alice_a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5` | alice | weather, analytics |
