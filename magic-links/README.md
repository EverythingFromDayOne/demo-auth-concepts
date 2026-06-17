# Magic Links — Inkwell Demo

Inkwell is a personal writing platform with passwordless email authentication. Users enter their email, receive a one-time sign-in link, and click it to authenticate.

## How it works

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
```

| Port | Server | Role |
|------|--------|------|
| 3076 | `vulnerable-server.js` | Weak — Math.random, no expiry, reusable, no rate limit |
| 3077 | `guide-server.js` | Magic Links & Passwordless Lab |
| 3078 | `secure-server.js` | Hardened — crypto.randomBytes, 15-min expiry, single-use, rate limited |

## Run the demo

```bash
cd auth-concepts/magic-links
npm install
npm run vulnerable  # terminal 1 → localhost:3076
npm run guide       # terminal 2 → localhost:3077
npm run secure      # terminal 3 → localhost:3078
```

## Walkthrough

1. Open **localhost:3077** — read the flow diagram and entropy comparison.
2. Open **localhost:3076** — enter `alice@example.com`, click **Send Magic Link**, then **Open Link →**.
3. Click **Open Again (replay test)** — it works again. Same link, second session.
4. Open **localhost:3078** — same flow. After clicking the link, **Open Again** → `/?error=invalid_token`.
5. On **3078**, send a magic link 4 times with the same email. The 4th shows success but no demo link — rate limiting.
6. On **3077**, run **Request link + replay on :3076** to see HTTP status codes side-by-side.

## Key concepts

**The token IS the credential** — whoever has the magic link can authenticate. Strong randomness, short lifetime, and single-use are essential.

**Email access = authentication** — magic links transfer trust to email security. Best for lower-stakes apps where password fatigue is the bigger risk.

**Delete before issue** — the token is removed from the store before the session is created, preventing race-condition replay.

**Same response for all outcomes** — rate-limited, unknown email, and success all return the same message to prevent email enumeration.
