# Magic Links — Inkwell

Inkwell is a personal writing platform with passwordless email authentication. Users enter their email, receive a one-time sign-in link, and click it to authenticate. The demo contrasts weak token generation and lifetime with hardened entropy, expiry, single-use enforcement, and rate limiting.

---

## Port Reference

| Port | File | Role |
|------|------|------|
| 3076 | `vulnerable-server.js` | Vulnerable — Math.random, no expiry, reusable, no rate limit |
| 3077 | `guide-server.js` | Concept guide — Magic Links & Passwordless Lab |
| 3078 | `secure-server.js` | Hardened — crypto.randomBytes, 15-min expiry, single-use, rate limited |

---

## How It Works

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

```
TOKEN LIFECYCLE (hardened):

  POST /api/auth/send-link { email }
          ↓
  [VULNERABLE] token = Math.random().toString(36)... (~30 bits)
  [HARDENED]   token = crypto.randomBytes(32).toString('hex') (256 bits)
          ↓
  magicTokens.set(token, { email, expiresAt: now + 15min })
          ↓
  "Email sent" (console.log in demo) — token shown in response for demo purposes

  GET /auth/verify?token=<token>
          ↓
  Look up token → check expiry
          ↓
  [VULNERABLE] token NOT deleted — reusable forever
  [HARDENED]   magicTokens.delete(token) — single use, before session creation
          ↓
  sessions.set(sid, { email, createdAt })
  Set-Cookie: iw_session=<sid>; Path=/; HttpOnly; SameSite=Lax
  302 /dashboard
```

---

## The Vulnerability

```js
// Math.random() uses a PRNG seeded from timing and OS entropy sources.
// Output space for Math.random().toString(36).slice(2): ~15 bits per call
// Two calls concatenated: ~30 bits effective entropy
// ~1,073,741,824 possible tokens

// Compare:
// crypto.randomBytes(32).toString('hex'): 256 bits
// 2^256 ≈ 10^77 possible tokens — not brute-forceable
```

An attacker who observes the server startup time can narrow the seed space. Tools exist specifically to predict V8's Math.random() output given a starting seed.

Without expiry: tokens issued a year ago in a forwarded email are still valid. Without single-use: email providers that scan links for malware detection consume the token, potentially before the intended user clicks it.

---

## The Fix

The hardened server on port 3078 generates tokens with `crypto.randomBytes(32)` (256 bits of entropy), sets a 15-minute expiry on every link, deletes the token before creating the session so each link works exactly once, returns the same response whether or not the email is registered (preventing enumeration), and limits send requests to three links per email per hour.

---

## How to Run

```bash
cd auth-concepts/magic-links
npm install
npm run vulnerable  # terminal 1 → localhost:3076
npm run guide       # terminal 2 → localhost:3077
npm run secure      # terminal 3 → localhost:3078
```

---

## Demo Walkthrough

1. Open `http://localhost:3077` — read the flow diagram and entropy comparison.
2. Open `http://localhost:3076` — enter `alice@example.com`, click **Send Magic Link**, then **Open Link →**.
3. Click **Open Again (replay test)** — it works again. Same link, second session — the token was never consumed.
4. On `http://localhost:3077`, run **Request link + replay on :3076** to see HTTP status codes side-by-side.

---

## Hardened Demo

1. Open `localhost:3076` — send link to `alice@example.com`, click **Open Link**.
2. Click **Open Again (replay)** — second session created — link is not consumed.
3. Open `localhost:3078` — send link, click once — authenticated.
4. Try the same token again — `invalid_token` — single-use enforced.
5. Send a link 4 times to the same email on `3078` — 4th attempt: rate limited (no demo link in response).
6. Inspect the two token values side-by-side in the demo banner — length and entropy comparison.

---

## Vulnerable Lines

```js
// ⚠️ VULNERABLE — Math.random() PRNG; ~30 bits of entropy; offline predictable
function generateToken() {
  return Math.random().toString(36).slice(2) +
         Math.random().toString(36).slice(2);
}

// ⚠️ VULNERABLE — no expiresAt; token valid indefinitely
magicTokens.set(token, { email: email, createdAt: Date.now() });

// ⚠️ VULNERABLE — token NOT deleted after use; same link works unlimited times
// Email scanners auto-click links on delivery — scanner consumes first session,
// user's click creates a second. Both sessions are valid.
const stored = magicTokens.get(token);
sessions.set(sid, { email: stored.email, createdAt: Date.now() });
// magicTokens.delete(token) ← MISSING

// ⚠️ VULNERABLE — no rate limiting; attacker can flood inbox to exhaust token space
app.post('/api/auth/send-link', function (req, res) {
  const token = generateToken();
  // no rate check
```

---

## Defense Details

### Entropy requirement

256 bits from a CSPRNG. V8's PRNG output is deterministic given the seed. A 30-bit space means brute-force over a network is feasible.

### Token expiry

15 minutes matches typical user behaviour (open email, click link). Shorter reduces risk but increases friction if the user is distracted.

### Delete before session

Token deleted before session is written. If the write fails, no valid session exists. Prevents race-condition replay where two requests arrive simultaneously with the same token.

### Same response for all outcomes

`{ message: "If that email is registered, a link was sent" }` whether the email exists or not. Prevents email enumeration attacks.

### Rate limiting

Three links per email per hour. An attacker flooding links could (a) spam the target and (b) increase statistical chance of predicting a Math.random() token from timing observations.

**The token IS the credential** — whoever has the magic link can authenticate. Strong randomness, short lifetime, and single-use are essential.

**Email access = authentication** — magic links transfer trust to email security. Best for lower-stakes apps where password fatigue is the bigger risk.
