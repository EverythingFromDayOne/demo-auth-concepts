# Cursor Prompt — 09: Passkeys & WebAuthn
# Ports: 3073 (vulnerable) · 3074 (guide) · 3075 (secure)

Build three Node.js Express servers in `auth-concepts/passkeys-webauthn/` that teach WebAuthn security.

---

## File structure to create

```
passkeys-webauthn/
  vulnerable-server.js  ← port 3073, vulnerable
  guide-server.js       ← port 3074, guide
  secure-server.js      ← port 3075, secure
  public/
    index.html          ← PassKey demo SPA (shared)
    style.css
    guide.html
    guide.css
  package.json
```

---

## package.json

```json
{
  "name": "passkeys-webauthn",
  "scripts": {
    "vulnerable": "node vulnerable-server.js",
    "guide": "node guide-server.js",
    "secure": "node secure-server.js",
    "start": "node vulnerable-server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "@simplewebauthn/server": "^9.0.0"
  }
}
```

---

## Shared app: PassKey demo

**In-memory stores:**
```js
const users = new Map();       // username → { id, username, credentials: [] }
const challenges = new Map();  // username → { challenge, expiresAt? }
```

**RP config:**
```js
const rpName = 'PassKey Demo';
const rpID = 'localhost';
const origin = 'http://localhost:PORT'; // PORT = 3073 or 3075
```

---

## vulnerable-server.js (port 3073) — vulnerable

Top comment: `* Terminal 1: cd auth-concepts/passkeys-webauthn && npm install && npm run vulnerable`

**Vulnerabilities:**
1. `userVerification: 'discouraged'` — PIN/biometric NOT required, just device presence
2. Counter NOT checked or updated — replay attacks possible
3. Single global challenge slot per user — concurrent sessions break each other
4. Challenge NOT deleted after use — same challenge reusable
5. No challenge expiry — stale challenges valid indefinitely

```js
// Registration options:
const options = await generateRegistrationOptions({
  rpName, rpID,
  userID: Buffer.from(username),
  userName: username,
  userVerification: 'discouraged', // ⚠️ No PIN/biometric required
  attestationType: 'none',
});
challenges.set(username, options.challenge); // ⚠️ No expiry, no deletion after use

// Authentication verification:
const verification = await verifyAuthenticationResponse({
  response: body,
  expectedChallenge: challenges.get(username), // ⚠️ Not deleted after use
  expectedOrigin: origin,
  expectedRPID: rpID,
  authenticator: credential,
  requireUserVerification: false, // ⚠️
});
// ⚠️ credential.counter NOT updated after successful auth
```

**Routes:**
- `POST /api/register/options` → generate registration options → store challenge
- `POST /api/register/verify` → verify registration → store credential
- `POST /api/auth/options` → generate authentication options → store challenge
- `POST /api/auth/verify` → verify authentication (no counter update, no challenge delete)
- `GET /api/me` → return session user if logged in
- `GET /api/config` → `{ mode: 'vulnerable', port: 3073 }`
- Static + catch-all → `public/index.html`

---

## secure-server.js (port 3075) — secure

Top comment: `* Terminal 3: cd auth-concepts/passkeys-webauthn && npm run secure`

**Fixes:**
1. `userVerification: 'required'` — PIN/biometric enforced
2. Counter updated after each auth + anomaly detection (counter going backwards → credential cloned → reject + alert)
3. Per-credential challenge Map, not per-user → concurrent sessions safe
4. Challenge deleted on use (single-use)
5. Challenge expiry: 5 minutes
6. `excludeCredentials` prevents registering same authenticator twice
7. Opaque user IDs via `crypto.randomUUID()`

```js
// Authentication verification:
const verification = await verifyAuthenticationResponse({
  response: body,
  expectedChallenge: storedChallenge.challenge,
  expectedOrigin: origin,
  expectedRPID: rpID,
  authenticator: credential,
  requireUserVerification: true, // ✅
});
challenges.delete(credentialId); // ✅ Single-use challenge

// Counter anomaly detection:
if (verification.authenticationInfo.newCounter <= credential.counter) {
  // Counter not increasing → possible cloned authenticator
  return res.status(401).json({ error: 'Counter anomaly — credential may be cloned' });
}
credential.counter = verification.authenticationInfo.newCounter; // ✅ Update counter
```

Same routes as vulnerable. `GET /api/config` → `{ mode: 'secure', port: 3075 }`.

---

## public/index.html — WebAuthn SPA (shared)

On load:
1. `fetch('/api/config')` → set banner:
   - vulnerable: orange — `⚠ WEAK WEBAUTHN: userVerification:discouraged, counter not updated, challenges reusable`
   - secure: green — `✅ HARDENED WEBAUTHN: userVerification:required, counter anomaly detection, single-use challenges`

**UI:**
- Username input
- "Register Passkey" button → `POST /api/register/options` → `navigator.credentials.create(options)` → `POST /api/register/verify`
- "Sign In with Passkey" button → `POST /api/auth/options` → `navigator.credentials.get(options)` → `POST /api/auth/verify`
- Status display: show registration/auth result, credential counter value (demonstrates the counter check)
- Registered credentials list

Note: use `@simplewebauthn/browser` CDN for client-side helpers, or implement raw `navigator.credentials` API calls manually.

---

## guide-server.js (port 3074) — guide

Top comment: `* Terminal 2: cd auth-concepts/passkeys-webauthn && npm run guide`

Thin static server serving `public/guide.html`.

**`public/guide.html`** — dark terminal-green theme:
- Title: "Passkeys & WebAuthn"
- Target switcher: "Vulnerable WebAuthn (3073)" dark slate, "Hardened WebAuthn (3075)" green `#16a34a`
- Content: registration ceremony diagram (challenge → create → attestation → store public key), authentication ceremony diagram (challenge → get → assertion → verify signature), what userVerification enforces, counter replay attack, authenticator cloning detection, comparison table.

---

## Inline Comments

Every `// ⚠️` and `// ✅` comment must answer three questions:

1. **What** is wrong (or fixed)
2. **Why** it is exploitable (or why the fix is safe)
3. **How** the attack works mechanically (step by step)

Format:
```js
// ⚠️ VULNERABLE — <one-line summary>
// <explanation: what is wrong, why it matters, how an attacker exploits it>
// <mechanical detail: what the attacker does step by step, what they gain>
const badThing = ...;

// ✅ PROTECTED — <one-line summary>
// <explanation: what the fix does and why it closes the attack vector>
// <mechanical detail: what would need to be true for this to still fail>
const goodThing = ...;
```

**Never shorten an existing comment. Only expand.**
Annotate **vulnerable servers and secure servers only** — never guide servers.

### passkeys-webauthn

**`passkeys-webauthn/vulnerable-server.js`** — root causes to annotate:
- `userVerification: 'discouraged'`: the authenticator is not required to verify the user's identity (PIN, biometric, or password). Device presence alone is sufficient. If an attacker gains physical access to the user's device (unlocked laptop, unattended phone), they can complete authentication without any user secret.
- Counter not checked or updated: WebAuthn authenticators maintain a monotonically increasing counter. If a credential is cloned (hardware attack), the clone and the original both start incrementing from the same baseline — the server can detect this because it will receive the same counter value twice. Skipping the counter check makes cloned authenticators undetectable.
- Challenges reused: after a successful authentication, the challenge remains in the Map. The same challenge can be used again in a replay attack — the authenticator's signed response is valid for as long as the challenge exists.

**`passkeys-webauthn/secure-server.js`** — fixes to annotate:
- `userVerification: 'required'`: the authenticator must verify the user's identity before releasing the private key. A stolen device is useless without the PIN or biometric.
- Counter anomaly detection: the server stores the last-seen counter value. If the new counter is not strictly greater than the stored value, the credential may be cloned — the server rejects the authentication and can alert the user. The counter is updated on every successful authentication.
- Single-use challenges: the challenge Map entry is deleted immediately after successful verification. Replaying a captured response fails because the expected challenge no longer exists.

---

## README

Follow this canonical section order for this concept's `README.md`. Use `---` between every section:

```
# [Concept Name] — [App Name]
(one-paragraph description)
---
## Port Reference
---
## How It Works
---
## The Vulnerability
---
## The Fix
---
## How to Run
---
## Demo Walkthrough
---
## Hardened Demo
---
## Vulnerable Lines
---
## Defense Details
---
## Credentials   ← only if needed; always last
```

**Section rename mappings:**

| Old name | Canonical name |
|----------|----------------|
| `## How it works` | `## How It Works` |
| `## Vulnerability (port XXXX)` | `## The Vulnerability` |
| `## Fix (port XXXX)` | `## The Fix` |
| `## Run the demo` / `## Run` | `## How to Run` |
| `## Walkthrough` | `## Demo Walkthrough` |
| `## Hardened Demo` / `## Protected Demo` | `## Hardened Demo` |
| `## Key concepts` | `## Defense Details` |
| `## Demo credentials` / `## Demo API keys` | `## Credentials` |
| `## Ports` | `## Port Reference` |

**Script names to fix:**

| Old | Correct |
|-----|---------|
| `npm run basic` | `npm run vulnerable` |
| `npm run session` (in basic-digest) | `npm run secure` |
| `npm run url` | `npm run vulnerable` |
| `npm run header` | `npm run secure` |
| `npm run weak` | `npm run vulnerable` |
| `npm run strong` | `npm run secure` |
| `npm run hardened` | `npm run secure` |
| `npm run session` (in session/) | `npm run vulnerable` |

### Per-concept README instructions — passkeys-webauthn (CloudPortal)

This README is very brief — needs full content built from scratch.

**`## How It Works`** — expand with both ceremonies:

```
REGISTRATION CEREMONY:
  1. User clicks "Register Passkey" → POST /api/register/begin
  2. Server: generateRegistrationOptions({ rpID, userID, userVerification, ... })
             → { challenge, rp, user, ... }
  3. Browser: navigator.credentials.create(options)
             → authenticator creates key pair
             → private key stored in authenticator (TPM, Secure Enclave)
             → public key + attestation in response
  4. POST /api/register/complete { attestation }
  5. Server: verifyRegistrationResponse() → stores { credentialID, publicKey, counter: 0 }

AUTHENTICATION CEREMONY:
  1. User clicks "Sign In with Passkey" → POST /api/auth/begin
  2. Server: generateAuthenticationOptions({ rpID, challenge, ... })
  3. Browser: navigator.credentials.get(options)
             → authenticator signs challenge with private key
             → signature + authenticatorData (includes counter) in response
  4. POST /api/auth/complete { assertion }
  5. Server: verifyAuthenticationResponse()
             → verifies signature with stored public key
             → [hardened] checks counter strictly increases
             → [hardened] deletes challenge (single-use)
             → issues session token
```

Note: WebAuthn requires a secure context. `http://localhost` is valid without HTTPS.

**`## The Vulnerability`** — expand:

**`userVerification: 'discouraged'`** — the authenticator proves *device possession* but not *user identity*. An unlocked laptop, unattended phone, or hardware key without a PIN satisfies the assertion. Physical access to the device = full authentication.

**Counter not updated:**
```
WebAuthn spec: authenticator increments a counter on each assertion.
Server should check: new_counter > stored_counter

If a credential is cloned (hardware attack against a security key):
  - Original key counter: 5
  - Cloned key counter: also 5 (snapshot at time of clone)
  - Server stores: counter = 5

  Original auth: counter → 6. Server: 6 > 5? Yes → accept. Update stored: 6.
  Clone auth:    counter → 6. Server: 6 > 6? No  → [should reject, but doesn't without this check]
  Without counter check: clone is accepted indefinitely.
```

**Reusable challenges:** if `challenges.delete(username)` is never called after auth, an attacker who captures a valid signed assertion can replay it. The challenge will still match.

**`## Vulnerable Lines`**:
```js
// ⚠️ VULNERABLE — device presence sufficient; no PIN or biometric required
const options = await generateRegistrationOptions({
  userVerification: 'discouraged',  // ← attacker with physical device access can authenticate
});

// ⚠️ VULNERABLE — challenge not deleted after use; same assertion can be replayed
challenges.set(username, options.challenge);
// ... after successful auth:
// challenges.delete(username) ← MISSING

// ⚠️ VULNERABLE — counter not checked; cloned authenticators undetectable
// After verifyAuthenticationResponse():
// credential.counter = authInfo.newCounter; ← MISSING
```

**`## Defense Details`**:
- `### userVerification: required` — enforces PIN or biometric at the authenticator. Device possession alone is insufficient. A stolen device cannot authenticate without the user's secret.
- `### Counter anomaly detection` — counter must strictly increase. A counter that doesn't increase (or decreases) signals a cloned credential. The server rejects the auth and should alert the user.
- `### Single-use challenges` — challenge deleted immediately after successful auth. A replayed assertion finds no matching challenge and is rejected.
- `### Why passkeys are phishing-resistant` — origin is bound into the authenticatorData. An authenticator will not sign a challenge for `attacker.com` pretending to be `localhost`. Even a perfect phishing clone of the UI cannot extract the assertion for the real origin.

**`## Hardened Demo`**:
1. Open `localhost:3073` — register a passkey for `alice`, note the counter value in the UI
2. Authenticate — counter increments. Note that no PIN/biometric was required (macOS/Windows may still prompt depending on platform — the server doesn't enforce it)
3. Open `localhost:3075` — register and authenticate — biometric/PIN enforced by `userVerification: required`
4. Try replaying a captured authentication response on `localhost:3075` — challenge mismatch (single-use)
5. Simulate counter anomaly: manually set stored counter higher than returned counter → rejected on `localhost:3075`
