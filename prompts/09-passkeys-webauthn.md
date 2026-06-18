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
