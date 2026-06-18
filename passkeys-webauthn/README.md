# Passkeys / WebAuthn — CloudPortal

CloudPortal replaces passwords (or supplements them) with passkeys using the WebAuthn API. The demo runs registration and authentication ceremonies in the browser, stores public keys server-side, and contrasts weak verification settings with hardened user verification, counter tracking, and single-use challenges.

WebAuthn requires a secure context. `http://localhost` qualifies, so this demo works without HTTPS certificate setup.

---

## Port Reference

| Port | File | Role |
|------|------|------|
| 3073 | `vulnerable-server.js` | Vulnerable — UV discouraged, no counter update, reusable challenge |
| 3074 | `guide-server.js` | Concept guide — registration and authentication ceremonies |
| 3075 | `secure-server.js` | Hardened — UV required, counter update, single-use challenge |

---

## How It Works

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

---

## The Vulnerability

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

**Reusable challenges:**

If `challenges.delete(username)` is never called after auth, an attacker who captures a valid signed assertion can replay it. The challenge will still match.

---

## The Fix

The hardened server on port 3075 sets `userVerification: 'required'` so the authenticator must verify a PIN or biometric before signing, updates the stored counter after every successful authentication to detect cloned credentials, and deletes challenges immediately after use so captured assertions cannot be replayed.

---

## How to Run

```bash
cd auth-concepts/passkeys-webauthn
npm install
npm run vulnerable  # terminal 1 → localhost:3073
npm run guide       # terminal 2 → localhost:3074
npm run secure      # terminal 3 → localhost:3075
```

---

## Demo Walkthrough

1. Open `http://localhost:3074` for the concept guide.
2. On `http://localhost:3073`, login with `alice / pass1234` and register a passkey.
3. Sign out and authenticate with the passkey — the weak server accepts device presence alone (`userVerification: 'discouraged'`).
4. Note the counter value in the UI after authentication — it does not increment on the vulnerable server.
5. Observe that no PIN or biometric is required by server policy (platform may still prompt depending on OS settings).

---

## Hardened Demo

1. Open `localhost:3073` — register a passkey for `alice`, note the counter value in the UI.
2. Authenticate — counter increments. Note that no PIN/biometric was required (macOS/Windows may still prompt depending on platform — the server doesn't require it).
3. Open `localhost:3075` — register and authenticate — biometric/PIN enforced by `userVerification: required`.
4. Try replaying a captured authentication response on `3075` — challenge mismatch (single-use).
5. Simulate counter anomaly: manually set stored counter higher than returned counter → rejected on `3075`.

---

## Vulnerable Lines

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

---

## Defense Details

### userVerification: required

Enforces PIN or biometric at the authenticator. Device possession alone is insufficient. A stolen device cannot authenticate without the user's secret.

### Counter anomaly detection

Counter must strictly increase. A counter that doesn't increase (or decreases) signals a cloned credential. The server rejects the auth and should alert the user.

### Single-use challenges

Challenge deleted immediately after successful auth. A replayed assertion finds no matching challenge and is rejected.

### Why passkeys are phishing-resistant

Origin is bound into the authenticatorData. An authenticator will not sign a challenge for `attacker.com` pretending to be `localhost`. Even a perfect phishing clone of the UI cannot extract the assertion for the real origin.

---

## Credentials

| Username | Password |
|----------|----------|
| alice | pass1234 |
