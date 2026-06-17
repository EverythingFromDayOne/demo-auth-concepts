# Passkeys / WebAuthn — CloudPortal Demo

CloudPortal replaces passwords (or supplements them) with passkeys using WebAuthn.

## How it works

```txt
Registration:
  GET  /api/register/begin   (requires password session)
  -> browser: navigator.credentials.create()
  -> POST /api/register/complete
  -> server stores { credentialID, publicKey, counter }

Authentication:
  POST /api/auth/begin
  -> browser: navigator.credentials.get()
  -> POST /api/auth/complete
  -> server verifies signature + challenge + counter, returns session token
```

- Weak (`3073`): UV discouraged, no counter update, reusable/long-lived challenge
- Hardened (`3075`): UV required, counter update, single-use challenge with expiry

## Prerequisites

WebAuthn needs a secure context. `http://localhost` is valid, so this demo works without HTTPS cert setup.

## Run

```bash
cd auth-concepts/passkeys-webauthn
npm install
npm run vulnerable  # localhost:3073
npm run guide       # localhost:3074
npm run secure      # localhost:3075
```

## Walkthrough

1. Open `http://localhost:3074` for the concept guide.
2. On `3073`, login with password and register a passkey.
3. Sign out and use passkey login; weak server uses low-assurance verification.
4. Repeat on `3075`; biometric/PIN is required and challenge handling is hardened.
