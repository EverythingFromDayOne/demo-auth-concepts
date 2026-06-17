# MFA & TOTP — SecureVault Demo

SecureVault uses two-phase login with TOTP-based MFA for sensitive vault access.

## How it works

```txt
Phase 1 (password):
  POST /api/login { username, password }
  -> { mfaRequired: true, pendingToken }

Phase 2 (TOTP):
  POST /api/verify-totp { pendingToken, code }
  -> { token }  (full authenticated session)

Protected API:
  GET /api/vault
  Authorization: Bearer <token>
```

Vulnerable vs hardened:

- `3070` weak: `window:10`, no replay tracking, no rate limit
- `3072` hardened: `window:1`, replay prevention, lockout after 5 failures, backup codes

## TOTP setup

Alice secret (demo): `JBSWY3DPEHPK3PXP`

```txt
otpauth://totp/SecureVault:alice?secret=JBSWY3DPEHPK3PXP&issuer=SecureVault
```

The servers include demo helper endpoints:

- `GET /api/current-totp?username=alice`
- `GET /api/totp-qr?username=alice`

Both are demo-only and never belong in production.

## Run

```bash
cd auth-concepts/mfa-totp
npm install
npm run vulnerable  # localhost:3070
npm run guide       # localhost:3071
npm run secure      # localhost:3072
```

## Demo walkthrough

1. Open `http://localhost:3071` and review TOTP math + replay demo.
2. Open `http://localhost:3070`, login as `alice / pass1234`, enter helper code.
3. Re-submit the same code quickly after a new login; replay is accepted.
4. Open `http://localhost:3072` and repeat; replay is rejected.
5. Submit wrong codes 5 times on `3072`; observe lockout.
6. Use a backup code to complete login on `3072`.
7. Login as `bob / qwerty123` on either server; bob has no MFA and goes straight in.
