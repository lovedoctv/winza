# WINZA production foundation

This repository now has a safe deployment boundary and account-security API for the existing front-end.
It starts in `sandbox` mode and intentionally rejects the idea that browser
balances are real funds. KYC, withdrawal-request scaffolding, and deposits via
Paystack/OPay exist, but there is still no wagering or actual payout system yet.
Authentication requires PostgreSQL and environment secrets before it can run.

## Run locally

1. Install Node.js 20 or newer.
2. Run `npm install` to install the PostgreSQL driver.
3. Apply `schema.sql` to a managed PostgreSQL database (fresh install). If you already
   applied an earlier version of `schema.sql`, run `migration_002_phone_kyc.sql` and
   `migration_004_payments.sql` instead — they only add columns/tables, safe to run
   against an existing database.
4. Copy `.env.example` values into your deployment secret manager and generate distinct `JWT_SECRET` and `MFA_ENCRYPTION_KEY` values.
5. Run `npm start`.
6. Open `http://127.0.0.1:3000`.
7. Create at least one staff account so the admin panel is usable — see "Staff accounts" below.

## Account API

All endpoint bodies are JSON. Access tokens are returned only after a successful
login/verify and must be sent as `Authorization: Bearer <token>`.

**Players** register and log in with phone + OTP — the same endpoint handles both;
the first successful verification for a phone number creates the account.
- `POST /api/v1/auth/otp/request` — `{ phone }`. Sends a 6-digit code, 5-minute expiry.
  No SMS provider is configured out of the box — see `OTP_SMS_WEBHOOK_URL` in
  `.env.example`. Until that's wired up, non-live responses include a `devCode`
  field so you can test the flow; this is structurally disabled once `WINZA_MODE=live`.
- `POST /api/v1/auth/otp/verify` — `{ phone, code }`. Returns `{ user, accessToken, isNewAccount }`.

No KYC fields are collected at registration — a new account starts with
`kycStatus: "not_verified"` and nothing else is asked.

**Staff** (`support`/`risk`/`admin`/`owner`) use email + password instead, since
there's no self-serve signup for privileged roles — see "Staff accounts" below.
- `POST /api/v1/auth/register`, `POST /api/v1/auth/login` — same as before.
- `POST /api/v1/auth/mfa/enroll`, `/confirm`, `/disable` — TOTP, unchanged.

Shared:
- `GET /api/v1/auth/me` and `POST /api/v1/auth/logout` — authenticated session management.
- `POST /api/v1/auth/password-reset/request` and `/confirm` — email-based, so only
  meaningful for staff accounts that have an email set.

## Wallet

- `GET /api/v1/wallet/me` — authenticated, read-only balance summary.
- `POST /api/v1/wallet/withdrawal-requests` — `{ amount }`. Moves funds from
  `cash_available` into `pending_withdrawal` (never pays out automatically — staff
  review is a later step). **Blocked with 403 if KYC is required and the caller
  isn't `verified`** — see `platform_settings.kyc_required_for_withdrawal`, a
  backend-controlled flag, not a client one.

A wallet row is still created automatically, in the same transaction as the user
row, for every new account. There is still no route that lets anyone adjust a
balance directly — money only moves through `wallet.postTransaction()`, following
the same idempotency-key/row-locking/append-only-ledger guarantees as before.

## Deposits (Paystack / OPay)

- `POST /api/v1/wallet/deposits/initialize` — `{ provider: "paystack"|"opay", amount }`.
  Creates a `payment_intents` row, calls the provider's own API, and returns
  `{ redirectUrl, reference }`. The client navigates the player's full browser
  to `redirectUrl` — the provider's own hosted payment page — so card details
  never touch this server and no CSP/script changes were needed.
- A provider only shows up in this flow (and in `depositProviders` on
  `GET /api/v1/public/config`) once its env vars are set — see `.env.example`.
  With neither set, deposits behave exactly as before (disabled, with the
  existing "Deposits not configured" message).
- **The wallet is only ever credited once the provider confirms success**,
  via two paths that both funnel into the same idempotent `creditDeposit()`:
  - `POST /api/v1/payments/webhook/{paystack,opay}` — the authoritative path.
    Verifies the request signature (`x-paystack-signature` HMAC-SHA512 for
    Paystack; `Signature` header for OPay) before trusting anything in the body.
  - `GET /api/v1/payments/callback/{paystack,opay}` — the browser redirect back
    from the provider after payment; re-verifies the transaction against the
    provider's API (never trusts the query string alone) and is purely a UX
    backstop in case the webhook is delayed.
  - Both paths key off `wallet.postTransaction()`'s existing idempotency
    guarantee (`{provider}:{providerReference}`), so a webhook and a callback
    racing each other — or a provider retrying a webhook — can never double-credit.
- Paystack is implemented against its stable, well-documented Transaction API
  (`/transaction/initialize`, `/transaction/verify/:reference`) and should work
  as-is with `sk_test_...`/`sk_live_...` keys from the Paystack dashboard.
- OPay is implemented against its publicly documented Cashier API shape, but
  this environment couldn't reach OPay's docs site to verify field names
  line-by-line — treat it as best-effort plumbing. Once you have OPay merchant
  dashboard access, double-check the endpoint path, request/response fields,
  and signature scheme in `payments.js` (`opayInitialize`/`opayVerify`/`opaySign`)
  against what's actually issued to your merchant account before relying on it
  for real payments.

## KYC

- `GET /api/v1/kyc/me` — current status (`not_verified`/`pending`/`verified`/`rejected`)
  and the latest submission, if any.
- `POST /api/v1/kyc/submit` — `{ fullName, dateOfBirth, idType, idNumber }`.
  `idType` is one of `nin`/`bvn`/`drivers_license`/`passport`/`voters_card`.
  Rejects under-18 submissions. One pending submission at a time.

This collects identity fields as text only — no document photo upload yet. Adding
that would mean wiring up object storage (an S3-compatible bucket or similar),
which isn't part of this pass.

## Admin panel

`/admin.html` (also served at `/admin`) is a separate, staff-only page for
reviewing KYC submissions — sign in with a staff email/password, filter by
Pending/Verified/Rejected, and approve or reject with a reason. It calls:
- `GET /api/v1/admin/kyc/submissions?status=pending`
- `POST /api/v1/admin/kyc/submissions/:id/approve`
- `POST /api/v1/admin/kyc/submissions/:id/reject` — `{ reason }`

All three require the caller's role to be `risk`, `admin`, or `owner`.

## Staff accounts

There's no invite flow yet, so staff accounts are provisioned directly:
```
DATABASE_URL="..." DATABASE_SSL=true node create-staff-account.js you@example.com "a-strong-password" admin
```
Role must be one of `support`, `risk`, `admin`, `owner`. Building a proper
owner-audited invite workflow is still a "later, reviewed feature," same as before.

Roles are stored server-side: `player`, `support`, `risk`, `admin`, and `owner`.
Players always get `player` on registration.

## Required before real-money launch

- Licensed-jurisdiction rules, age gating, responsible gambling and self-exclusion.
- Server-side identity/accounts, MFA, sessions, roles and audit logs.
- Immutable double-entry wallet ledger in a managed database; never LocalStorage.
- Payment-provider integration with signed webhook validation, idempotency and reconciliation.
- KYC identity capture and staff review now exist; sanctions screening, fraud/risk limits, and document-photo verification do not yet.
- Game/RNG certification, reporting, incident response, backups, observability and penetration testing.

Do not change `realMoneyEnabled` to true until these systems have been implemented,
reviewed by the client's compliance and security teams, and approved for the
licensed operating jurisdiction.
