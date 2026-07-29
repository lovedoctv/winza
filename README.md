# WINZA production foundation

This repository now has a safe deployment boundary and account-security API for the existing front-end.
It starts in `sandbox` mode and intentionally rejects the idea that browser
balances are real funds. KYC and withdrawal-request scaffolding exist, but there is
still no live payment processor, wagering, or actual payout system yet.
Authentication requires PostgreSQL and environment secrets before it can run.

## Run locally

1. Install Node.js 20 or newer.
2. Run `npm install` to install the PostgreSQL driver.
3. Apply `schema.sql` to a managed PostgreSQL database (fresh install). If you already
   applied an earlier version of `schema.sql`, run `migration_002_phone_kyc.sql`,
   `migration_003_rtp_config.sql`, and `migration_004_phone_recovery.sql` instead, in
   that order — each only adds columns/tables, safe to run against an existing database.
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
  `.env.example`. Until that's wired up, set `OTP_DEV_ECHO=true` locally to get
  the code back in the response as a `devCode` field for testing. Leave
  `OTP_DEV_ECHO` unset in any deployment real users can reach — including the
  sandbox build shipped to the Play Store — or anyone can read back the OTP
  for any phone number and take over that account.
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

## KYC

- `GET /api/v1/kyc/me` — current status (`not_verified`/`pending`/`verified`/`rejected`)
  and the latest submission, if any.
- `POST /api/v1/kyc/submit` — `{ fullName, dateOfBirth, idType, idNumber }`.
  `idType` is one of `nin`/`bvn`/`drivers_license`/`passport`/`voters_card`.
  Rejects under-18 submissions. One pending submission at a time.

This collects identity fields as text only — no document photo upload yet. Adding
that would mean wiring up object storage (an S3-compatible bucket or similar),
which isn't part of this pass.

**Sanctions/PEP screening runs on approval, not submission.** See
`sanctions.js` and `SANCTIONS_SCREENING_WEBHOOK_URL` in `.env.example`. When a
staff member approves a submission:
- No provider configured (the default): approval requires an explicit
  `sanctionsScreeningOverrideReason` (10+ characters) in the request —
  `/admin.html` prompts for this automatically and records it on the
  submission (`sanctions_screening_status = 'not_configured_override'`).
  Unscreened approvals are never silent.
- Provider configured and clear: approval proceeds,
  `sanctions_screening_status = 'clear'`.
- Provider configured and a hit: approval is refused outright (409) — the
  submission has to be rejected or escalated for manual review instead.

## Account recovery (lost phone number)

Players authenticate with phone + OTP only — there's no password, so there's
no "forgot password" flow. But losing access to the phone number itself (lost
phone, stolen SIM, a recycled number) leaves a player locked out with no way
back in, since `phone_number` is a hard unique identifier on the account. This
is the recovery path for that case, modeled on how KYC review works: staff
verify the requester's identity against the KYC record already on file rather
than any automated check.

- `POST /api/v1/auth/recovery/phone-change-request` — unauthenticated (the
  whole point is the requester can't log in): `{ oldPhone, newPhone, fullName,
  dateOfBirth, idType, idNumber, reason }`. Same identity-field validation as
  KYC submission. Like `password-reset/request`, the response never confirms
  whether `oldPhone` belongs to an account — it always returns a generic 202 —
  but a request row is only created when it does.
- Staff review it from `/admin.html`'s "Phone recovery requests" tab, or
  directly: `GET /api/v1/admin/phone-recovery-requests?status=pending`,
  `POST .../:id/approve`, `POST .../:id/reject` — `{ reason }`. All three
  require `risk`, `admin`, or `owner`, same as KYC review. The admin UI shows
  the submitted identity fields next to what's on file from the account's
  latest verified KYC submission (if any) so a mismatch is visible at a
  glance — a request with no verified KYC on file to compare against is
  flagged rather than silently allowed through.
- Approval rewrites `users.phone_number` to the new number and revokes all of
  that account's existing sessions, so the next sign-in goes through OTP on
  the new number rather than carrying over a stale session tied to the old one.

This is a support-assisted flow, not self-service — there's no automated
identity match, by design. A player with no KYC on file has nothing for staff
to verify the request against, which is itself a reason to require KYC before
real-money launch (see below).

## Responsible gambling

Stake limits, cool-off, and self-exclusion are server-enforced, not just
client-side UI state — clearing browser storage or switching devices no
longer undoes them.

- `GET /api/v1/account/limits` — current stake limit (and any pending
  change), cool-off, and self-exclusion status.
- `PUT /api/v1/account/limits/stake` — `{ dailyStakeLimit }` (or `null` to
  remove it). Tightening a limit, or setting one for the first time, applies
  immediately. Loosening or removing one is deferred 24 hours — long enough
  that it can't be undone in the same moment of impulse that prompted it.
- `POST /api/v1/account/limits/cool-off` — `{ hours }`, 24-720. Can be
  extended but never shortened once active.
- `POST /api/v1/account/limits/self-exclude` — 180 days, cannot be reversed
  early through this app at all.

Starting a cool-off or self-exclusion immediately revokes every active
session on the account. While either is in effect, `POST
/api/v1/auth/otp/verify` refuses to issue a new session (with a message
naming which restriction and until when), and `POST
/api/v1/wallet/withdrawal-requests` checks it again as defense-in-depth for
a session that was already issued in the hours just before a restriction
started. There's currently no server-mediated wagering endpoint — gameplay
itself is still a client-side simulation (see the top of this file) — so
login and withdrawals are the two points that actually matter today.

## Admin panel

`/admin.html` (also served at `/admin`) is a separate, staff-only page with two
queues — sign in with a staff email/password, switch between them with the
tabs at the top:
- **KYC submissions** — filter by Pending/Verified/Rejected, approve or reject
  with a reason. Calls `GET /api/v1/admin/kyc/submissions?status=pending`,
  `POST /api/v1/admin/kyc/submissions/:id/approve`, and
  `POST /api/v1/admin/kyc/submissions/:id/reject` — `{ reason }`.
- **Phone recovery requests** — see "Account recovery" above. Calls
  `GET /api/v1/admin/phone-recovery-requests?status=pending`,
  `POST /api/v1/admin/phone-recovery-requests/:id/approve`, and
  `POST /api/v1/admin/phone-recovery-requests/:id/reject` — `{ reason }`.

All of the above require the caller's role to be `risk`, `admin`, or `owner`.

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
