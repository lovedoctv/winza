# WINZA production foundation

This repository now has a safe deployment boundary, an account-security API,
and a server-authoritative wheel/lotto betting engine for the existing
front-end. It starts in `sandbox` mode and intentionally rejects the idea
that browser balances are real funds — but every spin/draw is now a real,
server-recorded bet against the account's real wallet balance (see "Wheel/lotto
betting" below), not a client-side `Math.random()` simulation. KYC,
withdrawal-request scaffolding, and deposits via Paystack/OPay exist too.
Authentication requires PostgreSQL and environment secrets before it can run.

## Run locally

1. Install Node.js 20 or newer.
2. Run `npm install` to install the PostgreSQL driver.
3. Apply `schema.sql` to a managed PostgreSQL database (fresh install). If you already
   applied an earlier version of `schema.sql`, run `migration_002_phone_kyc.sql`,
   `migration_003_rtp_config.sql`, `migration_004_phone_recovery.sql`,
   `migration_005_player_limits.sql`, `migration_006_sanctions_screening.sql`,
   `migration_007_withdrawal_limits.sql`, `migration_008_deposit_intents.sql`,
   `migration_009_bets.sql`, and `migration_010_withdrawal_review.sql`
   instead, in that order — each only adds columns/tables, safe to run
   against an existing database. **These do not run automatically on
   deploy** — a fresh deploy of the app code alone does not apply them;
   run each migration file against your database yourself (e.g. `psql
   "$DATABASE_URL" -f migration_010_withdrawal_review.sql`) whenever a new
   one is added.
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
  No SMS provider is configured out of the box. Delivery is tried in order:
  Termii (`termii.js` — a built-in integration, set `TERMII_API_KEY` and
  `TERMII_SENDER_ID` in `.env.example`), then `OTP_SMS_WEBHOOK_URL` (point it at
  any other provider — Africa's Talking, Twilio, etc.). Until one of those is
  wired up, set `OTP_DEV_ECHO=true` locally to get the code back in the
  response as a `devCode` field for testing. Leave `OTP_DEV_ECHO` unset in any
  deployment real users can reach — including the sandbox build shipped to
  the Play Store — or anyone can read back the OTP for any phone number and
  take over that account.
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
- `GET /api/v1/wallet/transactions?limit=` (default 30, max 100) — the
  player's own real transaction history: deposits, withdrawal
  requests/rejections, and actual bets (with game/result/multiplier), read
  from `wallet_transactions`/`bets`. Excludes `payout` rows (releasing a
  held withdrawal once staff approve — see below — never touches
  `cash_available`, so there's nothing new to show beyond the
  `withdrawal_request` the player already saw). `winza.html`'s Transaction
  History card used to be entirely local/client-side (sandbox game-play and
  reward events only, never the real thing) — it now calls this endpoint
  whenever signed in.
- `POST /api/v1/wallet/withdrawal-requests` — `{ amount }`. Moves funds from
  `cash_available` into `pending_withdrawal` and records the request as
  `wallet_transactions.status='pending'` — this app never pays out
  automatically. **Blocked with 403 if KYC is required and the caller
  isn't `verified`** — see `platform_settings.kyc_required_for_withdrawal`, a
  backend-controlled flag, not a client one. **Also blocked with 429 if it would
  exceed the account's rolling 24-hour withdrawal limit** — a fully KYC-verified
  account still can't drain funds in one shot. Defaults: ₦500,000/day, 5
  requests/day. Admin/owner-adjustable via `GET`/`PUT
  /api/v1/admin/withdrawal-limits`, bounded to ₦1,000–₦50,000,000 and 1–50
  requests — always some cap, never unlimited, same principle as the RTP floor.
- **Staff review** — `GET /api/v1/admin/withdrawal-requests?status=pending|posted|rejected`
  lists requests (any of risk/admin/owner can view, same gate as the KYC
  queue); `POST .../:id/approve` and `POST .../:id/reject` (admin/owner only,
  same risk tier as RTP changes) resolve one. Approving releases the held
  `pending_withdrawal` amount via a `payout` transaction — it does **not**
  send money anywhere; staff pay the player via bank transfer/payment
  provider outside the app, then click approve to record that. Rejecting
  reverses the hold via a `withdrawal_reversal` transaction, returning the
  funds to `cash_available`. Both are exposed in `admin.html`'s "Withdrawal
  requests" tab, mirroring the KYC review UI.

A wallet row is still created automatically, in the same transaction as the user
row, for every new account. There is still no route that lets anyone adjust a
balance directly — money only moves through `wallet.postTransaction()`, following
the same idempotency-key/row-locking/append-only-ledger guarantees as before.

## Wheel/lotto betting (server-authoritative)

The client never decides win/loss, never computes a payout, and never
mutates the balance itself — it sends `{ gameId, stake, multiplier }` to the
server and renders whatever comes back. Everything that determines the
outcome and moves money lives server-side:

- `POST /api/v1/games/bets` — `{ gameId: "wheel"|"lotto", stake, multiplier,
  clientRequestId }`. Requires an authenticated session. Validates, in order:
  stake is a whole number within `rtp-config.js`'s `STAKE_MIN`/`STAKE_MAX`
  (₦100–₦50,000); multiplier is within `MULTIPLIER_MIN`/`MULTIPLIER_MAX`
  (1.1×–10×) on the same 0.1 step the client's slider offers; the account
  isn't in an active cool-off/self-exclusion (same check as login/withdrawal);
  and the bet wouldn't push the account's trailing-24h stake total over its
  `player_limits.daily_stake_limit`, if one is set. `clientRequestId` is a
  client-generated idempotency key — resubmitting the same value (a retried
  request after a dropped connection, a double-tap) replays the original
  result instead of charging twice; see `wallet.placeBet()`.
- The outcome itself is generated in `game-engine.js`: a cryptographically
  secure random draw (`crypto.randomInt`, never `Math.random()`) compared
  against a chance derived from the configured RTP and the chosen multiplier
  (`chance = clamp(rtp / multiplier, MIN_CHANCE, MAX_CHANCE)` — the same
  formula `rtp-config.js` exposes to the client for its pre-bet odds preview,
  so the preview can never drift from what the server actually resolves).
  Winning payout is `round(stake × multiplier / 100) × 100`.
- `wallet.placeBet()` (in `wallet.js`) settles the whole thing in a single
  database transaction: locks the wallet row (`SELECT ... FOR UPDATE`),
  checks the balance, resolves the outcome, writes the stake-debit and (if a
  win) payout-credit as `wallet_ledger_entries` under one new `bet`-typed
  `wallet_transactions` row, updates the wallet balance, and inserts the
  audit row into `bets` — all committed together or none of it is. Row
  locking means a concurrent retry with the same `clientRequestId` blocks
  until the first attempt finishes rather than racing it.
- Every bet is recorded in `bets`: stake, multiplier, the RTP actually used,
  the computed chance, the raw `[0,1)` random draw, an HMAC audit fingerprint
  over that draw (keyed with `GAME_AUDIT_SECRET`, never sent to the client —
  see `.env.example`), payout, result, and timestamps. This is the permanent
  record for disputes, regulatory reporting, and RTP verification.
- The response back to the client is deliberately minimal: `{ outcome,
  stake, multiplier, payout, balance, betId, transactionId }`. Nothing about
  the random draw, the chance used, or anything else that could help predict
  future outcomes.
- Bets stake and pay out against the same real wallet balance shown
  everywhere else (`wallets.cash_available`) — there is no separate
  play-money ledger. Since deposits stay gated behind `WINZA_MODE=live` (see
  below), that balance is ₦0 for every account until then; `POST
  /api/v1/wallet/sandbox-credit` (no body, or `{ amount }` bounded
  ₦100–₦50,000) is a sandbox-only faucet that credits it for testing —
  hard-disabled with 403 the instant `WINZA_MODE=live`, the same gating
  pattern as `OTP_DEV_ECHO`.

### Deposits (Paystack / OPay) — built, but inert until deliberately switched on

`POST /api/v1/wallet/deposits/initiate`, `POST /api/v1/webhooks/paystack`, and
`POST /api/v1/webhooks/opay` exist and are fully wired, but real money still
can't move through this app: `realMoneyEnabled` in `/api/v1/public/config` is
hardcoded `false` regardless of any of this, and every path below stays gated
behind `WINZA_MODE=live` on top of that. This is the integration built ahead
of time, not the integration turned on — see "Required before real-money
launch" below for what still has to happen first.

- `POST /api/v1/wallet/deposits/initiate` — `{ provider: "paystack"|"opay", amount }`
  (₦, min 100; `provider` defaults to `paystack` if omitted). An unrecognized
  `provider` value is always rejected (400) regardless of mode/config. Returns
  403 with the same "Payments are unavailable..." message the client already
  shows unless **both** `WINZA_MODE=live` and that specific provider's
  credentials are set — Paystack and OPay are switched on independently of
  each other. When enabled: records a `deposit_intents` row (the
  reconciliation trail — created before the provider is even called, so an
  abandoned checkout still leaves a record; its `provider` column tracks
  which one was used), calls that provider's own initialize API, and returns
  `{ authorizationUrl, reference }` for the client to redirect the player's
  full browser to — the provider's own hosted payment page, so card details
  never touch this server. Players have no email on file (phone+OTP only);
  `paystack.js` synthesizes a placeholder one since Paystack requires the
  field — see its comments.
- `POST /api/v1/webhooks/paystack` / `POST /api/v1/webhooks/opay` —
  unauthenticated (the provider calls these, not a player); each provider's
  own signature scheme (`x-paystack-signature` HMAC-SHA512 over the raw body
  for Paystack; `signature` for OPay) is what proves a request actually came
  from that provider, checked against the **raw** request body before any
  JSON parsing. On a successful-payment event: looks up the `deposit_intents`
  row by reference, verifies the webhook's amount matches what was actually
  initiated (not just trusted from the payload), and credits the wallet via
  the same idempotent `wallet.postTransaction()` every other balance change
  goes through — a retried webhook delivery is a no-op, not a double-credit.
  Any other event type, or a reference that's unknown or already completed,
  is acknowledged with 200 and otherwise ignored.
- **Deposit reconciliation** (`reconciliation.js`) — for `deposit_intents` rows
  that stay `pending` because a webhook was dropped or the payer abandoned
  checkout. Polls the relevant provider directly (`paystack.verifyTransaction`
  / `opay.queryTransactionStatus`) for any row still `pending` after
  `DEPOSIT_RECONCILE_AFTER_MINUTES` (default 30). A confirmed success credits
  the wallet through the same idempotent `wallet.postTransaction()` the
  webhook uses (keyed by the deposit's `reference`), so a late webhook and
  this job resolving the same deposit is a no-op, not a double-credit; a
  confirmed failure, or a row still unresolved after
  `DEPOSIT_ABANDON_AFTER_HOURS` (default 24), is marked `failed`. Runs
  automatically every `DEPOSIT_RECONCILE_INTERVAL_MINUTES` (default 15) and
  is also triggerable on demand via `POST /api/v1/admin/reconcile-deposits`
  (admin/owner only).
- `PAYSTACK_SECRET_KEY` doubles as the webhook-signing secret — Paystack
  doesn't issue a separate one. OPay issues `OPAY_MERCHANT_ID`,
  `OPAY_PUBLIC_KEY`, and `OPAY_SECRET_KEY` separately from its merchant
  dashboard. See `.env.example`.
- **OPay caveat**: `opay.js` is implemented against OPay's publicly
  documented Cashier API shape (`MerchantId` + Bearer public-key auth,
  HMAC-SHA512-signed request body, a `cashierUrl` to redirect to), but this
  pass couldn't reach OPay's docs site to verify field names line-by-line the
  way Paystack's were. Treat it as best-effort plumbing — double-check the
  endpoint path, request/response fields, and signature scheme against your
  actual OPay merchant dashboard before relying on it for a real payment.

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
naming which restriction and until when), and both `POST
/api/v1/wallet/withdrawal-requests` and `POST /api/v1/games/bets` check it
again as defense-in-depth for a session that was already issued in the hours
just before a restriction started. The daily stake limit is enforced the
same way, directly on `POST /api/v1/games/bets` — see "Wheel/lotto betting"
above — not just displayed in the UI.

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

## Mobile app

`mobile/` is a Capacitor wrapper that loads this same deployed site inside a
native Android/iOS shell — no separate frontend to maintain. See
`mobile/README.md` for building, signing, and app-store submission notes.

## Required before real-money launch

- **A gambling licence for the operating jurisdiction.** Nothing below substitutes for this.
- Licensed-jurisdiction age gating and responsible-gambling rules — age gating and
  server-enforced stake limits/cool-off/self-exclusion now exist (see "Responsible
  gambling" above); jurisdiction-specific licensing requirements on top of that do not.
- Server-side identity/accounts, MFA, sessions, roles and audit logs — exist.
- Immutable double-entry wallet ledger in a managed database; never LocalStorage — exists.
- Payment-provider integration with signed webhook validation, idempotency and
  reconciliation — **built and tested, but not live**: see "Deposits (Paystack /
  OPay)" above. Still needed before flipping it on: real Paystack credentials
  tested end-to-end (only verified against a local mock so far), OPay's
  integration confirmed field-by-field against real merchant-dashboard docs
  (this pass couldn't reach OPay's docs site — see the caveat above). Withdrawals
  are staff-reviewed only by design (no automated payout) — see "Wallet" above.
  A reconciliation job for deposit_intents rows stuck `pending` (abandoned
  checkout, dropped webhook) now exists: it polls the provider directly for
  any deposit still pending after `DEPOSIT_RECONCILE_AFTER_MINUTES` (default
  30), runs automatically every `DEPOSIT_RECONCILE_INTERVAL_MINUTES` (default
  15), and is also triggerable on demand via `POST
  /api/v1/admin/reconcile-deposits` (admin/owner only). See `reconciliation.js`.
- KYC identity capture, staff review, and sanctions/PEP screening now exist (see
  "KYC" above); document-photo verification does not yet — that needs object
  storage (an S3-compatible bucket or similar), which isn't part of this pass.
- Withdrawal fraud/velocity limits now exist (see "Wallet" above).
- Server-authoritative, cryptographically-random, RTP-configured wheel/lotto
  betting with a single-transaction ledger and a per-bet audit trail now
  exists (see "Wheel/lotto betting" above). Independent third-party RNG/RTP
  certification from the operating jurisdiction's approved testing lab does
  not — that's an external audit, not something this codebase can self-certify.
- Reporting, incident response, backups, observability, and penetration
  testing — none of this exists yet. These are largely external audits and
  operational processes, not application code.

Do not change `realMoneyEnabled` to true until these systems have been implemented,
reviewed by the client's compliance and security teams, and approved for the
licensed operating jurisdiction.
