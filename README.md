# WINZA production foundation

This repository now has a safe deployment boundary and account-security API for the existing front-end.
It starts in `sandbox` mode and intentionally rejects the idea that browser
balances are real funds. There is no live payment, wagering, KYC, or withdrawal system yet.
Authentication requires PostgreSQL and environment secrets before it can run.

## Run locally

1. Install Node.js 20 or newer.
2. Run `npm install` to install the PostgreSQL driver.
3. Apply `schema.sql` to a managed PostgreSQL database.
4. Copy `.env.example` values into your deployment secret manager and generate distinct `JWT_SECRET` and `MFA_ENCRYPTION_KEY` values.
5. Run `npm start`.
6. Open `http://127.0.0.1:3000`.

## Account API

All endpoint bodies are JSON. Access tokens are returned only after successful login and
must be sent as `Authorization: Bearer <token>`.

- `POST /api/v1/auth/register` — email, displayName, password (minimum 12 characters).
- `POST /api/v1/auth/login` — email/password, plus `code` when MFA is enabled.
- `GET /api/v1/auth/me` and `POST /api/v1/auth/logout` — authenticated session management.
- `POST /api/v1/auth/password-reset/request` and `/confirm` — reset token workflow. Configure the private mail webhook before enabling it publicly.
- `POST /api/v1/auth/mfa/enroll`, `/confirm`, `/disable` — TOTP authenticator enrollment.

## Wallet

- `GET /api/v1/wallet/me` — authenticated, read-only. Returns the caller's own balance
  summary (`cashAvailable`, `bonusAvailable`, `lockedBalance`, `pendingWithdrawal`, `currency`).

A wallet row is created automatically, in the same transaction as the user row, when an
account registers — every account has exactly one wallet, and it starts at zero. There is
**no route that adjusts a balance**. Money can only move through the internal
`wallet.postTransaction()` helper in `wallet.js`, which is not wired to any HTTP endpoint.
It exists so that a specific, reviewed feature (a reconciled payment webhook, a settled
wager, an audited admin correction) can be given access to it deliberately later — it is
not something the current API surface exposes to users, admins, or anything else yet.
The helper enumerates allowed transaction types, requires an idempotency key, locks the
wallet row for the duration of the update, and relies on the `wallets` table's own
`CHECK (... >= 0)` constraints to reject anything that would drive a balance negative.
`wallet_ledger_entries` is meant to be append-only in production — grant the application
database role `INSERT`/`SELECT` only, never `UPDATE`/`DELETE`, on that table.

Roles are stored server-side: `player`, `support`, `risk`, `admin`, and `owner`. The API
assigns `player` on registration. Privileged-role assignment must be added only behind an
owner-only, audited admin workflow.

## Required before real-money launch

- Licensed-jurisdiction rules, age gating, responsible gambling and self-exclusion.
- Server-side identity/accounts, MFA, sessions, roles and audit logs.
- Immutable double-entry wallet ledger in a managed database; never LocalStorage.
- Payment-provider integration with signed webhook validation, idempotency and reconciliation.
- KYC/AML, sanctions screening, fraud/risk limits and monitored manual withdrawal review.
- Game/RNG certification, reporting, incident response, backups, observability and penetration testing.

Do not change `realMoneyEnabled` to true until these systems have been implemented,
reviewed by the client's compliance and security teams, and approved for the
licensed operating jurisdiction.
