-- Converts the wheel/lotto game from a client-side simulation into a
-- server-authoritative bet: adds the 'bet' wallet_transactions type and the
-- `bets` audit table that records every wager. Safe to run against a
-- database that already has migrations 002-008 applied.
--
-- See server.js's /api/v1/games/bets handler, wallet.js's placeBet(), and
-- game-engine.js for how these are used.
ALTER TABLE wallet_transactions DROP CONSTRAINT IF EXISTS wallet_transactions_type_check;
ALTER TABLE wallet_transactions ADD CONSTRAINT wallet_transactions_type_check
  CHECK (type IN ('deposit','withdrawal_request','withdrawal_reversal','stake','payout','bonus','adjustment','bet'));

-- One row per wheel/lotto wager, written in the same database transaction as
-- the wallet_transactions/wallet_ledger_entries rows that move the money —
-- see the comment above this table in schema.sql for the full rationale
-- behind client_request_id, random_value, and audit_fingerprint.
CREATE TABLE IF NOT EXISTS bets (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE RESTRICT,
  wallet_transaction_id UUID NOT NULL REFERENCES wallet_transactions(id) ON DELETE RESTRICT,
  game_id TEXT NOT NULL CHECK (game_id IN ('wheel','lotto')),
  client_request_id TEXT NOT NULL,
  stake NUMERIC(18,2) NOT NULL CHECK (stake > 0),
  multiplier NUMERIC(6,2) NOT NULL CHECK (multiplier > 0),
  rtp_used NUMERIC(5,4) NOT NULL,
  chance NUMERIC(7,6) NOT NULL,
  random_value DOUBLE PRECISION NOT NULL,
  audit_fingerprint TEXT NOT NULL,
  payout NUMERIC(18,2) NOT NULL DEFAULT 0 CHECK (payout >= 0),
  result TEXT NOT NULL CHECK (result IN ('win','loss')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (wallet_id, client_request_id)
);
CREATE INDEX IF NOT EXISTS bets_user_idx ON bets(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS bets_wallet_idx ON bets(wallet_id, created_at DESC);
