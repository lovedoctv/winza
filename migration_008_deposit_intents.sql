-- Adds deposit intent tracking for the Paystack integration. Safe to run
-- against an existing database that already has migrations 002-007 applied.
--
-- Why a separate table instead of writing straight into wallet_transactions:
-- an intent is created the moment a player starts a deposit (before Paystack
-- has confirmed anything), so it doubles as a reconciliation trail for
-- abandoned/failed checkouts, and gives the webhook handler something to
-- look up and verify the expected amount against rather than trusting the
-- webhook payload alone. wallet_transactions only gets a row once the
-- webhook actually confirms payment (see server.js's /api/v1/webhooks/paystack
-- handler and wallet.postTransaction, keyed by this table's `reference`).
CREATE TABLE deposit_intents (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
  reference TEXT NOT NULL UNIQUE,
  amount NUMERIC(18,2) NOT NULL CHECK (amount > 0),
  provider TEXT NOT NULL DEFAULT 'paystack',
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','completed','failed')),
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX deposit_intents_user_idx ON deposit_intents(user_id, created_at DESC);
