-- Safe to run against an existing database that already has schema.sql (or
-- migration_002/003) applied — only adds a new table, touches nothing else.
-- Apply with: psql "$DATABASE_URL" -f migration_004_payments.sql

-- Tracks a deposit from the moment it's initialized with a payment provider
-- through to confirmation. Kept separate from wallet_transactions because a
-- payment intent can exist (and fail, expire, or be abandoned) without ever
-- becoming a posted ledger entry — the wallet is only credited once a
-- provider confirms success (see creditDeposit() in server.js).
CREATE TABLE IF NOT EXISTS payment_intents (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE RESTRICT,
  provider TEXT NOT NULL CHECK (provider IN ('paystack','opay')),
  provider_reference TEXT NOT NULL,
  amount NUMERIC(18,2) NOT NULL CHECK (amount > 0),
  currency CHAR(3) NOT NULL DEFAULT 'NGN',
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','success','failed')),
  raw_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (provider, provider_reference)
);
CREATE INDEX IF NOT EXISTS payment_intents_user_idx ON payment_intents(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS payment_intents_status_idx ON payment_intents(status, created_at);
