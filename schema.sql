-- Apply this to a managed PostgreSQL database before starting WINZA.
CREATE TABLE users (
  id UUID PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'player' CHECK (role IN ('player','support','risk','admin','owner')),
  mfa_secret_encrypted TEXT,
  mfa_pending_secret_encrypted TEXT,
  mfa_enabled_at TIMESTAMPTZ,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE auth_sessions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX auth_sessions_user_id_idx ON auth_sessions(user_id);
CREATE TABLE password_reset_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE audit_events (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  type TEXT NOT NULL,
  ip_hash TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_events_user_id_idx ON audit_events(user_id, created_at DESC);

-- One locked summary row per user. Balances are cacheable summaries only;
-- wallet_ledger_entries is the permanent financial record.
CREATE TABLE wallets (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE RESTRICT,
  cash_available NUMERIC(18,2) NOT NULL DEFAULT 0 CHECK (cash_available >= 0),
  bonus_available NUMERIC(18,2) NOT NULL DEFAULT 0 CHECK (bonus_available >= 0),
  locked_balance NUMERIC(18,2) NOT NULL DEFAULT 0 CHECK (locked_balance >= 0),
  pending_withdrawal NUMERIC(18,2) NOT NULL DEFAULT 0 CHECK (pending_withdrawal >= 0),
  currency CHAR(3) NOT NULL DEFAULT 'NGN',
  version INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE wallet_transactions (
  id UUID PRIMARY KEY,
  wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE RESTRICT,
  type TEXT NOT NULL CHECK (type IN ('deposit','withdrawal_request','withdrawal_reversal','stake','payout','bonus','adjustment')),
  status TEXT NOT NULL DEFAULT 'posted' CHECK (status IN ('pending','posted','reversed','rejected')),
  idempotency_key TEXT NOT NULL,
  reference_type TEXT,
  reference_id TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (wallet_id, idempotency_key)
);

-- An append-only signed entry. Application roles must never receive UPDATE or DELETE grants on this table.
CREATE TABLE wallet_ledger_entries (
  id UUID PRIMARY KEY,
  transaction_id UUID NOT NULL REFERENCES wallet_transactions(id) ON DELETE RESTRICT,
  wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE RESTRICT,
  balance_type TEXT NOT NULL CHECK (balance_type IN ('cash_available','bonus_available','locked_balance','pending_withdrawal')),
  amount NUMERIC(18,2) NOT NULL CHECK (amount <> 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX wallet_transactions_wallet_created_idx ON wallet_transactions(wallet_id, created_at DESC);
CREATE INDEX wallet_ledger_entries_wallet_idx ON wallet_ledger_entries(wallet_id, created_at DESC);
