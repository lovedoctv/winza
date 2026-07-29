-- Apply this to a managed PostgreSQL database before starting WINZA.
CREATE TABLE users (
  id UUID PRIMARY KEY,
  email TEXT UNIQUE,
  phone_number TEXT UNIQUE,
  display_name TEXT NOT NULL,
  password_hash TEXT,
  role TEXT NOT NULL DEFAULT 'player' CHECK (role IN ('player','support','risk','admin','owner')),
  mfa_secret_encrypted TEXT,
  mfa_pending_secret_encrypted TEXT,
  mfa_enabled_at TIMESTAMPTZ,
  -- Players register via phone + OTP and start with no KYC data at all;
  -- verification happens later, only when the backend decides it's required
  -- (see platform_settings). Staff accounts (support/risk/admin/owner) use
  -- email + password instead and are provisioned directly, not self-registered.
  kyc_status TEXT NOT NULL DEFAULT 'not_verified' CHECK (kyc_status IN ('not_verified','pending','verified','rejected')),
  kyc_reviewed_by UUID REFERENCES users(id),
  kyc_reviewed_at TIMESTAMPTZ,
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

-- One-time codes for phone verification. Stored hashed, single-use, short-lived.
CREATE TABLE phone_otp_codes (
  id UUID PRIMARY KEY,
  phone_number TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX phone_otp_codes_phone_idx ON phone_otp_codes(phone_number, created_at DESC);

-- KYC submissions. Kept separate from users so there's a full history of every
-- attempt, not just the current status.
CREATE TABLE kyc_submissions (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  full_name TEXT NOT NULL,
  date_of_birth DATE NOT NULL,
  id_type TEXT NOT NULL CHECK (id_type IN ('nin','bvn','drivers_license','passport','voters_card')),
  id_number TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','verified','rejected')),
  reviewed_by UUID REFERENCES users(id),
  reviewed_at TIMESTAMPTZ,
  rejection_reason TEXT,
  -- Set on approval by server.js's sanctions-screening step (sanctions.js).
  -- 'not_configured_override' means no screening provider was configured and
  -- a staff member explicitly acknowledged that instead of it being silently
  -- treated as clear — see sanctions_screening_detail for their reason.
  sanctions_screening_status TEXT CHECK (sanctions_screening_status IN ('clear','hit','not_configured_override')),
  sanctions_screening_detail TEXT,
  sanctions_screened_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX kyc_submissions_user_idx ON kyc_submissions(user_id, created_at DESC);
CREATE INDEX kyc_submissions_status_idx ON kyc_submissions(status, created_at);

-- Players authenticate with phone + OTP only (no password), so there's no
-- "forgot password" flow — but a player who loses access to the phone number
-- on their account (lost phone, stolen SIM, recycled number) has no way back
-- in either, since phone_number is a hard unique identifier. This backs a
-- staff-reviewed recovery path: the player submits identity details plus a
-- new number, staff compares that against the KYC record on file, and
-- approval is what actually rewrites users.phone_number (see server.js).
CREATE TABLE phone_recovery_requests (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  old_phone_number TEXT NOT NULL,
  new_phone_number TEXT NOT NULL,
  full_name TEXT NOT NULL,
  date_of_birth DATE NOT NULL,
  id_type TEXT NOT NULL CHECK (id_type IN ('nin','bvn','drivers_license','passport','voters_card')),
  id_number TEXT NOT NULL,
  reason TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
  reviewed_by UUID REFERENCES users(id),
  reviewed_at TIMESTAMPTZ,
  rejection_reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX phone_recovery_requests_status_idx ON phone_recovery_requests(status, created_at);
CREATE INDEX phone_recovery_requests_user_idx ON phone_recovery_requests(user_id, created_at DESC);

-- Server-enforced responsible-gambling limits. Previously this lived only in
-- the browser's localStorage, which meant clearing site data or switching
-- devices silently undid a self-exclusion or cool-off — exactly the failure
-- mode these controls are supposed to be immune to. See server.js: OTP login
-- and withdrawal requests both check this table now.
CREATE TABLE player_limits (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  daily_stake_limit NUMERIC(18,2),
  -- Loosening or removing a limit is deferred 24h (see server.js) so it
  -- can't be undone in the same moment of impulse that prompted it.
  -- Tightening a limit, or setting one for the first time, is immediate.
  pending_daily_stake_limit NUMERIC(18,2),
  pending_stake_limit_effective_at TIMESTAMPTZ,
  cool_off_until TIMESTAMPTZ,
  self_excluded_until TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Backend-controlled feature flags (e.g. "is KYC required for withdrawal"),
-- so behavior can change without a redeploy.
CREATE TABLE platform_settings (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Sandbox/staging convenience only. server.js hard-codes this to true and
-- never reads this row once WINZA_MODE=live, so changing this value has no
-- effect on a real-money deployment — see the withdrawal-requests handler.
INSERT INTO platform_settings (key, value) VALUES ('kyc_required_for_withdrawal', 'true'::jsonb);

-- Defense-in-depth for the RTP (Return to Player) floor introduced ahead of
-- a future real-money launch: the server already validates 0.90-1.00 before
-- writing game_rtp (see server.js), but this trigger rejects an
-- out-of-bounds value even on a direct SQL write that skips the API entirely.
CREATE OR REPLACE FUNCTION enforce_game_rtp_bounds() RETURNS trigger AS $$
DECLARE
  rtp_value NUMERIC;
BEGIN
  IF NEW.key = 'game_rtp' THEN
    IF jsonb_typeof(NEW.value) <> 'number' THEN
      RAISE EXCEPTION 'game_rtp must be a JSON number';
    END IF;
    rtp_value := (NEW.value)::text::numeric;
    IF rtp_value < 0.90 OR rtp_value > 1.00 THEN
      RAISE EXCEPTION 'game_rtp must be between 0.90 and 1.00, got %', rtp_value;
    END IF;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER platform_settings_rtp_bounds
  BEFORE INSERT OR UPDATE ON platform_settings
  FOR EACH ROW EXECUTE FUNCTION enforce_game_rtp_bounds();

-- Default RTP: 96%, within the 90-100% floor/ceiling above.
INSERT INTO platform_settings (key, value) VALUES ('game_rtp', '0.96'::jsonb);
