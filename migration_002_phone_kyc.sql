-- Run this against your EXISTING database (the one schema.sql was already
-- applied to). It only adds things — nothing here drops or rewrites data.
--   psql "<External Database URL>" -f migration_002_phone_kyc.sql

-- Players now register/log in with phone + OTP, not email/password. Staff
-- accounts (support/risk/admin/owner) keep using email + password, so both
-- columns become optional rather than one replacing the other.
ALTER TABLE users ALTER COLUMN email DROP NOT NULL;
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS phone_number TEXT UNIQUE;

ALTER TABLE users ADD COLUMN IF NOT EXISTS kyc_status TEXT NOT NULL DEFAULT 'not_verified'
  CHECK (kyc_status IN ('not_verified','pending','verified','rejected'));
ALTER TABLE users ADD COLUMN IF NOT EXISTS kyc_reviewed_by UUID REFERENCES users(id);
ALTER TABLE users ADD COLUMN IF NOT EXISTS kyc_reviewed_at TIMESTAMPTZ;

-- One-time codes for phone verification. Codes are stored hashed, never in
-- the clear, and each row is single-use (consumed_at) with a short expiry.
CREATE TABLE IF NOT EXISTS phone_otp_codes (
  id UUID PRIMARY KEY,
  phone_number TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS phone_otp_codes_phone_idx ON phone_otp_codes(phone_number, created_at DESC);

-- KYC submissions. Kept separate from users so there's a full history of every
-- attempt, not just the current status — an admin reviewing a rejected-then-
-- resubmitted case can see both submissions.
CREATE TABLE IF NOT EXISTS kyc_submissions (
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
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS kyc_submissions_user_idx ON kyc_submissions(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS kyc_submissions_status_idx ON kyc_submissions(status, created_at);

-- Backend-controlled feature flags, so things like "is KYC required for
-- withdrawal" can be toggled without a redeploy. Read via getSetting() in
-- server.js.
CREATE TABLE IF NOT EXISTS platform_settings (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO platform_settings (key, value) VALUES ('kyc_required_for_withdrawal', 'true'::jsonb)
  ON CONFLICT (key) DO NOTHING;
