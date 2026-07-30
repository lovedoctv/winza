-- Adds phone-number recovery requests. Safe to run against an existing
-- database that already has migration_002_phone_kyc.sql and
-- migration_003_rtp_config.sql applied — it only adds a new table.
--
-- Why this exists: players authenticate with phone + OTP only (no password),
-- so there is no "forgot password" flow for them. But a player who loses
-- access to the phone number on their account (lost phone, stolen SIM,
-- recycled number) has no way back in either, since phone_number is a hard
-- unique identifier with nothing to fall back on. This table backs a
-- staff-reviewed recovery path: the player submits identity details plus the
-- new number from wherever they can still reach the app, staff compares that
-- against the KYC record already on file for the account, and approval is
-- what actually rewrites users.phone_number.
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
