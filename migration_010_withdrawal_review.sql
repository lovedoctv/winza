-- Adds staff-review tracking to withdrawal_request wallet_transactions rows
-- so admin/owner staff have somewhere to actually approve or reject a
-- pending withdrawal (previously: funds moved into pending_withdrawal at
-- request time, but nothing surfaced the request to staff at all — see
-- POST /api/v1/admin/withdrawal-requests/:id/approve|reject in server.js).
-- Same pattern as kyc_submissions' reviewed_by/reviewed_at/rejection_reason.
-- Safe to run against a database that already has migrations 002-009 applied.
ALTER TABLE wallet_transactions ADD COLUMN IF NOT EXISTS reviewed_by UUID REFERENCES users(id);
ALTER TABLE wallet_transactions ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;
ALTER TABLE wallet_transactions ADD COLUMN IF NOT EXISTS rejection_reason TEXT;

CREATE INDEX IF NOT EXISTS wallet_transactions_withdrawal_review_idx
  ON wallet_transactions(status, created_at) WHERE type = 'withdrawal_request';
