-- Adds sanctions/PEP screening tracking to KYC submissions. Safe to run
-- against an existing database that already has migrations 002-005 applied
-- — it only adds columns.
--
-- Why this exists: KYC identity capture and staff review already existed,
-- but nothing screened a submission against sanctions/PEP lists before
-- approval. See server.js's KYC approve handler and sanctions.js — if no
-- screening provider is configured (SANCTIONS_SCREENING_WEBHOOK_URL unset),
-- approval requires an explicit, logged staff override rather than silently
-- treating an unscreened submission as clear.
ALTER TABLE kyc_submissions ADD COLUMN sanctions_screening_status TEXT CHECK (sanctions_screening_status IN ('clear','hit','not_configured_override'));
ALTER TABLE kyc_submissions ADD COLUMN sanctions_screening_detail TEXT;
ALTER TABLE kyc_submissions ADD COLUMN sanctions_screened_at TIMESTAMPTZ;
