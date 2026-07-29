-- Adds default withdrawal velocity/fraud limits to platform_settings. Safe
-- to run against an existing database that already has migrations 002-006
-- applied.
--
-- Why this exists: KYC verification alone doesn't stop a compromised or
-- abused account from draining funds in one shot once verified. See
-- server.js's withdrawal-requests handler and the new
-- /api/v1/admin/withdrawal-limits endpoints — these caps are admin/owner
-- adjustable but always bounded, same pattern as the RTP floor.
INSERT INTO platform_settings (key, value) VALUES ('withdrawal_daily_amount_limit', '500000'::jsonb) ON CONFLICT (key) DO NOTHING;
INSERT INTO platform_settings (key, value) VALUES ('withdrawal_daily_count_limit', '5'::jsonb) ON CONFLICT (key) DO NOTHING;
