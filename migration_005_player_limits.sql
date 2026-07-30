-- Adds server-enforced responsible-gambling limits. Safe to run against an
-- existing database that already has migrations 002-004 applied — it only
-- adds a new table.
--
-- Why this exists: stake limits, cool-off, and self-exclusion previously
-- lived only in the browser's localStorage (winza.html's `state.rg`), which
-- means clearing site data or switching devices silently undid them —
-- exactly the failure mode responsible-gambling controls are supposed to be
-- immune to. This table makes cool-off and self-exclusion account-level
-- facts enforced by the server (see server.js: OTP login and withdrawal
-- requests both check this), not just client-side UI state.
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
