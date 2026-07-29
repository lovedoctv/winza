-- Adds server- and database-level enforcement of the RTP (Return to Player)
-- floor/ceiling (90%-100%, default 96%) introduced ahead of a future
-- regulated real-money launch. Safe to run against a database that already
-- has schema.sql or migration_002_phone_kyc.sql applied — only adds a
-- function, a trigger, and (if missing) one platform_settings row.
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

DROP TRIGGER IF EXISTS platform_settings_rtp_bounds ON platform_settings;
CREATE TRIGGER platform_settings_rtp_bounds
  BEFORE INSERT OR UPDATE ON platform_settings
  FOR EACH ROW EXECUTE FUNCTION enforce_game_rtp_bounds();

INSERT INTO platform_settings (key, value) VALUES ('game_rtp', '0.96'::jsonb)
  ON CONFLICT (key) DO NOTHING;
