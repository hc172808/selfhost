-- ─────────────────────────────────────────────────────────────────────────────
-- Supabase self-hosted initial DB setup
-- This runs automatically when the Postgres container first starts.
-- The main NETLIFE CASH schema is in all_migrations.sql (pushed by setup.sh)
-- ─────────────────────────────────────────────────────────────────────────────

-- Enable commonly needed extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pgjwt";

-- Ensure the realtime publication exists (Supabase expects it)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_publication WHERE pubname = 'supabase_realtime') THEN
    CREATE PUBLICATION supabase_realtime;
  END IF;
END$$;
