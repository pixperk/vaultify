ALTER TABLE secrets
ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ DEFAULT NULL;

CREATE INDEX IF NOT EXISTS secrets_expires_at_idx ON secrets (expires_at);