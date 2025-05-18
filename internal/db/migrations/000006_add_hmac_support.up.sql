CREATE TABLE hmac_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ DEFAULT NULL,
    is_active BOOLEAN DEFAULT true
);

ALTER TABLE secret_versions
ADD COLUMN IF NOT EXISTS hmac_signature BYTEA NOT NULL DEFAULT ''::BYTEA,
ADD COLUMN IF NOT EXISTS hmac_key_id UUID REFERENCES hmac_keys(id);


CREATE INDEX IF NOT EXISTS idx_hmac_key_id ON secret_versions(hmac_key_id);
