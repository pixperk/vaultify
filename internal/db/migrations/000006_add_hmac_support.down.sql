DROP INDEX IF EXISTS idx_hmac_key_id;

ALTER TABLE secret_versions
DROP COLUMN IF EXISTS hmac_signature,
DROP COLUMN IF EXISTS hmac_key_id;

DROP TABLE IF EXISTS hmac_keys;
