-- name: GetActiveHMACKey :one
SELECT id, key, created_at, is_active
FROM hmac_keys
WHERE is_active = true
LIMIT 1;

-- name: GetHMACKeyByID :one
SELECT id, key, created_at, is_active
FROM hmac_keys
WHERE id = $1;

-- name: InsertHMACKey :one
INSERT INTO hmac_keys (key,  is_active)
VALUES ($1,  true)
RETURNING id;

-- name: DeactivateAllHMACKeys :exec
UPDATE hmac_keys
SET is_active = false
WHERE is_active = true;

-- name: GetSecretVersionWithHMAC :one
SELECT sv.id, sv.secret_id, sv.version, sv.encrypted_value, sv.nonce,
       sv.created_at, sv.created_by, sv.hmac_signature, sv.hmac_key_id,
       hk.key AS hmac_key
FROM secret_versions sv
JOIN hmac_keys hk ON sv.hmac_key_id = hk.id
WHERE sv.secret_id = $1 AND sv.version = $2;
