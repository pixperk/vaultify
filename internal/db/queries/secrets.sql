-- name: CreateSecret :one
INSERT INTO secrets (user_id, path, encrypted_value, nonce, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetSecretByPath :one
SELECT * FROM secrets WHERE path = $1 AND (expires_at IS NULL OR expires_at > now());

-- name: GetAllSecretsForUser :many
SELECT * FROM secrets WHERE user_id = $1 AND (expires_at IS NULL OR expires_at > now());

-- name: UpdateSecret :one
UPDATE secrets
SET encrypted_value = $2,
    nonce = $3,
    updated_at = NOW()
WHERE path = $1
RETURNING *;

-- name: DeleteExpiredSecrets :exec
DELETE FROM secrets
WHERE expires_at IS NOT NULL AND expires_at < now();

