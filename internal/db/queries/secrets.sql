-- name: CreateSecret :one
INSERT INTO secrets (user_id, path, encrypted_value, nonce)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetSecretByPath :one
SELECT * FROM secrets WHERE path = $1;

-- name: GetAllSecretsForUser :many
SELECT * FROM secrets WHERE user_id = $1;

-- name: UpdateSecret :one
UPDATE secrets
SET encrypted_value = $2,
    nonce = $3,
    updated_at = NOW()
WHERE path = $1
RETURNING *;
