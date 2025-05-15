-- name: CreateSecret :one
INSERT INTO secrets (user_id, name, encrypted_value)
VALUES ($1, $2, $3)
RETURNING *;

-- name: ListSecretsForUser :many
SELECT * FROM secrets WHERE user_id = $1 ORDER BY created_at DESC;

-- name: DeleteSecret :exec
DELETE FROM secrets WHERE id = $1 AND user_id = $2;
