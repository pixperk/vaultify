-- name: ShareSecret :one
INSERT INTO sharing_rules (owner_email, target_email, path, permission)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetSharedWith :many
SELECT owner_email, target_email 
FROM sharing_rules
WHERE path = $1;

-- name: GetPermissions :one
SELECT permission
FROM sharing_rules
WHERE path = $1 AND target_email = $2;

-- name: GetSecretsSharedWithMe :many
SELECT path, permission, owner_email
FROM sharing_rules
WHERE target_email = $1;

-- name: CheckIfShared :one
SELECT EXISTS (
    SELECT 1
    FROM sharing_rules
    WHERE path = $1 AND target_email = $2
);