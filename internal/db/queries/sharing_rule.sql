-- name: ShareSecret :one
INSERT INTO sharing_rules (owner_email, target_email, path, permission, shared_until)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetSharedWith :many
SELECT owner_email, target_email 
FROM sharing_rules
WHERE path = $1 AND (shared_until IS NULL OR shared_until > NOW())
AND target_email != $2;

-- name: GetPermissions :one
SELECT permission
FROM sharing_rules
WHERE path = $1 AND target_email = $2 
AND (shared_until IS NULL OR shared_until > NOW());

-- name: GetSecretsSharedWithMe :many
SELECT path, permission, owner_email
FROM sharing_rules
WHERE target_email = $1 
AND (shared_until IS NULL OR shared_until > NOW());

-- name: CheckIfShared :one
SELECT EXISTS (
    SELECT 1
    FROM sharing_rules
    WHERE path = $1 AND target_email = $2 
    AND (shared_until IS NULL OR shared_until > NOW())
);