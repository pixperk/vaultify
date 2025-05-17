-- name: CreateSecretWithVersion :one
WITH inserted_secret AS (
    INSERT INTO secrets (user_id, path)
    VALUES ($1, $2)
    RETURNING id
)
INSERT INTO secret_versions (secret_id, version, encrypted_value, nonce, created_by, expires_at)
VALUES (
    (SELECT id FROM inserted_secret), 1, $3, $4, $1, $5
)
RETURNING *;

-- name: GetLatestSecretByPath :one
SELECT sv.*, s.id AS secret_id, s.path
FROM secrets s
JOIN secret_versions sv ON s.id = sv.secret_id
WHERE s.path = $1
  AND (sv.expires_at IS NULL OR sv.expires_at > now())
ORDER BY sv.version DESC
LIMIT 1;

-- name: GetLatestSecretsForUser :many
SELECT DISTINCT ON (s.id) s.id AS secret_id, s.path, sv.version, sv.encrypted_value, sv.nonce, sv.created_at, sv.expires_at
FROM secrets s
JOIN secret_versions sv ON s.id = sv.secret_id
WHERE s.user_id = $1
  AND (sv.expires_at IS NULL OR sv.expires_at > now())
ORDER BY s.id, sv.version DESC;

-- name: CreateNewSecretVersion :one
INSERT INTO secret_versions (secret_id, version, encrypted_value, nonce, created_by, expires_at)
SELECT 
  s.id, 
  COALESCE(MAX(sv.version), 0) + 1, 
  $2, $3, $4, $5
FROM secrets s
LEFT JOIN secret_versions sv ON s.id = sv.secret_id
WHERE s.path = $1
GROUP BY s.id
RETURNING *;


-- name: DeleteExpiredSecretVersions :exec
DELETE FROM secret_versions
WHERE expires_at IS NOT NULL AND expires_at < now();

-- name: GetSecretVersionByPathAndVersion :one
SELECT sv.*
FROM secrets s
JOIN secret_versions sv ON s.id = sv.secret_id
WHERE s.path = $1 AND sv.version = $2;

-- name: GetAllSecretVersionsByPath :many
SELECT sv.*
FROM secrets s
JOIN secret_versions sv ON s.id = sv.secret_id
WHERE s.path = $1
ORDER BY sv.version DESC;

-- name: DeleteSecretAndVersionsByPath :exec
WITH deleted AS (
    DELETE FROM secrets
    WHERE path = $1
    RETURNING id
)
DELETE FROM secret_versions
WHERE secret_id IN (SELECT id FROM deleted);

-- name: GetSecretsWithVersionCount :many
SELECT s.id, s.path, COUNT(sv.id) AS version_count
FROM secrets s
LEFT JOIN secret_versions sv ON s.id = sv.secret_id
GROUP BY s.id, s.path
ORDER BY version_count DESC;

-- name: GetLatestVersionNumberByPath :one
SELECT COALESCE(MAX(sv.version), 0) AS latest_version
FROM secrets s
LEFT JOIN secret_versions sv ON s.id = sv.secret_id
WHERE s.path = $1;

