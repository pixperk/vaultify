-- name: CreateSecretWithVersion :one
WITH inserted_secret AS (
    INSERT INTO secrets (user_id, path, expires_at)
    VALUES ($1, $2, $3)
    RETURNING id
)
INSERT INTO secret_versions (secret_id, version, encrypted_value, nonce, created_by)
VALUES (
    (SELECT id FROM inserted_secret), 1, $4, $5, $1
)
RETURNING *;


-- name: GetLatestSecretByPath :one
SELECT sv.*, s.id AS secret_id, s.user_id, s.path
FROM secrets s
JOIN secret_versions sv ON s.id = sv.secret_id
WHERE s.path = $1
  AND (s.expires_at IS NULL OR s.expires_at > now())
ORDER BY sv.version DESC
LIMIT 1;

-- name: GetLatestSecretsForUser :many
SELECT DISTINCT ON (s.id) s.id AS secret_id, s.path, sv.version, sv.encrypted_value, sv.nonce, sv.created_at
FROM secrets s
JOIN secret_versions sv ON s.id = sv.secret_id
WHERE s.user_id = $1
  AND (s.expires_at IS NULL OR s.expires_at > now())
ORDER BY s.id, sv.version DESC;

-- name: CreateNewSecretVersion :one
INSERT INTO secret_versions (
  secret_id, version, encrypted_value, nonce, created_by,
  hmac_signature, hmac_key_id
)
SELECT 
  s.id,
  COALESCE(MAX(sv.version), 0) + 1,
  $2,  -- encrypted_value
  $3,  -- nonce
  $4,  -- created_by
  $5,  -- hmac_signature
  $6   -- hmac_key_id
FROM secrets s
LEFT JOIN secret_versions sv ON s.id = sv.secret_id
WHERE s.path = $1
GROUP BY s.id
RETURNING *;





-- name: GetSecretVersionByPathAndVersion :one
SELECT sv.*, s.id AS secret_id,s.user_id, s.path
FROM secrets s
JOIN secret_versions sv ON s.id = sv.secret_id
WHERE s.path = $1 AND sv.version = $2;

-- name: GetAllSecretVersionsByPath :many
SELECT sv.*
FROM secrets s
JOIN secret_versions sv ON s.id = sv.secret_id
WHERE s.path = $1
ORDER BY sv.version DESC;

-- name: DeleteExpiredSecretAndVersions :exec
WITH deleted AS (
    DELETE FROM secrets
    WHERE expires_at < now()
    RETURNING id
)
DELETE FROM secret_versions
WHERE secret_id IN (SELECT id FROM deleted);

-- name: DeleteSecretAndVersionsByPath :exec
WITH deleted_secret AS (
    DELETE FROM secrets
    WHERE path = $1
    RETURNING id
)
DELETE FROM secret_versions
WHERE secret_id IN (SELECT id FROM deleted_secret);


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

