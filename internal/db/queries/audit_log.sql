-- name: CreateAuditLog :one
INSERT INTO audit_logs (
  user_id,
  user_email,
  action,
  resource_version,
  resource_path,
  success,
  reason
)
VALUES (
  $1, $2, $3, $4, $5, $6, $7
)
RETURNING *;

-- name: FilterAuditLogs :many
SELECT * FROM audit_logs
WHERE
  (user_email = $1 OR $1 = '')
  AND (resource_version = $2 OR $2 = 0)
  AND (action = $3 OR $3 = '')
  AND (created_at >= $4 OR $4 IS NULL)
  AND (created_at <= $5 OR $5 IS NULL)
  AND (resource_path = $6 OR $6 = '')
  AND (success = $7 OR $7 IS NULL)
ORDER BY created_at DESC
LIMIT $8 OFFSET $9;





