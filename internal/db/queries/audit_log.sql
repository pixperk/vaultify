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
  ($1::TEXT IS NULL OR user_email = $1)
  AND ($2::TEXT IS NULL OR resource_version = $2)
  AND ($3::TEXT IS NULL OR action = $3)
  AND ($4::TIMESTAMPTZ IS NULL OR created_at >= $4)
  AND ($5::TIMESTAMPTZ IS NULL OR created_at <= $5)
ORDER BY created_at DESC
LIMIT $6 OFFSET $7;
