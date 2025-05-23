# Vaultify: Technical Overview & Architecture

Vaultify is a modular, fast, and secure secrets management backend written in Go. This doc explains the core architecture, security flow, and how each part of the codebase fits together. If you want to dive into the API, check `/swagger/index.html` for interactive docs.

---

## Secret Management Flow


- **POST `/post secret`**:  
  Accepts `{path, value, ttl}`. The value is encrypted using XChaCha20-Poly1305 (see `internal/secrets/crypto.go`). The encrypted value, nonce, and expiration are saved to Postgres. Every secret creation, access, and share event is audit-logged (`internal/audit/audit.go`, `internal/api/audit.go`).

- **Access Control**:  
  Read/write permissions are enforced using middleware (`internal/api/auth_middleware.go`, `internal/api/permissions_middleware.go`) based on PASETO token claims (`internal/auth/paseto.go`).

- **Secret Sharing**:  
  When you share a secret (`/secret/share`), permissions are persisted and more audit logs are created.

- **Versioning & Rollback**:  
  Updates increment the secret version and regenerate the HMAC signature. Rollbacks are handled in `internal/api/rollback_secret.go`.

- **Rate Limiting**:  
  Token bucket rate limiting is enforced per user or API key (`internal/util/rate_limiter.go`).

- **HMAC Key Rotation**:  
  Secrets are HMAC-signed (`internal/util/hmac.go`). A background worker (`internal/api/rotate_hmac_worker.go`) rotates keys and marks old keys as inactive.

- **Expiration**:  
  Another background worker (`internal/api/expiration_worker.go`) deletes expired secrets and shares.

- **Audit Logs**:  
  Every action is logged for traceability and compliance.

---

## Folder-by-Folder: What Does What?

### `/cmd`
- `server/`: Main entrypoint, starts the API and background workers.

### `/internal/api`
- `access_secrets.go`: Handles GET/PUT secret endpoints, versioning, and updates.
- `audit.go`: Endpoints for audit logging.
- `auth_middleware.go`: Auth via PASETO tokens.
- `expiration_worker.go`: Deletes expired secrets/shares.
- `permissions_middleware.go`: Checks read/write access for secret paths.
- `rollback_secret.go`: Rollback support for previous secret versions.
- `rotate_hmac_worker.go`: Rotates HMAC keys.
- `secrets.go`: Core create/update/delete/read logic.
- `server.go`: Starts HTTP server, routes, and workers.
- `share.go`: Logic for sharing secrets.
- `user.go`: User management.

### `/internal/audit`
- `audit.go`: Core audit logging logic.

### `/internal/auth`
- `paseto.go`: PASETO token creation/validation.
- `payload.go`: Token payload structure.
- `token_maker.go`: Abstraction for token generation/validation.

### `/internal/config`
- `config.go`: Loads/manages app config (DB creds, keys, etc).

### `/internal/db`
- `migrations/`: SQL migration scripts.
- `queries/`: SQLC query files.
- `sqlc/`: Generated Go code from SQLC.

### `/internal/logger`
- `logger.go`: Sets up structured logging (Zap).

### `/internal/secrets`
- `crypto.go`: XChaCha20-Poly1305 encryption/decryption.

### `/internal/util`
- `hmac.go`: HMAC generation/verification.
- `password.go`: Password hashing/verification.
- `rate_limiter.go`: Token bucket rate limiter.

---

## API Docs

- The OpenAPI/Swagger spec is served at `/swagger/index.html`. You can use it to try out all endpoints for secret management, audit, sharing, and auth.

---

## Feature Implementation Details


![Vaultify Architecture](./assets/vaultify-arch.png)

- **Encryption**:  
  All secret values are encrypted with XChaCha20-Poly1305 before storage. Decryption only happens after successful auth and access checks.

- **Access Control**:  
  Permissions are enforced by middleware, using both PASETO token claims and DB-stored permissions.

- **HMAC Signatures & Key Rotation**:  
  Each secret version is HMAC-signed. A worker rotates HMAC keys and keeps old keys for signature verification.

- **Secret Versioning & Rollback**:  
  Updates create new versions. Rollback restores a previous version, re-encrypts, and re-signs.

- **Rate Limiting**:  
  Enforced per user/token using a token bucket.

- **Audit Logging**:  
  Every action (create, read, share, rollback, etc.) emits a structured audit log.

---

## Secret Lifecycle

1. **Secret Creation**:  
   User POSTs secret → Authenticated via PASETO → Value encrypted → HMAC generated → Saved to DB → Audit log written.

2. **Secret Sharing**:  
   Owner grants access to another user/path → DB entry for share, with expiry → All accesses and shares logged.

3. **Secret Access**:  
   Auth middleware validates user/token → Permissions checked → If allowed, secret decrypted and returned → Audit log written.

4. **Secret Update (PUT)**:  
   Value encrypted, version incremented, HMAC regenerated, DB updated, audit written.

5. **Versioning & Rollback**:  
   Each PUT creates a new version. Rollback restores a previous version, re-encrypts with latest key.

6. **Key Rotation**:  
   Worker rotates HMAC keys, deactivates old keys.

7. **Expiration & Cleanup**:  
   Worker removes expired secrets/shares.

8. **Audit & Observability**:  
   All actions are logged and queryable.

---
##  Project Structure

```
.
├── cmd/ # Entrypoint (main.go)
├── internal/
│ ├── api/ # HTTP handlers and routes
│ ├── auth/ # PASETO auth logic
│ ├── config/ # Configuration and env loading
│ ├── db/ # SQLC and migrations
│ ├── logger/ # Zap logger setup
│ ├── secrets/ # Core business logic for secret CRUD
│ └── util/ # Helpers & common utilities
├── Dockerfile # (WIP) App Dockerfile
├── docker-compose.yml # Local DB setup
├── Makefile # Dev scripts (run, migrate, etc)
├── go.mod/go.sum # Go deps
└── sqlc.yaml # SQLC config
```
---
## ⚙️ Setup Instructions

### 1. Clone and configure

```bash
git clone https://github.com/yourname/vaultify.git
cd vaultify
cp app.env.example app.env # Edit DB creds, secrets, etc
```

### 2. Run PostgreSQL

```bash
docker-compose up -d
```

### 3. Run Migrations

```bash
make migrate-up
```

### 4. Generate SQL Queries

```bash
make sqlc
```

### 5. Start the Server

```bash
make run
```

---


## File/Folder Responsibility Table

| Folder/File                         | Role in Secret Management                        |
|-------------------------------------|--------------------------------------------------|
| `internal/api/access_secrets.go`    | Secret GET/PUT/version logic                     |
| `internal/api/rollback_secret.go`   | Secret rollback/version handling                 |
| `internal/api/rotate_hmac_worker.go`| HMAC key rotation worker                         |
| `internal/api/expiration_worker.go` | Expiration cleanup of secrets/shares             |
| `internal/api/permissions_middleware.go` | Access control enforcement                  |
| `internal/audit/audit.go`           | Audit logging                                    |
| `internal/auth/paseto.go`           | Token creation/validation, user auth             |
| `internal/secrets/crypto.go`        | Encryption/decryption (XChaCha20-Poly1305)       |
| `internal/util/hmac.go`             | HMAC signature generation/verification           |
| `internal/util/rate_limiter.go`     | Rate limiting per user/token                     |
| `docs/`                             | API documentation, Swagger/OpenAPI, docs route   |

---

## Contributing

Contributions, issues, and feedback are welcome. For codebase details, check the repo. For API usage, see `/swagger/index.html`.

---
