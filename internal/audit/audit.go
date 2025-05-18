package audit

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	db "github.com/pixperk/vaultify/internal/db/sqlc"
	"github.com/pixperk/vaultify/internal/logger"
	"go.uber.org/zap"
)

type Service struct {
	store db.Store
	log   *zap.Logger
}

func NewAuditService(store db.Store, env string) *Service {
	return &Service{
		store: store,
		log:   logger.New(env),
	}
}

// Log writes audit logs using the normal store (outside tx)
func (a *Service) Log(ctx context.Context, userID uuid.UUID, email, action, resourceType, resourcePath string, success bool, reason *string) error {
	auditLog, err := a.logInternal(ctx, nil, userID, email, action, resourceType, resourcePath, success, reason)
	if err != nil {
		return err
	}

	a.logToZap(auditLog, reason)
	return nil
}

// LogTx writes audit logs using the given transaction Queries (inside tx)
func (a *Service) LogTx(ctx context.Context, tx *db.Queries, userID uuid.UUID, email, action, resourceType, resourcePath string, success bool, reason *string) error {
	auditLog, err := a.logInternal(ctx, tx, userID, email, action, resourceType, resourcePath, success, reason)
	if err != nil {
		return err
	}

	a.logToZap(auditLog, reason)
	return nil
}

// internal helper: if tx is nil use normal store, else use tx
func (a *Service) logInternal(ctx context.Context, tx *db.Queries, userID uuid.UUID, email, action, resourceType, resourcePath string, success bool, reason *string) (db.AuditLogs, error) {
	var nullReason sql.NullString
	if reason != nil {
		nullReason = sql.NullString{
			String: *reason,
			Valid:  true,
		}
	}

	params := db.CreateAuditLogParams{
		UserID:       userID,
		UserEmail:    email,
		Action:       action,
		ResourceType: resourceType,
		ResourcePath: resourcePath,
		Success:      success,
		Reason:       nullReason,
	}

	if tx != nil {
		return tx.CreateAuditLog(ctx, params)
	} else {
		return a.store.CreateAuditLog(ctx, params)
	}
}

// Helper function to log to zap
func (a *Service) logToZap(auditLog db.AuditLogs, reason *string) {
	fields := []zap.Field{
		zap.String("user", auditLog.UserEmail),
		zap.String("action", auditLog.Action),
		zap.String("resource_type", auditLog.ResourceType),
		zap.String("resource_path", auditLog.ResourcePath),
		zap.Bool("success", auditLog.Success),
	}
	if reason != nil {
		fields = append(fields, zap.String("reason", *reason))
	}

	a.log.Info("audit log", fields...)
}
