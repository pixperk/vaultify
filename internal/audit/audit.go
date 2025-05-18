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

func (a *Service) Log(ctx context.Context, userID uuid.UUID, email, action, resourceType, resourcePath string, success bool, reason *string) {
	var nullReason sql.NullString
	if reason != nil {
		nullReason = sql.NullString{
			String: *reason,
			Valid:  true,
		}
	}
	log, err := a.store.CreateAuditLog(ctx, db.CreateAuditLogParams{
		UserID:       userID,
		UserEmail:    email,
		Action:       action,
		ResourceType: resourceType,
		ResourcePath: resourcePath,
		Success:      success,
		Reason:       nullReason,
	})

	if err != nil {
		a.log.Error("failed to write audit log to db", zap.Error(err))
		return
	}

	// Log to stdout/dev
	fields := []zap.Field{
		zap.String("user", log.UserEmail),
		zap.String("action", log.Action),
		zap.String("resource_type", log.ResourceType),
		zap.String("resource_path", log.ResourcePath),
		zap.Bool("success", log.Success),
	}

	if reason != nil {
		fields = append(fields, zap.String("reason", *reason))
	}

	a.log.Info("audit log", fields...)
}
