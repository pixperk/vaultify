package api

import (
	"database/sql"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pixperk/vaultify/internal/auth"
	db "github.com/pixperk/vaultify/internal/db/sqlc"
)

func (s *Server) RequireReadAccess() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		rawPath := ctx.Param("path")
		path := strings.TrimPrefix(rawPath, "/") // remove leading slash
		authPayload := ctx.MustGet(authorizationPayloadKey).(*auth.Payload)

		secret, err := s.store.GetSecretByPath(ctx, path)
		if err != nil {
			if err == sql.ErrNoRows {
				ctx.AbortWithStatusJSON(404, gin.H{"error": "Secret not found"})
			} else {
				ctx.AbortWithStatusJSON(500, gin.H{"error": "Error fetching secret"})
			}
			return
		}

		// Check if the user is owner
		if secret.UserID == authPayload.UserID {
			ctx.Set("secret", secret)
			ctx.Next()
			return
		}

		// Check if shared
		canRead, err := s.store.CheckIfShared(ctx, db.CheckIfSharedParams{
			Path:        path,
			TargetEmail: authPayload.Email,
		})

		if err != nil {
			ctx.AbortWithStatusJSON(500, gin.H{"error": "Permission check failed"})
			return
		}

		if canRead {
			ctx.Set("secret", secret)
			ctx.Next()
			return
		}

		ctx.AbortWithStatusJSON(403, gin.H{"error": "Access denied"})
	}
}
