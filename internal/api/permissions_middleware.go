package api

import (
	"database/sql"
	"fmt"
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
		var err error
		var secret db.GetLatestSecretByPathRow
		//Get the query params for version
		version := ctx.Query("version")
		if version == "" {
			secret, err = s.store.GetLatestSecretByPath(ctx, path)
		} else {
			// Parse version string to int32
			var versionInt int32
			if _, err := fmt.Sscanf(version, "%d", &versionInt); err != nil {
				ctx.AbortWithStatusJSON(400, gin.H{"error": "Invalid version format"})
				return
			}

			// Get specific version
			versionSecret, err := s.store.GetSecretVersionByPathAndVersion(ctx, db.GetSecretVersionByPathAndVersionParams{
				Path:    path,
				Version: versionInt,
			})
			if err != nil {
				if err == sql.ErrNoRows {
					ctx.AbortWithStatusJSON(404, gin.H{"error": "Secret version not found"})
				} else {
					ctx.AbortWithStatusJSON(500, gin.H{"error": "Error fetching secret version"})
				}
				return
			}

			// Convert to GetLatestSecretByPathRow type using type conversion
			secret = db.GetLatestSecretByPathRow(versionSecret)
		}

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

func (s *Server) RequireWriteAccess() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		rawPath := ctx.Param("path")
		path := strings.TrimPrefix(rawPath, "/") // remove leading slash
		authPayload := ctx.MustGet(authorizationPayloadKey).(*auth.Payload)

		secret, err := s.store.GetLatestSecretByPath(ctx, path)
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
		permissions, err := s.store.GetPermissions(ctx, db.GetPermissionsParams{
			Path:        path,
			TargetEmail: authPayload.Email,
		})

		if err != nil {

			ctx.AbortWithStatusJSON(403, gin.H{"error": "Access denied"})
			return
		}

		// Check if the user has write access
		if permissions == "write" {
			ctx.Set("secret", secret)
			ctx.Next()
			return
		}

		ctx.AbortWithStatusJSON(403, gin.H{"error": "Access denied"})
	}
}
