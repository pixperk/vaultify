package api

import (
	"database/sql"

	"github.com/gin-gonic/gin"
	db "github.com/pixperk/vaultify/internal/db/sqlc"
)

type rollbackSecretRequest struct {
	Version int32 `json:"version" binding:"required"`
}

type rollbackSecretResponse struct {
	Path      string `json:"path"`
	Version   int32  `json:"version"`
	Encrypted []byte `json:"encrypted_value"`
	Nonce     []byte `json:"nonce"`
}

func (s *Server) rollbackSecret(ctx *gin.Context) {
	var req rollbackSecretRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(400, gin.H{"error": err.Error()})
		return
	}

	secret := ctx.MustGet("secret").(db.GetLatestSecretByPathRow)
	// Check if the version is valid
	if req.Version <= 0 || req.Version > secret.Version {
		ctx.JSON(400, gin.H{"error": "invalid version"})
		return
	}

	rollbackToSecret, err := s.store.GetSecretVersionByPathAndVersion(ctx, db.GetSecretVersionByPathAndVersionParams{
		Path:    secret.Path,
		Version: req.Version,
	},
	)

	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(404, gin.H{"error": "secret version not found"})
			return
		}
		ctx.JSON(500, gin.H{"error": "failed to get secret version"})
		return
	}

	mirroredSecret, err := s.store.CreateNewSecretVersion(ctx, db.CreateNewSecretVersionParams{
		CreatedBy:      rollbackToSecret.CreatedBy,
		EncryptedValue: rollbackToSecret.EncryptedValue,
		Nonce:          rollbackToSecret.Nonce,
		Path:           rollbackToSecret.Path,
	})

	if err != nil {
		ctx.JSON(500, gin.H{"error": "failed to create new secret version"})
		return
	}

	resp := rollbackSecretResponse{
		Path:      secret.Path,
		Version:   mirroredSecret.Version,
		Encrypted: mirroredSecret.EncryptedValue,
		Nonce:     mirroredSecret.Nonce,
	}

	ctx.JSON(200, resp)
}
