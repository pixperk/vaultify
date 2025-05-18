package api

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pixperk/vaultify/internal/auth"
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

	authorizationPayload := ctx.MustGet(authorizationPayloadKey).(*auth.Payload)

	//Get the HMAC key from the database associated with the secret
	secretHmacKey, err := s.store.GetHMACKeyByID(ctx, secret.HmacKeyID.UUID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	//Verify the hmac signature
	isVerified, err := VerifySecretHMAC(secret, secretHmacKey.Key)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	if !isVerified {
		ctx.JSON(http.StatusUnauthorized, errorResponse(fmt.Errorf("invalid HMAC signature")))
		failureReason := "invalid HMAC signature"
		//Log the secret access in the database
		err = s.auditSvc.Log(ctx, authorizationPayload.UserID, authorizationPayload.Email, "rollback_secret", secret.Path, secret.Version, false, &failureReason)
		return
	}
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

	args := db.CreateNewSecretVersionParams{
		CreatedBy:      rollbackToSecret.CreatedBy,
		EncryptedValue: rollbackToSecret.EncryptedValue,
		Nonce:          rollbackToSecret.Nonce,
		Path:           rollbackToSecret.Path,
	}

	var mirroredSecret db.SecretVersions

	s.store.ExecTx(ctx, func(q *db.Queries) error {
		mirroredSecret, err = s.store.CreateNewSecretVersion(ctx, args)
		if err != nil {
			return err
		}

		// Log the action
		if err = s.auditSvc.LogTx(ctx, q, authorizationPayload.UserID, authorizationPayload.Email, "rollback_secret", secret.Path, mirroredSecret.Version, true, nil); err != nil {
			return fmt.Errorf("failed to log action: %w", err)
		}
		return nil
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
