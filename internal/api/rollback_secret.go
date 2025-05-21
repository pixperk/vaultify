package api

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pixperk/vaultify/internal/auth"
	db "github.com/pixperk/vaultify/internal/db/sqlc"
	"github.com/pixperk/vaultify/internal/logger"
	"github.com/pixperk/vaultify/internal/util"
	"go.uber.org/zap"
)

type rollbackSecretRequest struct {
	Version int32 `json:"version" binding:"required"`
}

type rollbackSecretResponse struct {
	Path            string `json:"path"`
	ExistingVersion int32  `json:"existing_version"`
	ToVersion       int32  `json:"to_version"`
	NewVersion      int32  `json:"new_version"`
	Encrypted       []byte `json:"encrypted_value"`
	Nonce           []byte `json:"nonce"`
}

// rollbackSecret godoc
// @Summary      Rollback secret to a previous version
// @Description  Reverts a secret to a previous version by duplicating the selected version with a new version number. Verifies HMAC before proceeding.
// @Tags         Secrets
// @Accept       json
// @Produce      json
// @Param        path    path     string                  true  "Secret path"
// @Param        request body     rollbackSecretRequest   true  "Rollback secret request payload"
// @Success      200     {object} rollbackSecretResponse
// @Failure      400     {object} swaggerErrorResponse "Invalid input or bad version"
// @Failure      401     {object} swaggerErrorResponse "Unauthorized: invalid HMAC or missing token"
// @Failure      404     {object} swaggerErrorResponse "Secret version not found"
// @Failure      500     {object} swaggerErrorResponse "Internal server error during rollback"
// @Security     ApiKeyAuth
// @Router       /api/v1/secrets/{path}/rollback [post]
func (s *Server) rollbackSecret(ctx *gin.Context) {
	var req rollbackSecretRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
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
		if err != nil {
			logger.New(s.config.Env).Error("failed to log secret access", zap.Error(err))
		}
		return
	} // Check if the version is valid
	if req.Version <= 0 || req.Version > secret.Version {
		ctx.JSON(http.StatusBadRequest, errorResponse(fmt.Errorf("invalid version")))
		return
	}

	rollbackToSecret, err := s.store.GetSecretVersionByPathAndVersion(ctx, db.GetSecretVersionByPathAndVersionParams{
		Path:    secret.Path,
		Version: req.Version,
	},
	)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, errorResponse(fmt.Errorf("secret version not found")))
			return
		}
		ctx.JSON(http.StatusInternalServerError, errorResponse(fmt.Errorf("failed to get secret version")))
		return
	}

	decryptedValue, err := s.encryptor.Decrypt(rollbackToSecret.EncryptedValue, rollbackToSecret.Nonce)

	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	encryptedValue, nonce, err := s.encryptor.Encrypt([]byte(decryptedValue))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	// Create a new HMAC signature for the new secret value
	hmacKey, err := s.store.GetActiveHMACKey(ctx)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(fmt.Errorf("failed to fetch active HMAC key")))
		return
	}

	hmacPayload := util.ComputeHMACPayload(encryptedValue, nonce)
	hmacSig, err := util.GenerateHMACSignature(hmacPayload, hmacKey.Key)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(fmt.Errorf("failed to generate HMAC signature")))
		return
	}

	args := db.CreateNewSecretVersionParams{
		CreatedBy:      rollbackToSecret.CreatedBy,
		EncryptedValue: encryptedValue,
		Nonce:          nonce,
		Path:           rollbackToSecret.Path,
		HmacSignature:  hmacSig,
		HmacKeyID: uuid.NullUUID{
			UUID:  hmacKey.ID,
			Valid: true,
		},
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
	resp := rollbackSecretResponse{
		Path:            secret.Path,
		ExistingVersion: secret.Version,
		ToVersion:       req.Version,
		NewVersion:      mirroredSecret.Version,
		Encrypted:       mirroredSecret.EncryptedValue,
		Nonce:           mirroredSecret.Nonce,
	}

	ctx.JSON(http.StatusOK, resp)
}
