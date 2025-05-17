package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pixperk/vaultify/internal/auth"
	db "github.com/pixperk/vaultify/internal/db/sqlc"
	"github.com/pixperk/vaultify/internal/logger"
	"go.uber.org/zap"
)

type getSecretResponse struct {
	Path      string `json:"path"`
	Version   int32  `json:"version"`
	Decrypted string `json:"decrypted_value"`
}

type updateSecretRequest struct {
	Value string `json:"value" binding:"required"`
}

type updateSecretResponse struct {
	Path      string `json:"path"`
	Version   int32  `json:"version"`
	Encrypted []byte `json:"encrypted_value"`
	Nonce     []byte `json:"nonce"`
}

func (s *Server) getSecret(ctx *gin.Context) {

	log := logger.New(s.config.Env)

	secret := ctx.MustGet("secret").(db.GetLatestSecretByPathRow)

	// Decrypt the secret value
	decryptedValue, err := s.encryptor.Decrypt(secret.EncryptedValue, secret.Nonce)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	//log who accessed the secret
	authorizationPayload := ctx.MustGet(authorizationPayloadKey).(*auth.Payload)
	log.Info("Secret read",
		zap.String("user", authorizationPayload.Email),
		zap.String("secret_path", secret.Path))

	resp := getSecretResponse{
		Path:      secret.Path,
		Version:   secret.Version,
		Decrypted: string(decryptedValue),
	}

	ctx.JSON(http.StatusOK, resp)

}

func (s *Server) updateSecret(ctx *gin.Context) {

	log := logger.New(s.config.Env)

	var req updateSecretRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	secret := ctx.MustGet("secret").(db.GetLatestSecretByPathRow)
	// Encrypt the new secret value

	encryptedValue, nonce, err := s.encryptor.Encrypt([]byte(req.Value))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	authorizationPayload := ctx.MustGet(authorizationPayloadKey).(*auth.Payload)
	//log who accessed the secret
	log.Info("Secret overwritten",
		zap.String("user", authorizationPayload.Email),
		zap.String("secret_path", secret.Path))

	// Update the secret in the database
	updatedSecret, err := s.store.CreateNewSecretVersion(ctx, db.CreateNewSecretVersionParams{
		CreatedBy: uuid.NullUUID{
			UUID:  authorizationPayload.UserID,
			Valid: true,
		},
		Path:           secret.Path,
		EncryptedValue: encryptedValue,
		Nonce:          nonce,
	})

	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	resp := updateSecretResponse{
		Path:      secret.Path,
		Version:   updatedSecret.Version,
		Encrypted: updatedSecret.EncryptedValue,
		Nonce:     updatedSecret.Nonce,
	}

	ctx.JSON(http.StatusOK, resp)

}
