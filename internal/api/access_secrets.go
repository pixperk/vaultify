package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	db "github.com/pixperk/vaultify/internal/db/sqlc"
)

func (s *Server) getSecret(ctx *gin.Context) {

	secret := ctx.MustGet("secret").(db.Secrets)

	// Decrypt the secret value
	decryptedValue, err := s.encryptor.Decrypt(secret.EncryptedValue, secret.Nonce)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	resp := getSecretResponse{
		Path:      secret.Path,
		Decrypted: string(decryptedValue),
	}

	ctx.JSON(http.StatusOK, resp)

}

type updateSecretRequest struct {
	Value string `json:"value" binding:"required"`
}

type updateSecretResponse struct {
	Path      string `json:"path"`
	Encrypted []byte `json:"encrypted_value"`
	Nonce     []byte `json:"nonce"`
}

func (s *Server) updateSecret(ctx *gin.Context) {

	var req updateSecretRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	secret := ctx.MustGet("secret").(db.Secrets)
	// Encrypt the new secret value

	encryptedValue, nonce, err := s.encryptor.Encrypt([]byte(req.Value))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	// Update the secret in the database
	updatedSecret, err := s.store.UpdateSecret(ctx, db.UpdateSecretParams{
		Path:           secret.Path,
		EncryptedValue: encryptedValue,
		Nonce:          nonce,
	})

	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	resp := updateSecretResponse{
		Path:      updatedSecret.Path,
		Encrypted: updatedSecret.EncryptedValue,
		Nonce:     updatedSecret.Nonce,
	}

	ctx.JSON(http.StatusOK, resp)

}
