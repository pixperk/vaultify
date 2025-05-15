package api

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/pixperk/vaultify/internal/auth"
	db "github.com/pixperk/vaultify/internal/db/sqlc"
)

type createSecretRequest struct {
	Path  string `json:"path" binding:"required"`
	Value string `json:"value" binding:"required"`
}

type secretResponse struct {
	Path      string `json:"path"`
	Encrypted []byte `json:"encrypted_value"`
	Nonce     []byte `json:"nonce"`
}

func (s *Server) createSecret(ctx *gin.Context) {
	var req createSecretRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(400, gin.H{"error": err.Error()})
		return
	}

	authPayload := ctx.MustGet(authorizationPayloadKey).(*auth.Payload)

	// Encrypt the secret value
	encryptedValue, nonce, err := s.encryptor.Encrypt([]byte(req.Value))
	if err != nil {
		ctx.JSON(500, gin.H{"error": "failed to encrypt secret"})
		return
	}

	arg := db.CreateSecretParams{
		UserID: authPayload.ID,
		Path:   fmt.Sprintf("%s/%s", authPayload.Email, req.Path),
	}

	resp := secretResponse{
		Path:      arg.Path,
		Encrypted: encryptedValue, // return encrypted value for client use
		Nonce:     nonce,          // return nonce hex encoded for client use (optional)
	}

	ctx.JSON(200, resp)

}
