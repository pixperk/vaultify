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
