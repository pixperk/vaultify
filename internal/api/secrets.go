package api

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/lib/pq"
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

type getSecretResponse struct {
	Path      string `json:"path"`
	Decrypted string `json:"decrypted_value"`
}

func (s *Server) createSecret(ctx *gin.Context) {
	var req createSecretRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(400, gin.H{"error": err.Error()})
		return
	}

	authPayload := ctx.MustGet(authorizationPayloadKey).(*auth.Payload)

	if authPayload == nil {
		ctx.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	user, err := s.store.GetUserByID(ctx, authPayload.UserID)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, errorResponse(err))
			return
		}
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	// Encrypt the secret value
	encryptedValue, nonce, err := s.encryptor.Encrypt([]byte(req.Value))
	if err != nil {
		ctx.JSON(500, gin.H{"error": "failed to encrypt secret"})
		return
	}

	arg := db.CreateSecretParams{
		UserID:         authPayload.ID,
		Path:           fmt.Sprintf("%s/%s", user.Email, req.Path),
		EncryptedValue: encryptedValue,
		Nonce:          nonce,
	}

	secret, err := s.store.CreateSecret(ctx, arg)

	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok {
			switch pqErr.Code.Name() {
			case "unique_violation":
				ctx.JSON(http.StatusForbidden, errorResponse(err))
				return
			}
		}
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	resp := secretResponse{
		Path:      arg.Path,
		Encrypted: secret.EncryptedValue,
		Nonce:     secret.Nonce,
	}

	ctx.JSON(200, resp)

}

func (s *Server) getSecret(ctx *gin.Context) {

	authPayload := ctx.MustGet(authorizationPayloadKey).(*auth.Payload)

	rawPath := ctx.Param("path")
	path := strings.TrimPrefix(rawPath, "/") // remove leading slash
	secret, err := s.store.GetSecretByPath(ctx, path)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, errorResponse(err))
			return
		}
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	//TODO : Check if secret is shared with the user
	if secret.UserID != authPayload.UserID {
		ctx.JSON(http.StatusForbidden, errorResponse(fmt.Errorf("you are not authorized to access this secret")))
		return
	}

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
