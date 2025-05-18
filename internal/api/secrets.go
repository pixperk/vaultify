package api

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pixperk/vaultify/internal/auth"
	db "github.com/pixperk/vaultify/internal/db/sqlc"
	"github.com/pixperk/vaultify/internal/util"
)

type createSecretRequest struct {
	Path       string `json:"path" binding:"required"`
	Value      string `json:"value" binding:"required"`
	TTLSeconds int64  `json:"ttl_seconds"`
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

	if authPayload == nil {
		ctx.JSON(401, gin.H{"error": "unauthorized"})
		return
	}

	// Encrypt the secret value
	encryptedValue, nonce, err := s.encryptor.Encrypt([]byte(req.Value))
	if err != nil {
		ctx.JSON(500, gin.H{"error": "failed to encrypt secret"})
		return
	}

	var expiresAt sql.NullTime
	if req.TTLSeconds > 0 {
		expiresAt = sql.NullTime{
			Time:  time.Now().Add(time.Duration(req.TTLSeconds) * time.Second),
			Valid: true,
		}
	}

	//make an array of path string words separated by space
	pathWords := strings.Fields(req.Path)
	var path string
	if len(pathWords) < 2 {
		path = fmt.Sprintf("%s/%s", authPayload.Email, req.Path)
	} else {
		//join the path words with a -
		path = fmt.Sprintf("%s/%s", authPayload.Email, strings.Join(pathWords, "-"))
	}

	hmacKey, err := s.store.GetActiveHMACKey(ctx)
	if err != nil {
		ctx.JSON(500, gin.H{"error": "failed to fetch active HMAC key"})
		return
	}

	hmacPayload := util.ComputeHMACPayload(encryptedValue, nonce)
	hmacSig, err := util.GenerateHMACSignature(hmacPayload, hmacKey.Key)
	if err != nil {
		ctx.JSON(500, gin.H{"error": "failed to generate HMAC signature"})
		return
	}

	arg := db.CreateSecretWithVersionParams{
		CreatedBy: uuid.NullUUID{
			UUID:  authPayload.UserID,
			Valid: true,
		},
		Path:           path,
		EncryptedValue: encryptedValue,
		Nonce:          nonce,
		ExpiresAt:      expiresAt,
		HmacSignature:  hmacSig,
		HmacKeyID: uuid.NullUUID{
			UUID:  hmacKey.ID,
			Valid: true,
		},
	}

	secret, err := s.store.CreateSecretWithVersion(ctx, arg)

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
