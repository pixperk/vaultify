package api

import (
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

func VerifySecretHMAC(secret db.GetLatestSecretByPathRow, key []byte) (bool, error) {
	payload := util.ComputeHMACPayload(secret.EncryptedValue, secret.Nonce)
	return util.VerifyHMAC(payload, secret.HmacSignature, key)
}

func (s *Server) getSecret(ctx *gin.Context) {

	log := logger.New(s.config.Env)

	secret := ctx.MustGet("secret").(db.GetLatestSecretByPathRow)

	authorizationPayload := ctx.MustGet(authorizationPayloadKey).(*auth.Payload)

	//Get the HMAC key from the database associated with the secret
	hmacKey, err := s.store.GetHMACKeyByID(ctx, secret.HmacKeyID.UUID)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	//Verify the hmac signature
	isVerified, err := VerifySecretHMAC(secret, hmacKey.Key)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}
	if !isVerified {
		ctx.JSON(http.StatusUnauthorized, errorResponse(fmt.Errorf("invalid HMAC signature")))
		failureReason := "invalid HMAC signature"
		//Log the secret access in the database
		err = s.auditSvc.Log(ctx, authorizationPayload.UserID, authorizationPayload.Email, "read_secret", secret.Path, secret.Version, false, &failureReason)
		if err != nil {
			log.Error("failed to log secret access", zap.Error(err))
		}
		return
	}

	// Decrypt the secret value
	decryptedValue, err := s.encryptor.Decrypt(secret.EncryptedValue, secret.Nonce)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	//log who accessed the secret

	log.Info("Secret read",
		zap.String("user", authorizationPayload.Email),
		zap.String("secret_path", secret.Path))

	//Log the secret access in the database
	err = s.auditSvc.Log(ctx, authorizationPayload.UserID, authorizationPayload.Email, "read_secret", secret.Path, secret.Version, true, nil)
	if err != nil {
		log.Error("failed to log secret access", zap.Error(err))
	}

	resp := getSecretResponse{
		Path:      secret.Path,
		Version:   secret.Version,
		Decrypted: string(decryptedValue),
	}

	ctx.JSON(http.StatusOK, resp)

}

func (s *Server) updateSecret(ctx *gin.Context) {

	var req updateSecretRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	secret := ctx.MustGet("secret").(db.GetLatestSecretByPathRow)

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
		return
	}

	// Encrypt the new secret value

	encryptedValue, nonce, err := s.encryptor.Encrypt([]byte(req.Value))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	// Create a new HMAC signature for the new secret value

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

	authorizationPayload := ctx.MustGet(authorizationPayloadKey).(*auth.Payload)

	// Update the secret in the database
	updatedSecret, err := s.store.CreateNewSecretVersion(ctx, db.CreateNewSecretVersionParams{
		CreatedBy: uuid.NullUUID{
			UUID:  authorizationPayload.UserID,
			Valid: true,
		},
		Path:           secret.Path,
		EncryptedValue: encryptedValue,
		Nonce:          nonce,
		HmacSignature:  hmacSig,
		HmacKeyID: uuid.NullUUID{
			UUID:  hmacKey.ID,
			Valid: true,
		},
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
