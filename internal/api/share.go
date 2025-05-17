package api

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pixperk/vaultify/internal/auth"
	db "github.com/pixperk/vaultify/internal/db/sqlc"
)

type shareSecretRequest struct {
	Path         string `json:"path" binding:"required"`
	TargetEmail  string `json:"target_email" binding:"email,required"`
	Permission   string `json:"permission" binding:"required,oneof=read write"`
	ShareTTLSecs int    `json:"share_ttl_secs"`
}

type shareSecretResponse struct {
	Success     bool   `json:"success"`
	Path        string `json:"path"`
	Permission  string `json:"permission"`
	OwnerEmail  string `json:"owner_email"`
	TargetEmail string `json:"target_email"`
}

func (s *Server) shareSecret(ctx *gin.Context) {

	var req shareSecretRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	authPayload := ctx.MustGet(authorizationPayloadKey).(*auth.Payload)
	ownerEmail := authPayload.Email
	// Check if the secret exists
	secret, err := s.store.GetLatestSecretByPath(ctx, req.Path)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "the secret does not exist"})
			return
		}
	}

	// Check if the user is the owner of the secret
	if secret.UserID != authPayload.UserID {
		ctx.JSON(http.StatusForbidden, gin.H{"error": "you do not have permission to share this secret"})
		return
	}

	if ownerEmail == req.TargetEmail {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "you cannot share a secret with yourself"})
		return
	}

	// Check if the target user exists
	_, err = s.store.GetUserByEmail(ctx, req.TargetEmail)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, gin.H{"error": "the target user does not exist"})
			return
		}
	}

	// Check if the target user is already shared
	isAlreadyShared, err := s.store.CheckIfShared(ctx, db.CheckIfSharedParams{
		Path:        req.Path,
		TargetEmail: req.TargetEmail,
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check if the secret is already shared"})
		return
	}
	if isAlreadyShared {
		ctx.JSON(http.StatusConflict, gin.H{"error": "the secret is already shared with the target user"})
		return
	}

	var sharedUntil sql.NullTime
	if req.ShareTTLSecs > 0 {
		sharedUntil = sql.NullTime{
			Time:  time.Now().Add(time.Duration(req.ShareTTLSecs) * time.Second),
			Valid: true,
		}
	}

	args := db.ShareSecretParams{
		OwnerEmail:  ownerEmail,
		TargetEmail: req.TargetEmail,
		Path:        req.Path,
		Permission:  req.Permission,
		SharedUntil: sharedUntil,
	}

	// Share the secret
	sharedSecret, err := s.store.ShareSecret(ctx, args)

	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to share the secret"})
		return
	}

	/* log.Info("Secret shared",
	zap.String("by", ownerEmail),
	zap.String("with", req.TargetEmail),
	zap.String("secret_path", )) */

	resp := shareSecretResponse{
		Success:     true,
		Path:        sharedSecret.Path,
		Permission:  sharedSecret.Permission,
		OwnerEmail:  sharedSecret.OwnerEmail,
		TargetEmail: sharedSecret.TargetEmail,
	}

	ctx.JSON(http.StatusOK, resp)

}
