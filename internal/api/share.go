package api

import (
	"database/sql"
	"fmt"
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

// @Summary      Share a secret with another user
// @Description  Allows a user to share their secret with another user, specifying access permission and optional TTL. Verifies ownership before proceeding.
// @Tags         Secrets
// @Accept       json
// @Produce      json
// @Param        request body     shareSecretRequest  true  "Secret share request payload"
// @Success      200     {object} shareSecretResponse
// @Failure      400     {object} swaggerErrorResponse "Invalid input or sharing with self"
// @Failure      401     {object} swaggerErrorResponse "Unauthorized: missing or invalid bearer token"
// @Failure      403     {object} swaggerErrorResponse "Forbidden: not the secret owner"
// @Failure      404     {object} swaggerErrorResponse "Secret or target user not found"
// @Failure      409     {object} swaggerErrorResponse "Secret already shared with target user"
// @Failure      500     {object} swaggerErrorResponse "Internal server error during sharing"
// @Security     ApiKeyAuth
// @Router       /secrets/share [post]
func (s *Server) shareSecret(ctx *gin.Context) {
	var req shareSecretRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}
	authPayload := ctx.MustGet(authorizationPayloadKey).(*auth.Payload)
	ownerEmail := authPayload.Email // Check if the secret exists
	secret, err := s.store.GetLatestSecretByPath(ctx, req.Path)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, errorResponse(fmt.Errorf("the secret does not exist")))
			return
		}
	}

	// Check if the user is the owner of the secret
	if secret.UserID != authPayload.UserID {
		ctx.JSON(http.StatusForbidden, errorResponse(fmt.Errorf("you do not have permission to share this secret")))
		return
	}
	if ownerEmail == req.TargetEmail {
		ctx.JSON(http.StatusBadRequest, errorResponse(fmt.Errorf("you cannot share a secret with yourself")))
		return
	}

	// Check if the target user exists
	_, err = s.store.GetUserByEmail(ctx, req.TargetEmail)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, errorResponse(fmt.Errorf("the target user does not exist")))
			return
		}
	}
	// Check if the target user is already shared
	isAlreadyShared, err := s.store.CheckIfShared(ctx, db.CheckIfSharedParams{
		Path:        req.Path,
		TargetEmail: req.TargetEmail,
	})
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(fmt.Errorf("failed to check if the secret is already shared")))
		return
	}
	if isAlreadyShared {
		ctx.JSON(http.StatusConflict, errorResponse(fmt.Errorf("the secret is already shared with the target user")))
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
	var sharedSecret db.SharingRules
	s.store.ExecTx(ctx, func(q *db.Queries) error {
		sharedSecret, err = s.store.ShareSecret(ctx, args)
		if err != nil {
			return err
		}

		// Log the action
		if err = s.auditSvc.LogTx(ctx, q, authPayload.UserID, authPayload.Email, "share_secret", secret.Path, secret.Version, true, nil); err != nil {
			return fmt.Errorf("failed to log action: %w", err)
		}
		return nil
	})

	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(fmt.Errorf("failed to share the secret")))
		return
	}

	resp := shareSecretResponse{
		Success:     true,
		Path:        sharedSecret.Path,
		Permission:  sharedSecret.Permission,
		OwnerEmail:  sharedSecret.OwnerEmail,
		TargetEmail: sharedSecret.TargetEmail,
	}

	ctx.JSON(http.StatusOK, resp)

}
