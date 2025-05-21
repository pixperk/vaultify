package api

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pixperk/vaultify/internal/auth"
	db "github.com/pixperk/vaultify/internal/db/sqlc"
)

type auditLogResponse struct {
	ID              uuid.UUID `json:"id"`
	UserEmail       string    `json:"user_email"`
	Action          string    `json:"action"`
	ResourcePath    string    `json:"resource_path"`
	ResourceVersion int32     `json:"resource_version"`
	Success         bool      `json:"success"`
	Reason          *string   `json:"reason,omitempty"` // pointer avoids issues with NullString
	CreatedAt       time.Time `json:"created_at"`
}

type getAuditLogsResponse struct {
	Logs []auditLogResponse `json:"logs"`
}

// @Summary      Get audit logs
// @Description  Fetch audit logs for the authenticated user with optional filters
// @Tags         Audit
// @Accept       json
// @Produce      json
// @Param        action     query     string  false  "Action filter (e.g., CREATE_SECRET)"
// @Param        path       query     string  false  "Resource path filter (e.g., /vault/secrets/foo)"
// @Param        version    query     int     false  "Resource version filter"
// @Param        success    query     bool    false  "Success status filter (true/false)"
// @Param        from       query     string  false  "Start date in RFC3339 or YYYY-MM-DD"
// @Param        to         query     string  false  "End date in RFC3339 or YYYY-MM-DD"
// @Param        limit      query     int     false  "Limit number of results (default 50)"
// @Param        offset     query     int     false  "Offset for pagination (default 0)"
// @Success      200  {array}   getAuditLogsResponse "List of audit logs"
// @Failure      400  {object}  swaggerErrorResponse "Invalid query parameter"
// @Failure      404  {object}  swaggerErrorResponse "No logs found"
// @Failure      500  {object}  swaggerErrorResponse "Internal server error"
// @Security     BearerAuth
// @Router       /audit/logs [get]
func (s *Server) getAuditLogs(c *gin.Context) {
	authPayload := c.MustGet(authorizationPayloadKey).(*auth.Payload)
	email := authPayload.Email

	// Parse query params
	action := c.Query("action")
	path := c.Query("path")
	versionStr := c.Query("version")
	fromStr := c.Query("from")
	toStr := c.Query("to")
	successStr := c.Query("success")

	// Optional int32 version
	var version int32
	if versionStr != "" {
		v, err := strconv.Atoi(versionStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid version"})
			return
		}
		version = int32(v)
	}

	// Optional success bool
	var successBool bool
	if successStr != "" {
		success, err := strconv.ParseBool(successStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid success value"})
			return
		}
		successBool = success
	}

	// Optional time filters
	var fromTime sql.NullTime
	if fromStr != "" {
		t, err := time.Parse(time.RFC3339, fromStr)
		if err != nil {
			t, err = time.Parse("2006-01-02", fromStr)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid from time"})
				return
			}
		}
		fromTime = sql.NullTime{Time: t.UTC(), Valid: true}
	}

	var toTime sql.NullTime
	if toStr != "" {
		t, err := time.Parse(time.RFC3339, toStr)
		if err != nil {
			t, err = time.Parse("2006-01-02", toStr)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid to time"})
				return
			}
			t = t.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
		}
		toTime = sql.NullTime{Time: t.UTC(), Valid: true}
	}

	limit, err := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if err != nil || limit < 1 {
		limit = 50
	}

	offset, err := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if err != nil || offset < 0 {
		offset = 0
	}

	// Build filter params
	params := db.FilterAuditLogsParams{
		UserEmail:       email,
		Action:          action,
		ResourcePath:    path,
		ResourceVersion: version,
		Success:         successBool,
		CreatedAt:       fromTime,
		CreatedAt_2:     toTime,
		Limit:           int32(limit),
		Offset:          int32(offset),
	}

	// Fetch logs
	logs, err := s.store.FilterAuditLogs(c.Request.Context(), params)
	if err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "no logs found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch logs"})
		return
	}

	cleanLogs := make([]auditLogResponse, 0, len(logs))
	for _, l := range logs {
		var reason *string
		if l.Reason.Valid {
			reason = &l.Reason.String
		}

		cleanLogs = append(cleanLogs, auditLogResponse{
			ID:              l.ID,
			UserEmail:       l.UserEmail,
			Action:          l.Action,
			ResourcePath:    l.ResourcePath,
			ResourceVersion: l.ResourceVersion,
			Success:         l.Success,
			Reason:          reason,
			CreatedAt:       l.CreatedAt.Time, // .Time is valid since .Valid is true from db
		})
	}

	resp := getAuditLogsResponse{
		Logs: cleanLogs,
	}

	c.JSON(http.StatusOK, resp)
}
