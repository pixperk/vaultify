package api

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pixperk/vaultify/internal/auth"
	db "github.com/pixperk/vaultify/internal/db/sqlc"
)

func (s *Server) getAuditLogs(c *gin.Context) {

	authPayload := c.MustGet(authorizationPayloadKey).(*auth.Payload)
	email := authPayload.Email
	action := c.Query("action")      // "" means no filter
	path := c.Query("path")          // "" means no filter
	successStr := c.Query("success") // "" means no filter

	// Validate success query param
	var success bool
	var err error
	if successStr != "" {
		if successStr != "true" && successStr != "false" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid success value"})
			return
		}
		success, err = strconv.ParseBool(successStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid success value"})
			return
		}

		// Convert to int32
		versionStr := c.Query("version")
		var version int32 = 0
		if versionStr != "" {
			v, err := strconv.Atoi(versionStr)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid version"})
				return
			}
			version = int32(v)
		}

		// Parse from time with fallback
		fromTime := time.Unix(0, 0).UTC()
		if fromStr := c.Query("from"); fromStr != "" {
			t, err := time.Parse(time.RFC3339, fromStr)
			if err != nil {
				t, err = time.Parse("2006-01-02", fromStr)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "invalid from time"})
					return
				}
			}
			fromTime = t.UTC()
		}

		// Parse to time with fallback (inclusive end of day)
		toTime := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
		if toStr := c.Query("to"); toStr != "" {
			t, err := time.Parse(time.RFC3339, toStr)
			if err != nil {
				t, err = time.Parse("2006-01-02", toStr)
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "invalid to time"})
					return
				}
				t = t.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
			}
			toTime = t.UTC()
		}

		limit, err := strconv.Atoi(c.DefaultQuery("limit", "50"))
		if err != nil || limit < 1 {
			limit = 50
		}

		offset, err := strconv.Atoi(c.DefaultQuery("offset", "0"))
		if err != nil || offset < 0 {
			offset = 0
		}

		params := db.FilterAuditLogsParams{
			UserEmail:       email,
			ResourceVersion: version,
			Action:          action,
			CreatedAt:       sql.NullTime{Time: fromTime, Valid: true},
			CreatedAt_2:     sql.NullTime{Time: toTime, Valid: true},
			ResourcePath:    path,
			Success:         success,
			Limit:           int32(limit),
			Offset:          int32(offset),
		}

		logs, err := s.store.FilterAuditLogs(c.Request.Context(), params)
		if err != nil {
			if err == sql.ErrNoRows {
				c.JSON(http.StatusNotFound, gin.H{"error": "no logs found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch logs"})
			return
		}

		c.JSON(http.StatusOK, logs)
	}
}
