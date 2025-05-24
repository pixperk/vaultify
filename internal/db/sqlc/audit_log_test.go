package db

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCreateAuditLog(t *testing.T) {
	// Create a user for the audit log
	user := createRandomUser(t)

	// Create audit log params for a successful action
	successfulParams := CreateAuditLogParams{
		UserID:          user.ID,
		UserEmail:       user.Email,
		Action:          "GET_SECRET",
		ResourceVersion: 1,
		ResourcePath:    "/secrets/api-key",
		Success:         true,
		Reason:          sql.NullString{Valid: false}, // No reason for success
	}

	auditLog, err := testQueries.CreateAuditLog(context.Background(), successfulParams)
	require.NoError(t, err)
	require.NotEmpty(t, auditLog)

	// Verify all fields match
	require.Equal(t, user.ID, auditLog.UserID)
	require.Equal(t, user.Email, auditLog.UserEmail)
	require.Equal(t, "GET_SECRET", auditLog.Action)
	require.Equal(t, int32(1), auditLog.ResourceVersion)
	require.Equal(t, "/secrets/api-key", auditLog.ResourcePath)
	require.True(t, auditLog.Success)
	require.False(t, auditLog.Reason.Valid)
	require.NotZero(t, auditLog.ID)
	require.NotZero(t, auditLog.CreatedAt)

	// Create audit log for a failed action with a reason
	failedParams := CreateAuditLogParams{
		UserID:          user.ID,
		UserEmail:       user.Email,
		Action:          "PUT_SECRET",
		ResourceVersion: 2,
		ResourcePath:    "/secrets/db-password",
		Success:         false,
		Reason: sql.NullString{
			String: "Permission denied",
			Valid:  true,
		},
	}

	failedLog, err := testQueries.CreateAuditLog(context.Background(), failedParams)
	require.NoError(t, err)
	require.NotEmpty(t, failedLog)

	// Verify all fields match for the failed action
	require.Equal(t, user.ID, failedLog.UserID)
	require.Equal(t, user.Email, failedLog.UserEmail)
	require.Equal(t, "PUT_SECRET", failedLog.Action)
	require.Equal(t, int32(2), failedLog.ResourceVersion)
	require.Equal(t, "/secrets/db-password", failedLog.ResourcePath)
	require.False(t, failedLog.Success)
	require.True(t, failedLog.Reason.Valid)
	require.Equal(t, "Permission denied", failedLog.Reason.String)
	require.NotZero(t, failedLog.ID)
	require.NotZero(t, failedLog.CreatedAt)
}
