package db

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDeleteExpiredSharingRules(t *testing.T) {
	// Create a user for testing
	user := createRandomUser(t)

	// Create another user as target
	targetUser := createRandomUser(t)
	// Create a secret to be shared
	_, path := createNewSecret(t)

	// Create an expired sharing rule (1 day in the past)
	expiredSharedUntil := sql.NullTime{
		Time:  time.Now().Add(-24 * time.Hour),
		Valid: true,
	}

	expiredParams := ShareSecretParams{
		OwnerEmail:  user.Email,
		TargetEmail: targetUser.Email,
		Path:        path,
		Permission:  "read",
		SharedUntil: expiredSharedUntil,
	}

	expiredRule, err := testQueries.ShareSecret(context.Background(), expiredParams)
	require.NoError(t, err)
	require.NotEmpty(t, expiredRule)
	require.Equal(t, expiredRule.OwnerEmail, user.Email)
	require.Equal(t, expiredRule.TargetEmail, targetUser.Email)
	require.Equal(t, expiredRule.Path, path)

	// Create a valid sharing rule (1 day in the future)
	validSharedUntil := sql.NullTime{
		Time:  time.Now().Add(24 * time.Hour),
		Valid: true,
	}

	// Create a different secret for the valid rule
	_, validPath := createNewSecret(t)

	validParams := ShareSecretParams{
		OwnerEmail:  user.Email,
		TargetEmail: targetUser.Email,
		Path:        validPath,
		Permission:  "read",
		SharedUntil: validSharedUntil,
	}

	validRule, err := testQueries.ShareSecret(context.Background(), validParams)
	require.NoError(t, err)
	require.NotEmpty(t, validRule)

	// Create a sharing rule with no expiration
	_, noExpiryPath := createNewSecret(t)

	noExpiryParams := ShareSecretParams{
		OwnerEmail:  user.Email,
		TargetEmail: targetUser.Email,
		Path:        noExpiryPath,
		Permission:  "read",
		SharedUntil: sql.NullTime{Valid: false}, // No expiration
	}

	noExpiryRule, err := testQueries.ShareSecret(context.Background(), noExpiryParams)
	require.NoError(t, err)
	require.NotEmpty(t, noExpiryRule)

	// Delete expired sharing rules
	err = testQueries.DeleteExpiredSharingRules(context.Background())
	require.NoError(t, err)

	// Verify the expired sharing rule no longer exists
	expiredCheckParams := CheckIfSharedParams{
		Path:        path,
		TargetEmail: targetUser.Email,
	}
	isShared, err := testQueries.CheckIfShared(context.Background(), expiredCheckParams)
	require.NoError(t, err)
	require.False(t, isShared)

	// Verify the valid sharing rule still exists
	validCheckParams := CheckIfSharedParams{
		Path:        validPath,
		TargetEmail: targetUser.Email,
	}
	isShared, err = testQueries.CheckIfShared(context.Background(), validCheckParams)
	require.NoError(t, err)
	require.True(t, isShared)

	// Verify the no expiry sharing rule still exists
	noExpiryCheckParams := CheckIfSharedParams{
		Path:        noExpiryPath,
		TargetEmail: targetUser.Email,
	}
	isShared, err = testQueries.CheckIfShared(context.Background(), noExpiryCheckParams)
	require.NoError(t, err)
	require.True(t, isShared)
}

func TestGetSecretsSharedWithMe(t *testing.T) {
	// Create users for testing
	owner := createRandomUser(t)
	target := createRandomUser(t)

	// Create a secret to share
	_, path := createNewSecret(t)

	// Share the secret with the target user
	shareParams := ShareSecretParams{
		OwnerEmail:  owner.Email,
		TargetEmail: target.Email,
		Path:        path,
		Permission:  "read",
		SharedUntil: sql.NullTime{Valid: false}, // No expiration
	}

	sharedSecret, err := testQueries.ShareSecret(context.Background(), shareParams)
	require.NoError(t, err)
	require.NotEmpty(t, sharedSecret)

	// Get secrets shared with the target user
	sharedSecrets, err := testQueries.GetSecretsSharedWithMe(context.Background(), target.Email)
	require.NoError(t, err)
	require.NotEmpty(t, sharedSecrets)
	require.Len(t, sharedSecrets, 1)
	require.Equal(t, sharedSecrets[0].Path, path)
	require.Equal(t, sharedSecrets[0].Permission, "read")
	require.Equal(t, sharedSecrets[0].OwnerEmail, owner.Email)
}

func TestGetPermissions(t *testing.T) {
	// Create users for testing
	owner := createRandomUser(t)
	target := createRandomUser(t)

	// Create a secret to share
	_, path := createNewSecret(t)

	// Share the secret with the target user with read permission
	shareParams := ShareSecretParams{
		OwnerEmail:  owner.Email,
		TargetEmail: target.Email,
		Path:        path,
		Permission:  "read",
		SharedUntil: sql.NullTime{Valid: false}, // No expiration
	}

	_, err := testQueries.ShareSecret(context.Background(), shareParams)
	require.NoError(t, err)

	// Get permissions for the shared secret
	permParams := GetPermissionsParams{
		Path:        path,
		TargetEmail: target.Email,
	}

	permission, err := testQueries.GetPermissions(context.Background(), permParams)
	require.NoError(t, err)
	require.Equal(t, "read", permission)
}

func TestCheckIfShared(t *testing.T) {
	// Create users for testing
	owner := createRandomUser(t)
	target := createRandomUser(t)
	otherUser := createRandomUser(t)

	// Create a secret to share
	_, path := createNewSecret(t)

	// Share the secret with the target user
	shareParams := ShareSecretParams{
		OwnerEmail:  owner.Email,
		TargetEmail: target.Email,
		Path:        path,
		Permission:  "read",
		SharedUntil: sql.NullTime{Valid: false}, // No expiration
	}

	_, err := testQueries.ShareSecret(context.Background(), shareParams)
	require.NoError(t, err)

	// Check if shared with target user (should be true)
	checkParams := CheckIfSharedParams{
		Path:        path,
		TargetEmail: target.Email,
	}

	isShared, err := testQueries.CheckIfShared(context.Background(), checkParams)
	require.NoError(t, err)
	require.True(t, isShared)

	// Check if shared with other user (should be false)
	checkParams.TargetEmail = otherUser.Email
	isShared, err = testQueries.CheckIfShared(context.Background(), checkParams)
	require.NoError(t, err)
	require.False(t, isShared)
}

func TestGetSharedWith(t *testing.T) {
	// Create users for testing
	owner := createRandomUser(t)
	target1 := createRandomUser(t)
	target2 := createRandomUser(t)

	// Create a secret to share
	_, path := createNewSecret(t)

	// Share the secret with target1
	shareParams1 := ShareSecretParams{
		OwnerEmail:  owner.Email,
		TargetEmail: target1.Email,
		Path:        path,
		Permission:  "read",
		SharedUntil: sql.NullTime{Valid: false}, // No expiration
	}

	_, err := testQueries.ShareSecret(context.Background(), shareParams1)
	require.NoError(t, err)

	// Share the secret with target2
	shareParams2 := ShareSecretParams{
		OwnerEmail:  owner.Email,
		TargetEmail: target2.Email,
		Path:        path,
		Permission:  "write",
		SharedUntil: sql.NullTime{Valid: false}, // No expiration
	}

	_, err = testQueries.ShareSecret(context.Background(), shareParams2)
	require.NoError(t, err)

	// Get users the secret is shared with (excluding owner)
	getSharedWithParams := GetSharedWithParams{
		Path:        path,
		TargetEmail: owner.Email, // This will be excluded from results
	}

	sharedWith, err := testQueries.GetSharedWith(context.Background(), getSharedWithParams)
	require.NoError(t, err)
	require.Len(t, sharedWith, 2)

	// Create a map to check if both target users are in the results
	emails := make(map[string]bool)
	for _, user := range sharedWith {
		emails[user.TargetEmail] = true
		require.Equal(t, owner.Email, user.OwnerEmail)
	}

	require.True(t, emails[target1.Email])
	require.True(t, emails[target2.Email])
}

func TestShareSecret(t *testing.T) {
	// Create users for testing
	owner := createRandomUser(t)
	target := createRandomUser(t)

	// Create a secret to share
	_, path := createNewSecret(t)

	// Test case 1: Share with no expiration
	noExpiryParams := ShareSecretParams{
		OwnerEmail:  owner.Email,
		TargetEmail: target.Email,
		Path:        path,
		Permission:  "read",
		SharedUntil: sql.NullTime{Valid: false}, // No expiration
	}

	noExpiryRule, err := testQueries.ShareSecret(context.Background(), noExpiryParams)
	require.NoError(t, err)
	require.NotEmpty(t, noExpiryRule)
	require.Equal(t, noExpiryRule.OwnerEmail, owner.Email)
	require.Equal(t, noExpiryRule.TargetEmail, target.Email)
	require.Equal(t, noExpiryRule.Path, path)
	require.Equal(t, noExpiryRule.Permission, "read")
	require.False(t, noExpiryRule.SharedUntil.Valid)
	require.NotZero(t, noExpiryRule.ID)
	require.NotZero(t, noExpiryRule.CreatedAt)

	// Test case 2: Share with expiration
	// Create a different secret for the timed rule
	_, timedPath := createNewSecret(t)

	futureDuration := 24 * time.Hour // 1 day in the future
	futureTime := time.Now().Add(futureDuration)

	timedParams := ShareSecretParams{
		OwnerEmail:  owner.Email,
		TargetEmail: target.Email,
		Path:        timedPath,
		Permission:  "write", // Different permission
		SharedUntil: sql.NullTime{
			Time:  futureTime,
			Valid: true,
		},
	}

	timedRule, err := testQueries.ShareSecret(context.Background(), timedParams)
	require.NoError(t, err)
	require.NotEmpty(t, timedRule)
	require.Equal(t, timedRule.OwnerEmail, owner.Email)
	require.Equal(t, timedRule.TargetEmail, target.Email)
	require.Equal(t, timedRule.Path, timedPath)
	require.Equal(t, timedRule.Permission, "write")
	require.True(t, timedRule.SharedUntil.Valid)

	// The stored time might lose some precision, so we check that it's within a minute
	timeDiff := timedRule.SharedUntil.Time.Sub(futureTime)
	require.Less(t, timeDiff.Abs(), time.Minute)

	// Test case 3: Verify the rules were correctly stored in the database
	// Check first rule using CheckIfShared
	checkParams1 := CheckIfSharedParams{
		Path:        path,
		TargetEmail: target.Email,
	}

	isShared1, err := testQueries.CheckIfShared(context.Background(), checkParams1)
	require.NoError(t, err)
	require.True(t, isShared1)

	// Check second rule using CheckIfShared
	checkParams2 := CheckIfSharedParams{
		Path:        timedPath,
		TargetEmail: target.Email,
	}

	isShared2, err := testQueries.CheckIfShared(context.Background(), checkParams2)
	require.NoError(t, err)
	require.True(t, isShared2)

	// Verify permissions are correct
	permParams1 := GetPermissionsParams{
		Path:        path,
		TargetEmail: target.Email,
	}

	permission1, err := testQueries.GetPermissions(context.Background(), permParams1)
	require.NoError(t, err)
	require.Equal(t, "read", permission1)

	permParams2 := GetPermissionsParams{
		Path:        timedPath,
		TargetEmail: target.Email,
	}

	permission2, err := testQueries.GetPermissions(context.Background(), permParams2)
	require.NoError(t, err)
	require.Equal(t, "write", permission2)
}
