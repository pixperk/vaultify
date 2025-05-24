package db

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/pixperk/vaultify/internal/util"
	"github.com/stretchr/testify/require"
)

func createRandomHmacKey(t *testing.T) uuid.UUID {
	key, err := util.GenerateRandomKey(32)
	require.NoError(t, err)
	hmacKey, err := testQueries.InsertHMACKey(context.Background(), key)
	require.NoError(t, err)
	return hmacKey
}

func TestInsertHMACKey(t *testing.T) {
	// Generate a random key
	key, err := util.GenerateRandomKey(32)
	require.NoError(t, err)
	require.NotEmpty(t, key)

	// Insert the key
	hmacKeyID, err := testQueries.InsertHMACKey(context.Background(), key)
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, hmacKeyID)

	// Retrieve the key to verify it was inserted correctly
	hmacKey, err := testQueries.GetHMACKeyByID(context.Background(), hmacKeyID)
	require.NoError(t, err)
	require.Equal(t, hmacKeyID, hmacKey.ID)
	require.Equal(t, key, hmacKey.Key)
	require.True(t, hmacKey.IsActive.Bool)
	require.True(t, hmacKey.IsActive.Valid)
	require.NotZero(t, hmacKey.CreatedAt)
}

func TestGetActiveHMACKey(t *testing.T) {
	// Deactivate all existing keys first to ensure a clean state
	err := testQueries.DeactivateAllHMACKeys(context.Background())
	require.NoError(t, err)

	// Insert a new key (which will be active)
	key, err := util.GenerateRandomKey(32)
	require.NoError(t, err)
	hmacKeyID, err := testQueries.InsertHMACKey(context.Background(), key)
	require.NoError(t, err)

	// Get the active key
	activeKey, err := testQueries.GetActiveHMACKey(context.Background())
	require.NoError(t, err)
	require.Equal(t, hmacKeyID, activeKey.ID)
	require.Equal(t, key, activeKey.Key)
	require.True(t, activeKey.IsActive.Bool)
}

func TestDeactivateAllHMACKeys(t *testing.T) {
	// Insert multiple keys (all will be active by default)
	firstKeyID := createRandomHmacKey(t)
	secondKeyID := createRandomHmacKey(t)

	// Verify both keys are active
	firstKey, err := testQueries.GetHMACKeyByID(context.Background(), firstKeyID)
	require.NoError(t, err)
	require.True(t, firstKey.IsActive.Bool)

	secondKey, err := testQueries.GetHMACKeyByID(context.Background(), secondKeyID)
	require.NoError(t, err)
	require.True(t, secondKey.IsActive.Bool)

	// Deactivate all keys
	err = testQueries.DeactivateAllHMACKeys(context.Background())
	require.NoError(t, err)

	// Verify both keys are now inactive
	firstKeyAfter, err := testQueries.GetHMACKeyByID(context.Background(), firstKeyID)
	require.NoError(t, err)
	require.False(t, firstKeyAfter.IsActive.Bool)

	secondKeyAfter, err := testQueries.GetHMACKeyByID(context.Background(), secondKeyID)
	require.NoError(t, err)
	require.False(t, secondKeyAfter.IsActive.Bool)

	// Try to get an active key, should fail
	_, err = testQueries.GetActiveHMACKey(context.Background())
	require.Error(t, err)
}

func TestGetHMACKeyByID(t *testing.T) {
	// Insert a new key
	key, err := util.GenerateRandomKey(32)
	require.NoError(t, err)
	hmacKeyID, err := testQueries.InsertHMACKey(context.Background(), key)
	require.NoError(t, err)

	// Retrieve the key by ID
	retrievedKey, err := testQueries.GetHMACKeyByID(context.Background(), hmacKeyID)
	require.NoError(t, err)
	require.Equal(t, hmacKeyID, retrievedKey.ID)
	require.Equal(t, key, retrievedKey.Key)

	// Try to retrieve a non-existent key
	nonExistentID := uuid.New()
	_, err = testQueries.GetHMACKeyByID(context.Background(), nonExistentID)
	require.Error(t, err)
}

func TestGetSecretVersionWithHMAC(t *testing.T) {
	// Create a user, secret, and HMAC key
	user := createRandomUser(t)
	path := util.RandomName()
	secret := util.RandomString(int(util.RandomInt(1, 200)))
	hmacID := createRandomHmacKey(t)

	// Encrypt the secret
	encrypted, nonce, _ := encryptAndDecrypt(t, secret)
	hmacSignature := append([]byte{}, encrypted...)
	hmacSignature = append(hmacSignature, nonce...)

	// Create a secret with version
	arg := CreateSecretWithVersionParams{
		CreatedBy: uuid.NullUUID{
			UUID:  user.ID,
			Valid: true,
		},
		Path:           path,
		ExpiresAt:      util.RandomSqlNullTime(),
		EncryptedValue: encrypted,
		Nonce:          nonce,
		HmacKeyID: uuid.NullUUID{
			UUID:  hmacID,
			Valid: true,
		},
		HmacSignature: hmacSignature,
	}

	newSecret, err := testQueries.CreateSecretWithVersion(context.Background(), arg)
	require.NoError(t, err)

	// Get the secret version with HMAC
	params := GetSecretVersionWithHMACParams{
		SecretID: newSecret.SecretID,
		Version:  newSecret.Version,
	}

	secretWithHMAC, err := testQueries.GetSecretVersionWithHMAC(context.Background(), params)
	require.NoError(t, err)

	// Verify the returned data
	require.Equal(t, newSecret.ID, secretWithHMAC.ID)
	require.Equal(t, newSecret.SecretID, secretWithHMAC.SecretID)
	require.Equal(t, newSecret.Version, secretWithHMAC.Version)
	require.Equal(t, newSecret.EncryptedValue, secretWithHMAC.EncryptedValue)
	require.Equal(t, newSecret.Nonce, secretWithHMAC.Nonce)
	require.Equal(t, newSecret.HmacSignature, secretWithHMAC.HmacSignature)
	require.Equal(t, newSecret.HmacKeyID.UUID, secretWithHMAC.HmacKeyID.UUID)

	// Verify the HMAC key is included
	require.NotEmpty(t, secretWithHMAC.HmacKey)

	// Get the HMAC key directly to compare
	hmacKey, err := testQueries.GetHMACKeyByID(context.Background(), hmacID)
	require.NoError(t, err)
	require.Equal(t, hmacKey.Key, secretWithHMAC.HmacKey)
}
