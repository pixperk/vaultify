package db

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pixperk/vaultify/internal/secrets"
	"github.com/pixperk/vaultify/internal/util"
	"github.com/stretchr/testify/require"
)

func encryptAndDecrypt(t *testing.T, secret string) (encrypted, nonce []byte, decrypted string) {
	key, err := util.GenerateRandomKey(32)
	require.NoError(t, err)
	encryptor, err := secrets.NewEncryptor(key)
	require.NoError(t, err)
	encrypted, nonce, err = encryptor.Encrypt([]byte(secret))
	require.NoError(t, err)
	require.NotEmpty(t, encrypted)
	require.NotEmpty(t, nonce)

	decryptedVal, err := encryptor.Decrypt(encrypted, nonce)
	require.NoError(t, err)
	decrypted = string(decryptedVal)
	require.Equal(t, secret, decrypted)

	return
}

func createNewSecret(t *testing.T) (newSecret SecretVersions, path string) {
	user := createRandomUser(t)
	path = util.RandomName()
	secret := util.RandomString(int(util.RandomInt(1, 200)))
	hmacId := createRandomHmacKey(t)
	encrypted, nonce, _ := encryptAndDecrypt(t, secret)
	hmacSignature := append([]byte{}, encrypted...)
	hmacSignature = append(hmacSignature, nonce...)
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
			UUID:  hmacId,
			Valid: true,
		},
		HmacSignature: hmacSignature,
	}

	newSecret, err := testQueries.CreateSecretWithVersion(context.Background(), arg)
	require.NoError(t, err)
	require.Equal(t, newSecret.CreatedBy, arg.CreatedBy)
	require.Equal(t, newSecret.EncryptedValue, arg.EncryptedValue)
	require.Equal(t, newSecret.Nonce, arg.Nonce)
	require.Equal(t, newSecret.HmacKeyID, arg.HmacKeyID)
	require.Equal(t, newSecret.HmacSignature, arg.HmacSignature)
	require.Equal(t, int(newSecret.Version), 1)
	require.NotZero(t, newSecret.CreatedAt)

	return
}

func TestCreateSecretWithVersion(t *testing.T) {
	createNewSecret(t)
}

func TestCreateNewSecretVersion(t *testing.T) {
	secret, path := createNewSecret(t)

	secretString := util.RandomString(int(util.RandomInt(1, 200)))
	encrypted, nonce, _ := encryptAndDecrypt(t, secretString)

	hmacId := createRandomHmacKey(t)
	hmacSignature := append([]byte{}, encrypted...)
	hmacSignature = append(hmacSignature, nonce...)

	args := CreateNewSecretVersionParams{
		Path:           path,
		EncryptedValue: encrypted,
		Nonce:          nonce,
		CreatedBy:      secret.CreatedBy,
		HmacKeyID: uuid.NullUUID{
			UUID:  hmacId,
			Valid: true,
		},
		HmacSignature: hmacSignature,
	}

	updatedSecret, err := testQueries.CreateNewSecretVersion(context.Background(), args)
	require.NoError(t, err)

	require.Equal(t, updatedSecret.Version, secret.Version+1)
	require.Equal(t, updatedSecret.EncryptedValue, encrypted)
	require.Equal(t, updatedSecret.Nonce, nonce)
	require.Equal(t, updatedSecret.CreatedBy, secret.CreatedBy)
	require.Equal(t, updatedSecret.HmacKeyID.UUID, hmacId)
	require.Equal(t, updatedSecret.HmacSignature, hmacSignature)
	require.NotEqual(t, updatedSecret.ID, secret.ID)
	require.NotZero(t, updatedSecret.CreatedAt)
}

func TestGetLatestSecretByPath(t *testing.T) {
	secret, path := createNewSecret(t)

	// Create another version
	secretString := util.RandomString(int(util.RandomInt(1, 200)))
	encrypted, nonce, _ := encryptAndDecrypt(t, secretString)
	hmacId := createRandomHmacKey(t)
	hmacSignature := append([]byte{}, encrypted...)
	hmacSignature = append(hmacSignature, nonce...)

	args := CreateNewSecretVersionParams{
		Path:           path,
		EncryptedValue: encrypted,
		Nonce:          nonce,
		CreatedBy:      secret.CreatedBy,
		HmacKeyID: uuid.NullUUID{
			UUID:  hmacId,
			Valid: true,
		},
		HmacSignature: hmacSignature,
	}

	newVersion, err := testQueries.CreateNewSecretVersion(context.Background(), args)
	require.NoError(t, err)
	require.Equal(t, newVersion.Version, secret.Version+1)

	// Get the latest secret version
	latestSecret, err := testQueries.GetLatestSecretByPath(context.Background(), path)
	require.NoError(t, err)

	require.Equal(t, latestSecret.Path, path)
	require.Equal(t, latestSecret.Version, newVersion.Version)
	require.Equal(t, latestSecret.EncryptedValue, newVersion.EncryptedValue)
	require.Equal(t, latestSecret.SecretID, newVersion.SecretID)
}

func TestGetSecretVersionByPathAndVersion(t *testing.T) {
	secret, path := createNewSecret(t)

	// Create another version
	secretString := util.RandomString(int(util.RandomInt(1, 200)))
	encrypted, nonce, _ := encryptAndDecrypt(t, secretString)
	hmacId := createRandomHmacKey(t)
	hmacSignature := append([]byte{}, encrypted...)
	hmacSignature = append(hmacSignature, nonce...)

	args := CreateNewSecretVersionParams{
		Path:           path,
		EncryptedValue: encrypted,
		Nonce:          nonce,
		CreatedBy:      secret.CreatedBy,
		HmacKeyID: uuid.NullUUID{
			UUID:  hmacId,
			Valid: true,
		},
		HmacSignature: hmacSignature,
	}

	newVersion, err := testQueries.CreateNewSecretVersion(context.Background(), args)
	require.NoError(t, err)

	// Get the first version
	params := GetSecretVersionByPathAndVersionParams{
		Path:    path,
		Version: 1,
	}

	firstVersion, err := testQueries.GetSecretVersionByPathAndVersion(context.Background(), params)
	require.NoError(t, err)
	require.Equal(t, firstVersion.Path, path)
	require.Equal(t, firstVersion.Version, int32(1))
	require.Equal(t, firstVersion.EncryptedValue, secret.EncryptedValue)

	// Get the second version
	params.Version = 2
	secondVersion, err := testQueries.GetSecretVersionByPathAndVersion(context.Background(), params)
	require.NoError(t, err)
	require.Equal(t, secondVersion.Path, path)
	require.Equal(t, secondVersion.Version, int32(2))
	require.Equal(t, secondVersion.EncryptedValue, newVersion.EncryptedValue)
}

func TestGetAllSecretVersionsByPath(t *testing.T) {
	secret, path := createNewSecret(t)

	// Create another version
	secretString := util.RandomString(int(util.RandomInt(1, 200)))
	encrypted, nonce, _ := encryptAndDecrypt(t, secretString)
	hmacId := createRandomHmacKey(t)
	hmacSignature := append([]byte{}, encrypted...)
	hmacSignature = append(hmacSignature, nonce...)

	args := CreateNewSecretVersionParams{
		Path:           path,
		EncryptedValue: encrypted,
		Nonce:          nonce,
		CreatedBy:      secret.CreatedBy,
		HmacKeyID: uuid.NullUUID{
			UUID:  hmacId,
			Valid: true,
		},
		HmacSignature: hmacSignature,
	}

	newVersion, err := testQueries.CreateNewSecretVersion(context.Background(), args)
	require.NoError(t, err)

	// Get all versions
	versions, err := testQueries.GetAllSecretVersionsByPath(context.Background(), path)
	require.NoError(t, err)
	require.Len(t, versions, 2)

	// Verify the order (descending by version)
	require.Equal(t, versions[0].Version, newVersion.Version)
	require.Equal(t, versions[1].Version, secret.Version)
	require.Equal(t, versions[0].SecretID, versions[1].SecretID)
}

func TestGetLatestSecretsForUser(t *testing.T) {
	// Create a user
	user := createRandomUser(t)

	// Create multiple secrets for the same user
	numSecrets := 3
	paths := make([]string, numSecrets)

	for i := 0; i < numSecrets; i++ {
		path := util.RandomName()
		paths[i] = path

		secret := util.RandomString(int(util.RandomInt(1, 200)))
		hmacId := createRandomHmacKey(t)
		encrypted, nonce, _ := encryptAndDecrypt(t, secret)
		hmacSignature := append([]byte{}, encrypted...)
		hmacSignature = append(hmacSignature, nonce...)

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
				UUID:  hmacId,
				Valid: true,
			},
			HmacSignature: hmacSignature,
		}

		_, err := testQueries.CreateSecretWithVersion(context.Background(), arg)
		require.NoError(t, err)

		// For one of the secrets, create a second version
		if i == 0 {
			newSecret := util.RandomString(int(util.RandomInt(1, 200)))
			newEncrypted, newNonce, _ := encryptAndDecrypt(t, newSecret)
			newHmacSignature := append([]byte{}, newEncrypted...)
			newHmacSignature = append(newHmacSignature, newNonce...)

			versionArg := CreateNewSecretVersionParams{
				Path:           path,
				EncryptedValue: newEncrypted,
				Nonce:          newNonce,
				CreatedBy:      arg.CreatedBy,
				HmacKeyID:      arg.HmacKeyID,
				HmacSignature:  newHmacSignature,
			}

			_, err = testQueries.CreateNewSecretVersion(context.Background(), versionArg)
			require.NoError(t, err)
		}
	}

	// Get all secrets for the user
	userSecrets, err := testQueries.GetLatestSecretsForUser(context.Background(), user.ID)
	require.NoError(t, err)
	require.Len(t, userSecrets, numSecrets)

	// Verify each path exists in the results
	foundPaths := make(map[string]bool)
	for _, secret := range userSecrets {
		foundPaths[secret.Path] = true
	}

	for _, path := range paths {
		require.True(t, foundPaths[path])
	}
}

func TestDeleteSecretAndVersionsByPath(t *testing.T) {
	secret, path := createNewSecret(t)

	// Create another version
	secretString := util.RandomString(int(util.RandomInt(1, 200)))
	encrypted, nonce, _ := encryptAndDecrypt(t, secretString)
	hmacId := createRandomHmacKey(t)
	hmacSignature := append([]byte{}, encrypted...)
	hmacSignature = append(hmacSignature, nonce...)

	args := CreateNewSecretVersionParams{
		Path:           path,
		EncryptedValue: encrypted,
		Nonce:          nonce,
		CreatedBy:      secret.CreatedBy,
		HmacKeyID: uuid.NullUUID{
			UUID:  hmacId,
			Valid: true,
		},
		HmacSignature: hmacSignature,
	}

	_, err := testQueries.CreateNewSecretVersion(context.Background(), args)
	require.NoError(t, err)

	// Verify secret exists
	versions, err := testQueries.GetAllSecretVersionsByPath(context.Background(), path)
	require.NoError(t, err)
	require.Len(t, versions, 2)

	// Delete the secret and all its versions
	err = testQueries.DeleteSecretAndVersionsByPath(context.Background(), path)
	require.NoError(t, err)

	// Verify the secret no longer exists
	latestSecret, err := testQueries.GetLatestSecretByPath(context.Background(), path)
	require.Error(t, err)
	require.Empty(t, latestSecret)
}

func TestDeleteExpiredSecretAndVersions(t *testing.T) {
	user := createRandomUser(t)

	// Create a secret that's already expired
	expiredPath := util.RandomName()
	expiredSecret := util.RandomString(int(util.RandomInt(1, 200)))
	hmacId := createRandomHmacKey(t)
	encrypted, nonce, _ := encryptAndDecrypt(t, expiredSecret)
	hmacSignature := append([]byte{}, encrypted...)
	hmacSignature = append(hmacSignature, nonce...)

	expiredTime := sql.NullTime{
		Time:  time.Now().Add(-24 * time.Hour), // 1 day in the past
		Valid: true,
	}

	expiredArg := CreateSecretWithVersionParams{
		CreatedBy: uuid.NullUUID{
			UUID:  user.ID,
			Valid: true,
		},
		Path:           expiredPath,
		ExpiresAt:      expiredTime,
		EncryptedValue: encrypted,
		Nonce:          nonce,
		HmacKeyID: uuid.NullUUID{
			UUID:  hmacId,
			Valid: true,
		},
		HmacSignature: hmacSignature,
	}

	expiredSecretVersion, err := testQueries.CreateSecretWithVersion(context.Background(), expiredArg)
	require.NoError(t, err)
	require.NotEmpty(t, expiredSecretVersion)

	// Create a secret that's not expired
	validPath := util.RandomName()
	validSecret := util.RandomString(int(util.RandomInt(1, 200)))
	validHmacId := createRandomHmacKey(t)
	validEncrypted, validNonce, _ := encryptAndDecrypt(t, validSecret)
	validHmacSignature := append([]byte{}, validEncrypted...)
	validHmacSignature = append(validHmacSignature, validNonce...)

	validTime := sql.NullTime{
		Time:  time.Now().Add(24 * time.Hour), // 1 day in the future
		Valid: true,
	}

	validArg := CreateSecretWithVersionParams{
		CreatedBy: uuid.NullUUID{
			UUID:  user.ID,
			Valid: true,
		},
		Path:           validPath,
		ExpiresAt:      validTime,
		EncryptedValue: validEncrypted,
		Nonce:          validNonce,
		HmacKeyID: uuid.NullUUID{
			UUID:  validHmacId,
			Valid: true,
		},
		HmacSignature: validHmacSignature,
	}

	validSecretVersion, err := testQueries.CreateSecretWithVersion(context.Background(), validArg)
	require.NoError(t, err)
	require.NotEmpty(t, validSecretVersion)

	// Create a secret with no expiration
	noExpiryPath := util.RandomName()
	noExpirySecret := util.RandomString(int(util.RandomInt(1, 200)))
	noExpiryHmacId := createRandomHmacKey(t)
	noExpiryEncrypted, noExpiryNonce, _ := encryptAndDecrypt(t, noExpirySecret)
	noExpiryHmacSignature := append([]byte{}, noExpiryEncrypted...)
	noExpiryHmacSignature = append(noExpiryHmacSignature, noExpiryNonce...)

	noExpiryArg := CreateSecretWithVersionParams{
		CreatedBy: uuid.NullUUID{
			UUID:  user.ID,
			Valid: true,
		},
		Path:           noExpiryPath,
		ExpiresAt:      sql.NullTime{Valid: false}, // No expiration
		EncryptedValue: noExpiryEncrypted,
		Nonce:          noExpiryNonce,
		HmacKeyID: uuid.NullUUID{
			UUID:  noExpiryHmacId,
			Valid: true,
		},
		HmacSignature: noExpiryHmacSignature,
	}

	noExpirySecretVersion, err := testQueries.CreateSecretWithVersion(context.Background(), noExpiryArg)
	require.NoError(t, err)
	require.NotEmpty(t, noExpirySecretVersion)

	// Delete expired secrets
	err = testQueries.DeleteExpiredSecretAndVersions(context.Background())
	require.NoError(t, err)

	// Verify the expired secret no longer exists
	expiredLatestSecret, err := testQueries.GetLatestSecretByPath(context.Background(), expiredPath)
	require.Error(t, err)
	require.Empty(t, expiredLatestSecret)

	// Verify the valid (not expired) secret still exists
	validLatestSecret, err := testQueries.GetLatestSecretByPath(context.Background(), validPath)
	require.NoError(t, err)
	require.NotEmpty(t, validLatestSecret)
	require.Equal(t, validLatestSecret.Path, validPath)

	// Verify the no expiry secret still exists
	noExpiryLatestSecret, err := testQueries.GetLatestSecretByPath(context.Background(), noExpiryPath)
	require.NoError(t, err)
	require.NotEmpty(t, noExpiryLatestSecret)
	require.Equal(t, noExpiryLatestSecret.Path, noExpiryPath)
}

func TestGetSecretsWithVersionCount(t *testing.T) {
	// Create several secrets with different version counts
	for i := 0; i < 3; i++ {
		secret, path := createNewSecret(t)

		// For the first secret, create 2 more versions
		if i == 0 {
			for j := 0; j < 2; j++ {
				secretString := util.RandomString(int(util.RandomInt(1, 200)))
				encrypted, nonce, _ := encryptAndDecrypt(t, secretString)
				hmacId := createRandomHmacKey(t)
				hmacSignature := append([]byte{}, encrypted...)
				hmacSignature = append(hmacSignature, nonce...)

				args := CreateNewSecretVersionParams{
					Path:           path,
					EncryptedValue: encrypted,
					Nonce:          nonce,
					CreatedBy:      secret.CreatedBy,
					HmacKeyID: uuid.NullUUID{
						UUID:  hmacId,
						Valid: true,
					},
					HmacSignature: hmacSignature,
				}

				_, err := testQueries.CreateNewSecretVersion(context.Background(), args)
				require.NoError(t, err)
			}
		}

		// For the second secret, create 1 more version
		if i == 1 {
			secretString := util.RandomString(int(util.RandomInt(1, 200)))
			encrypted, nonce, _ := encryptAndDecrypt(t, secretString)
			hmacId := createRandomHmacKey(t)
			hmacSignature := append([]byte{}, encrypted...)
			hmacSignature = append(hmacSignature, nonce...)

			args := CreateNewSecretVersionParams{
				Path:           path,
				EncryptedValue: encrypted,
				Nonce:          nonce,
				CreatedBy:      secret.CreatedBy,
				HmacKeyID: uuid.NullUUID{
					UUID:  hmacId,
					Valid: true,
				},
				HmacSignature: hmacSignature,
			}

			_, err := testQueries.CreateNewSecretVersion(context.Background(), args)
			require.NoError(t, err)
		}
	}

	// Get secrets with version counts
	secretsWithCounts, err := testQueries.GetSecretsWithVersionCount(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, secretsWithCounts)

	// Verify ordering - should be in descending order by version count
	for i := 0; i < len(secretsWithCounts)-1; i++ {
		require.GreaterOrEqual(t, secretsWithCounts[i].VersionCount, secretsWithCounts[i+1].VersionCount)
	}
}

func TestGetLatestVersionNumberByPath(t *testing.T) {
	secret, path := createNewSecret(t)

	// Check initial version number
	latestVersion, err := testQueries.GetLatestVersionNumberByPath(context.Background(), path)
	require.NoError(t, err)
	require.Equal(t, int64(1), latestVersion)

	// Create another version
	secretString := util.RandomString(int(util.RandomInt(1, 200)))
	encrypted, nonce, _ := encryptAndDecrypt(t, secretString)
	hmacId := createRandomHmacKey(t)
	hmacSignature := append([]byte{}, encrypted...)
	hmacSignature = append(hmacSignature, nonce...)

	args := CreateNewSecretVersionParams{
		Path:           path,
		EncryptedValue: encrypted,
		Nonce:          nonce,
		CreatedBy:      secret.CreatedBy,
		HmacKeyID: uuid.NullUUID{
			UUID:  hmacId,
			Valid: true,
		},
		HmacSignature: hmacSignature,
	}

	_, err = testQueries.CreateNewSecretVersion(context.Background(), args)
	require.NoError(t, err)

	// Check new version number
	latestVersion, err = testQueries.GetLatestVersionNumberByPath(context.Background(), path)
	require.NoError(t, err)
	require.Equal(t, int64(2), latestVersion)

	// Check non-existent path
	nonExistentPath := util.RandomName()
	latestVersion, err = testQueries.GetLatestVersionNumberByPath(context.Background(), nonExistentPath)
	require.NoError(t, err)
	require.Equal(t, int64(0), latestVersion)
}
