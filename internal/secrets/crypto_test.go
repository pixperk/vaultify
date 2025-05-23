package secrets_test

import (
	"testing"

	"github.com/pixperk/vaultify/internal/secrets"
	"github.com/stretchr/testify/require"
)

func setupEncryptor(t *testing.T) *secrets.Encryptor {
	t.Helper()
	key := []byte("01234567890123456789012345678901") // 32 bytes
	encryptor, err := secrets.NewEncryptor(key)
	require.NoError(t, err)
	require.NotNil(t, encryptor)
	return encryptor
}

func TestEncryptDecrypt(t *testing.T) {
	encryptor := setupEncryptor(t)
	plainText := []byte("Hello, World!")

	ciphertext, nonce, err := encryptor.Encrypt(plainText)
	require.NoError(t, err)
	require.NotNil(t, ciphertext)
	require.NotNil(t, nonce)

	decrypted, err := encryptor.Decrypt(ciphertext, nonce)
	require.NoError(t, err)
	require.NotNil(t, decrypted)
	require.Equal(t, plainText, decrypted)
}

func TestInvalidNonceSize(t *testing.T) {
	encryptor := setupEncryptor(t)
	_, err := encryptor.Decrypt([]byte("whatever"), []byte("short"))
	require.EqualError(t, err, "invalid nonce size")
}

func TestInvalidKeySize(t *testing.T) {
	shortKey := []byte("not_32_bytes")
	_, err := secrets.NewEncryptor(shortKey)
	require.EqualError(t, err, "invalid key size")
}
