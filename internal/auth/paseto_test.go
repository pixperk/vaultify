package auth_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pixperk/vaultify/internal/auth" // ← change this to match your module
	"github.com/stretchr/testify/require"
)

const testKey = "01234567890123456789012345678901" // 32 bytes

// helper: makes a token maker you can reuse everywhere
func newTestMaker(t *testing.T) auth.TokenMaker {
	maker, err := auth.NewPasetoMaker(testKey)
	require.NoError(t, err)
	return maker
}

// helper: makes a test user ID + email + duration
func newTestUser() (uuid.UUID, string, time.Duration) {
	return uuid.New(), "test@example.com", time.Minute
}

func TestPayloadValid(t *testing.T) {
	userID, email, duration := newTestUser()

	payload, err := auth.NewPayload(userID, email, duration)
	require.NoError(t, err)
	require.NotNil(t, payload)
	require.NoError(t, payload.Valid())

	require.Equal(t, userID, payload.UserID)
	require.Equal(t, email, payload.Email)
	require.WithinDuration(t, time.Now().Add(duration), payload.ExpiredAt, time.Second*2)

	// Simulate expiration
	payload.ExpiredAt = time.Now().Add(-time.Minute)
	require.ErrorIs(t, payload.Valid(), auth.ErrExpiredToken)
}

func TestPasetoMaker(t *testing.T) {
	maker := newTestMaker(t)
	userID, email, duration := newTestUser()

	token, err := maker.CreateToken(userID, email, duration)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	payload, err := maker.VerifyToken(token)
	require.NoError(t, err)
	require.NotNil(t, payload)

	require.Equal(t, userID, payload.UserID)
	require.Equal(t, email, payload.Email)
	require.WithinDuration(t, time.Now().Add(duration), payload.ExpiredAt, time.Second*2)
}

func TestPasetoExpiredToken(t *testing.T) {
	maker := newTestMaker(t)
	userID := uuid.New()
	email := "expired@example.com"
	duration := -time.Minute

	token, err := maker.CreateToken(userID, email, duration)
	require.NoError(t, err)

	payload, err := maker.VerifyToken(token)
	require.ErrorIs(t, err, auth.ErrExpiredToken)
	require.Nil(t, payload)
}
