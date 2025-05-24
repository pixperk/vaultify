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
