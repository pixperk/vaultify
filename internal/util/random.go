package util

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func GenerateRandomKey(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}
