package util

import (
	"crypto/rand"
	"fmt"
)

func GenerateRandomKey(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return bytes, nil
}
