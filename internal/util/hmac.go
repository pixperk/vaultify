package util

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
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

func GenerateHMACSignature(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

func VerifyHMAC(message, messageMAC, key []byte) bool {
	expectedMAC := GenerateHMACSignature(message, key)
	return hmac.Equal(messageMAC, expectedMAC)
}
