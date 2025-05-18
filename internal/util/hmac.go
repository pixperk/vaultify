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

func GenerateHMACSignature(message, key []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, key)
	_, err := mac.Write(message)
	if err != nil {
		return nil, fmt.Errorf("failed to write message to HMAC: %w", err)
	}
	return mac.Sum(nil), nil
}

func VerifyHMAC(message, messageMAC, key []byte) (bool, error) {
	expectedMAC, err := GenerateHMACSignature(message, key)
	if err != nil {
		return false, fmt.Errorf("failed to generate expected HMAC: %w", err)
	}
	return hmac.Equal(messageMAC, expectedMAC), nil
}

func ComputeHMACPayload(encrypted, nonce []byte) []byte {
	return append(encrypted, nonce...)
}
