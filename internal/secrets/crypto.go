package secrets

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

type Encryptor struct {
	key []byte
}

func NewEncryptor(key []byte) (*Encryptor, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key size")
	}

	return &Encryptor{key: key}, nil
}

// Encrypt takes plaintext and returns base64(nonce + ciphertext)
func (e *Encryptor) Encrypt(plainText []byte) (ciphertext, nonce []byte, err error) {
	nonce = make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	aead, err := chacha20poly1305.NewX(e.key)
	if err != nil {
		return nil, nil, err
	}

	ciphertext = aead.Seal(nil, nonce, plainText, nil)
	return ciphertext, nonce, nil

}

// Decrypt takes base64(nonce + ciphertext) and returns plaintext
func (e *Encryptor) Decrypt(ciphertext, nonce []byte) ([]byte, error) {

	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, errors.New("invalid nonce size")
	}

	aead, err := chacha20poly1305.NewX(e.key)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, nonce, ciphertext, nil)
}
