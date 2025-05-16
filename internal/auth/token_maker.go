package auth

import (
	"time"

	"github.com/google/uuid"
)

type TokenMaker interface {
	CreateToken(userId uuid.UUID, email string, duration time.Duration) (string, error)
	VerifyToken(token string) (*Payload, error)
}
