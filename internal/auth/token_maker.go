package auth

import (
	"time"

	"github.com/google/uuid"
)

type TokenMaker interface {
	CreateToken(userId uuid.UUID, duration time.Duration) (string, error)
	VerifyToken(token string) (*Payload, error)
}
