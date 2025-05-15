package auth

import "time"

type TokenMaker interface {
	CreateToken(email string, duration time.Duration) (string, error)
	VerifyToken(token string) (*Payload, error)
}
