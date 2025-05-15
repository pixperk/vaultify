package api

import (
	"time"

	db "github.com/pixperk/vaultify/internal/db/sqlc"
)

type createUserRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type userResponse struct {
	Email             string    `json:"email"`
	Name              string    `json:"name"`
	PasswordChangedAt time.Time `json:"password_changed_at"`
	CreatedAt         time.Time `json:"created_at"`
}

func newUserResponse(user db.Users) userResponse {
	return userResponse{
		Name:      user.Name,
		Email:     user.Email,
		CreatedAt: user.CreatedAt.Time,
	}
}
