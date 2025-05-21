package api

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	db "github.com/pixperk/vaultify/internal/db/sqlc"
	"github.com/pixperk/vaultify/internal/util"
)

// swaggerErrorResponse is a generic error wrapper for swagger docs
type swaggerErrorResponse struct {
	Error string `json:"error"`
}
type createUserRequest struct {
	Name     string `json:"name" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type userResponse struct {
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type loginUserRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type loginUserResponse struct {
	AccessToken string       `json:"access_token"`
	User        userResponse `json:"user"`
}

func newUserResponse(user db.Users) userResponse {
	return userResponse{
		Name:      user.Name,
		Email:     user.Email,
		CreatedAt: user.CreatedAt.Time,
	}
}

// @Summary      Register a new user
// @Description  Create a new user with hashed password
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        user  body  createUserRequest  true  "User registration info"
// @Success      200   {object}  userResponse
// @Failure      400   {object}  swaggerErrorResponse
// @Failure      500   {object}  swaggerErrorResponse
// @Router       /sign-up [post]
func (s *Server) createUser(ctx *gin.Context) {
	var req createUserRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	hashedPassword, err := util.HashPassword(req.Password)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	arg := db.CreateUserParams{
		Name:         req.Name,
		Email:        req.Email,
		PasswordHash: hashedPassword,
	}
	user, err := s.store.CreateUser(ctx, arg)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	ctx.JSON(http.StatusOK, newUserResponse(user))
}

// @Summary      Log in a user
// @Description  Verify credentials and return access token
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        user  body  loginUserRequest  true  "Login credentials"
// @Success      200   {object}  loginUserResponse
// @Failure      400   {object}  swaggerErrorResponse
// @Failure      401   {object}  swaggerErrorResponse
// @Failure      404   {object}  swaggerErrorResponse
// @Failure      500   {object}  swaggerErrorResponse
// @Router       /login [post]
func (s *Server) loginUser(ctx *gin.Context) {
	var req loginUserRequest
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorResponse(err))
		return
	}

	user, err := s.store.GetUserByEmail(ctx, req.Email)
	if err != nil {
		if err == sql.ErrNoRows {
			ctx.JSON(http.StatusNotFound, errorResponse(err))
			return
		}

		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	err = util.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorResponse(err))
		return
	}

	accessToken, err := s.tokenMaker.CreateToken(user.ID, user.Email, time.Duration(s.config.AccessTokenDuration))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorResponse(err))
		return
	}

	resp := loginUserResponse{
		AccessToken: accessToken,
		User:        newUserResponse(user),
	}

	ctx.JSON(http.StatusOK, resp)
}
