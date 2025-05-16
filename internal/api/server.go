package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pixperk/vaultify/internal/auth"
	"github.com/pixperk/vaultify/internal/config"
	db "github.com/pixperk/vaultify/internal/db/sqlc"
	"github.com/pixperk/vaultify/internal/secrets"
)

type Server struct {
	config     *config.Config
	store      db.Store
	tokenMaker auth.TokenMaker
	encryptor  *secrets.Encryptor
	router     *gin.Engine
}

func NewServer(config *config.Config, store db.Store) (*Server, error) {
	tokenMaker, err := auth.NewPasetoMaker(config.TokenSymmetricKey)
	if err != nil {
		return nil, fmt.Errorf("cannot create token maker : %w", err)
	}

	encryptor, err := secrets.NewEncryptor([]byte(config.SecretsSymmetricKey))
	if err != nil {
		return nil, fmt.Errorf("cannot create encryptor : %w", err)
	}

	server := &Server{
		config:     config,
		store:      store,
		tokenMaker: tokenMaker,
		encryptor:  encryptor,
	}

	r := server.setupRouter()
	server.router = r

	return server, nil
}

func (s *Server) setupRouter() *gin.Engine {
	r := gin.New()

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "pong"})
	})
	r.POST("/sign-up", s.createUser)
	r.POST("/login", s.loginUser)

	authRoutes := r.Group("/secrets").Use(authMiddleware(s.tokenMaker))
	authRoutes.POST("/", s.createSecret)
	authRoutes.GET("/*path", s.RequireReadAccess(), s.getSecret)
	authRoutes.PUT("/*path", s.RequireWriteAccess(), s.updateSecret)
	authRoutes.POST("/share", s.shareSecret)

	return r

}

func (s *Server) Start(address string) error {
	return http.ListenAndServe(address, s.router)
}

func errorResponse(err error) gin.H {
	return gin.H{"error": err.Error()}
}
