package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pixperk/vaultify/internal/auth"
	"github.com/pixperk/vaultify/internal/config"
	db "github.com/pixperk/vaultify/internal/db/sqlc"
)

type Server struct {
	config     *config.Config
	store      db.Store
	tokenMaker auth.TokenMaker
	router     *gin.Engine
}

func NewServer(config *config.Config, store db.Store) (*Server, error) {
	tokenMaker, err := auth.NewPasetoMaker(config.TokenSymmeticKey)
	if err != nil {
		return nil, fmt.Errorf("cannot create token maker : %w", err)
	}
	server := &Server{
		config:     config,
		store:      store,
		tokenMaker: tokenMaker,
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

	return r

}

func (s *Server) Start(address string) error {
	return http.ListenAndServe(address, s.router)
}

func errorResponse(err error) gin.H {
	return gin.H{"error": err.Error()}
}
