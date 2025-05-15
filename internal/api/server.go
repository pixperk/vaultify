package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pixperk/vaultify/internal/config"
	db "github.com/pixperk/vaultify/internal/db/sqlc"
)

type Server struct {
	config *config.Config
	store  db.Store
	//token Maker
	router *gin.Engine
}

func NewServer(config *config.Config, store db.Store) (*Server, error) {

	server := &Server{
		config: config,
		store:  store,
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

	return r

}

func (s *Server) Start(address string) error {
	return http.ListenAndServe(address, s.router)
}
