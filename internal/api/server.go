package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pixperk/vaultify/internal/audit"
	"github.com/pixperk/vaultify/internal/auth"
	"github.com/pixperk/vaultify/internal/config"
	db "github.com/pixperk/vaultify/internal/db/sqlc"
	"github.com/pixperk/vaultify/internal/secrets"
	"github.com/pixperk/vaultify/internal/util"
)

type Server struct {
	config     *config.Config
	store      db.Store
	tokenMaker auth.TokenMaker
	encryptor  *secrets.Encryptor
	router     *gin.Engine
	auditSvc   audit.Service
}

func NewServer(config *config.Config, store db.Store, auditSvc audit.Service) (*Server, error) {

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
		auditSvc:   auditSvc,
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

	rl := util.NewRateLimiter(s.config.RedisAddr, s.config.RateLimitTokens, s.config.RateLimitRefill)

	r.GET("/audit", authMiddleware(s.tokenMaker), rl.Middleware(), s.getAuditLogs)

	authRoutes := r.Group("/secrets").Use(authMiddleware(s.tokenMaker)).Use(rl.Middleware())
	authRoutes.POST("/", s.createSecret)

	authRoutes.GET("/*path", s.RequireReadAccess(), s.getSecret)
	authRoutes.PUT("/*path", s.RequireWriteAccess(), s.updateSecret)
	authRoutes.POST("/rollback/*path", s.RequireWriteAccess(), s.rollbackSecret)
	authRoutes.POST("/share", s.shareSecret)

	return r

}

func (s *Server) Start(address string) error {
	s.StartHMACRotationLoop(context.Background(), 1*time.Hour, 24*time.Hour)
	s.cleanExpiredSecrets(s.config.ExpirationCheckInterval)
	return http.ListenAndServe(address, s.router)
}

func errorResponse(err error) gin.H {
	return gin.H{"error": err.Error()}
}
