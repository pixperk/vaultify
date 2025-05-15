package main

import (
	"database/sql"
	"log"

	"github.com/pixperk/vaultify/internal/api"
	"github.com/pixperk/vaultify/internal/config"
	db "github.com/pixperk/vaultify/internal/db/sqlc"
	"github.com/pixperk/vaultify/internal/logger"
	"go.uber.org/zap"

	_ "github.com/lib/pq"
)

func main() {
	cfg, err := config.LoadConfig(".")
	if err != nil {
		log.Fatal("cannot load config", zap.Error(err))
	}
	log := logger.New(cfg.Env)

	conn, err := sql.Open("postgres", cfg.DBSource)
	if err != nil {
		log.Fatal("cannot connect to db", zap.Error(err))
	}

	store := db.NewStore(conn)

	server, err := api.NewServer(&cfg, *store)
	if err != nil {
		log.Fatal("cannot create server", zap.Error(err))
	}

	log.Info("Starting Vaultify server", zap.String("port", cfg.Port))

	err = server.Start(":" + cfg.Port)
	if err != nil {
		log.Fatal("cannot start server", zap.Error(err))
	}

}
