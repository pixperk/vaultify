package logger

import (
	"go.uber.org/zap"
)

func New(env string) *zap.Logger {
	if env == "production" {
		logger, _ := zap.NewProduction()
		return logger
	}
	logger, _ := zap.NewDevelopment()
	return logger
}
