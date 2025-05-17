package api

import (
	"context"
	"log"
	"time"
)

func (s *Server) cleanExpiredSecrets(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

			if err := s.store.DeleteExpiredSecretAndVersions(ctx); err != nil {
				log.Printf("Error deleting expired secrets: %v\n", err)
			}

			if err := s.store.DeleteExpiredSharingRules(ctx); err != nil {
				log.Printf("Error deleting expired sharing rules: %v\n", err)
			}

			cancel()

			log.Println("Expired secrets and sharing rules cleaned up.")
		}
	}()
}
