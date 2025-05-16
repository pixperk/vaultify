package api

import (
	"context"
	"fmt"
	"time"
)

func (s *Server) cleanExpiredSecrets(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := s.store.DeleteExpiredSecrets(ctx)
			cancel()

			if err != nil {
				fmt.Printf("failed to delete expired secrets: %v\n", err)
			} else {
				fmt.Println("expired secrets deleted successfully")
			}
		}
	}()
}
