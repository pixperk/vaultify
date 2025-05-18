package api

import (
	"context"
	"log"
	"time"
)

func (s *Server) StartHMACRotationLoop(ctx context.Context, interval time.Duration, staleDuration time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := s.store.RotateHmacKey(ctx, staleDuration); err != nil {
					log.Printf("HMAC key rotation failed: %v", err)
				}
			case <-ctx.Done():
				log.Println("Shutting down HMAC rotation loop...")
				return
			}
		}
	}()
}
