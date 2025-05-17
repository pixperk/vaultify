package util

import (
	"net/http"
	"sync"
	"time"

	"fmt"

	"github.com/gin-gonic/gin"
)

// Limit per IP (or key) struct
type client struct {
	Requests int
	Expiry   time.Time
}

type RateLimiter struct {
	clients map[string]*client
	mu      sync.Mutex
	limit   int           // max requests allowed
	window  time.Duration // time window duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		clients: make(map[string]*client),
		limit:   limit,
		window:  window,
	}

	// Background goroutine to clean expired clients and avoid memory leak
	go func() {
		for {
			time.Sleep(window)
			rl.cleanup()
		}
	}()

	return rl
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	for key, c := range rl.clients {
		if now.After(c.Expiry) {
			delete(rl.clients, key)
		}
	}
}

func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.ClientIP() // Use IP as key

		rl.mu.Lock()
		defer rl.mu.Unlock()

		now := time.Now()

		cl, exists := rl.clients[key]
		if !exists || now.After(cl.Expiry) {
			rl.clients[key] = &client{
				Requests: 1,
				Expiry:   now.Add(rl.window),
			}
		} else {
			if cl.Requests >= rl.limit {
				// Rate limit exceeded
				retryAfter := int(cl.Expiry.Sub(now).Seconds())
				c.Header("Retry-After", fmt.Sprint(retryAfter))
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
					"error": "rate limit exceeded",
				})
				return
			}
			cl.Requests++
		}

		c.Next()
	}
}
