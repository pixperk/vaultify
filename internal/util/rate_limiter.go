package util

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pixperk/vaultify/internal/auth"
	"github.com/redis/go-redis/v9"
)

var ctx = context.Background()

type RateLimiter struct {
	client     *redis.Client
	script     string
	maxTokens  int
	refillRate float64
}

func NewRateLimiter(redisAddr string, maxTokens int, refillRate float64) *RateLimiter {
	rdb := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})
	script, err := os.ReadFile("scripts/token_bucket.lua")
	if err != nil {
		panic("Could not read Lua script: " + err.Error())
	}

	return &RateLimiter{
		client:     rdb,
		script:     string(script),
		maxTokens:  maxTokens,
		refillRate: refillRate,
	}
}

// Middleware
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authorizationPayload := c.MustGet("authorization_payload").(*auth.Payload)
		key := fmt.Sprintf("rate_limit:%s", authorizationPayload.UserID)
		now := float64(time.Now().Unix())

		// Call the Lua script to manage the token bucket
		result, err := rl.client.Eval(ctx, rl.script, []string{key},
			rl.maxTokens,
			rl.refillRate,
			now,
		).Result()

		if err != nil {
			fmt.Println("Redis rate limiter error:", err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
			return
		}

		// Lua returns -1 if rate limit exceeded.
		tokensLeft := result.(int64)
		if tokensLeft < 0 {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate limit exceeded"})
			return
		}

		c.Next()
	}
}
