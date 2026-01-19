// Package redis provides a Redis rate limiter implementation.
package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// RateLimiter implements goauth.RateLimiter using Redis.
type RateLimiter struct {
	client *redis.Client
}

// New creates a new Redis rate limiter.
func New(client *redis.Client) *RateLimiter {
	return &RateLimiter{client: client}
}

// Allow checks if an action is allowed under the rate limit.
func (r *RateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error) {
	pipe := r.client.TxPipeline()
	countCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, 0, err
	}

	count := int(countCmd.Val())
	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}

	return count <= limit, remaining, nil
}
