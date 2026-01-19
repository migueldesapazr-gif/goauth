// Package memory provides an in-memory rate limiter for development.
package memory

import (
	"context"
	"sync"
	"time"
)

// RateLimiter implements goauth.RateLimiter using in-memory storage.
// Note: This is for development/testing only. Use Redis in production.
type RateLimiter struct {
	mu      sync.Mutex
	entries map[string]*entry
}

type entry struct {
	count   int
	expires time.Time
}

// New creates a new in-memory rate limiter.
func New() *RateLimiter {
	r := &RateLimiter{
		entries: make(map[string]*entry),
	}
	go r.cleanup()
	return r
}

// Allow checks if an action is allowed under the rate limit.
func (r *RateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	e, exists := r.entries[key]

	if !exists || now.After(e.expires) {
		r.entries[key] = &entry{
			count:   1,
			expires: now.Add(window),
		}
		return true, limit - 1, nil
	}

	e.count++
	remaining := limit - e.count
	if remaining < 0 {
		remaining = 0
	}

	return e.count <= limit, remaining, nil
}

func (r *RateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		r.mu.Lock()
		now := time.Now()
		for key, e := range r.entries {
			if now.After(e.expires) {
				delete(r.entries, key)
			}
		}
		r.mu.Unlock()
	}
}
