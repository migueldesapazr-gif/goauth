package goauth

import (
	"context"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// ==================== TOKEN BLACKLIST ====================

// TokenBlacklist allows immediate revocation of JWT tokens.
type TokenBlacklist interface {
	// Add adds a token to the blacklist until its expiry.
	Add(ctx context.Context, jti string, expiresAt time.Time) error
	// IsBlacklisted checks if a token is blacklisted.
	IsBlacklisted(ctx context.Context, jti string) (bool, error)
	// Cleanup removes expired entries (for in-memory implementation).
	Cleanup()
}

// ==================== REDIS BLACKLIST ====================

// RedisBlacklist uses Redis for distributed token blacklisting.
type RedisBlacklist struct {
	client *redis.Client
	prefix string
}

// NewRedisBlacklist creates a Redis-backed token blacklist.
func NewRedisBlacklist(client *redis.Client) *RedisBlacklist {
	return &RedisBlacklist{
		client: client,
		prefix: "goauth:blacklist:",
	}
}

func (b *RedisBlacklist) Add(ctx context.Context, jti string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return nil // Already expired
	}
	return b.client.Set(ctx, b.prefix+jti, "1", ttl).Err()
}

func (b *RedisBlacklist) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	exists, err := b.client.Exists(ctx, b.prefix+jti).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

func (b *RedisBlacklist) Cleanup() {
	// Redis handles TTL automatically
}

// ==================== MEMORY BLACKLIST ====================

// MemoryBlacklist uses in-memory storage for single-instance deployments.
type MemoryBlacklist struct {
	entries map[string]time.Time
	mu      sync.RWMutex
}

// NewMemoryBlacklist creates an in-memory token blacklist.
func NewMemoryBlacklist() *MemoryBlacklist {
	return &MemoryBlacklist{
		entries: make(map[string]time.Time),
	}
}

func (b *MemoryBlacklist) Add(ctx context.Context, jti string, expiresAt time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries[jti] = expiresAt
	return nil
}

func (b *MemoryBlacklist) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	expiry, exists := b.entries[jti]
	if !exists {
		return false, nil
	}
	if time.Now().After(expiry) {
		return false, nil // Expired
	}
	return true, nil
}

func (b *MemoryBlacklist) Cleanup() {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	for jti, expiry := range b.entries {
		if now.After(expiry) {
			delete(b.entries, jti)
		}
	}
}

// ==================== OPTIONS ====================

// WithTokenBlacklist enables immediate token revocation.
func WithTokenBlacklist(bl TokenBlacklist) Option {
	return func(s *AuthService) error {
		s.tokenBlacklist = bl
		return nil
	}
}

// WithRedisBlacklist enables Redis-backed token blacklisting.
func WithRedisBlacklist(client *redis.Client) Option {
	return func(s *AuthService) error {
		s.tokenBlacklist = NewRedisBlacklist(client)
		return nil
	}
}

// WithMemoryBlacklist enables in-memory token blacklisting.
func WithMemoryBlacklist() Option {
	return func(s *AuthService) error {
		s.tokenBlacklist = NewMemoryBlacklist()
		return nil
	}
}
