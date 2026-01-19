package goauth

import (
	"context"
	"sync"
	"time"
)

// RateLimitConfig defines per-endpoint rate limits.
type RateLimitConfig struct {
	LoginLimit          int
	LoginWindow         time.Duration
	TwoFALimit          int
	TwoFAWindow         time.Duration
	RegisterLimit       int
	RegisterWindow      time.Duration
	PasswordResetLimit  int
	PasswordResetWindow time.Duration
	MagicLinkLimit      int
	MagicLinkWindow     time.Duration
}

// IPBlockConfig defines IP block/penalty settings.
type IPBlockConfig struct {
	Enabled          bool
	FailureThreshold int
	FailureWindow    time.Duration
	BlockDuration    time.Duration
}

// IPBlocker blocks abusive IPs.
type IPBlocker interface {
	IsBlocked(ctx context.Context, ip string) (bool, time.Time, error)
	Block(ctx context.Context, ip string, duration time.Duration, reason string) error
	Unblock(ctx context.Context, ip string) error
}

type ipBlockEntry struct {
	until  time.Time
	reason string
}

type memoryIPBlocker struct {
	mu     sync.Mutex
	blocks map[string]ipBlockEntry
}

func newMemoryIPBlocker() *memoryIPBlocker {
	return &memoryIPBlocker{blocks: make(map[string]ipBlockEntry)}
}

func (b *memoryIPBlocker) IsBlocked(ctx context.Context, ip string) (bool, time.Time, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	entry, ok := b.blocks[ip]
	if !ok {
		return false, time.Time{}, nil
	}
	if time.Now().After(entry.until) {
		delete(b.blocks, ip)
		return false, time.Time{}, nil
	}
	return true, entry.until, nil
}

func (b *memoryIPBlocker) Block(ctx context.Context, ip string, duration time.Duration, reason string) error {
	if ip == "" || duration <= 0 {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.blocks[ip] = ipBlockEntry{until: time.Now().Add(duration), reason: reason}
	return nil
}

func (b *memoryIPBlocker) Unblock(ctx context.Context, ip string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.blocks, ip)
	return nil
}

// WithIPBlocker sets a custom IP blocker.
func WithIPBlocker(blocker IPBlocker) Option {
	return func(s *AuthService) error {
		s.ipBlocker = blocker
		return nil
	}
}

func (s *AuthService) allowRateLimit(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	if s.limiter == nil || limit <= 0 || window <= 0 {
		return true, nil
	}
	allowed, _, err := s.limiter.Allow(ctx, key, limit, window)
	return allowed, err
}

func (s *AuthService) isIPBlocked(ctx context.Context, ip string) bool {
	if !s.config.IPBlock.Enabled || s.ipBlocker == nil || ip == "" {
		return false
	}
	blocked, _, err := s.ipBlocker.IsBlocked(ctx, ip)
	if err != nil {
		return false
	}
	return blocked
}

func (s *AuthService) recordIPFailure(ctx context.Context, ip, kind string) {
	if !s.config.IPBlock.Enabled || s.ipBlocker == nil || ip == "" {
		return
	}
	threshold := s.config.IPBlock.FailureThreshold
	window := s.config.IPBlock.FailureWindow
	if threshold <= 0 || window <= 0 || s.limiter == nil {
		return
	}
	key := "ipfail:" + kind + ":" + s.hashIP(ip)
	allowed, err := s.allowRateLimit(ctx, key, threshold, window)
	if err != nil {
		return
	}
	if !allowed {
		_ = s.ipBlocker.Block(ctx, ip, s.config.IPBlock.BlockDuration, kind)
	}
}
