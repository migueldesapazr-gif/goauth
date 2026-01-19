package goauth

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ==================== CIRCUIT BREAKER ====================

// CircuitState represents the state of the circuit breaker.
type CircuitState int

const (
	CircuitClosed CircuitState = iota
	CircuitOpen
	CircuitHalfOpen
)

// CircuitBreaker implements the circuit breaker pattern for external services.
type CircuitBreaker struct {
	name          string
	maxFailures   int
	resetTimeout  time.Duration
	halfOpenLimit int

	state        atomic.Int32
	failures     atomic.Int32
	lastFailure  atomic.Int64
	halfOpenReqs atomic.Int32
	mu           sync.Mutex
}

// NewCircuitBreaker creates a new circuit breaker.
func NewCircuitBreaker(name string, maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	cb := &CircuitBreaker{
		name:          name,
		maxFailures:   maxFailures,
		resetTimeout:  resetTimeout,
		halfOpenLimit: 1,
	}
	cb.state.Store(int32(CircuitClosed))
	return cb
}

// Allow checks if a request should be allowed.
func (cb *CircuitBreaker) Allow() bool {
	state := CircuitState(cb.state.Load())

	switch state {
	case CircuitClosed:
		return true

	case CircuitOpen:
		// Check if reset timeout has passed
		lastFail := time.Unix(0, cb.lastFailure.Load())
		if time.Since(lastFail) >= cb.resetTimeout {
			// Transition to half-open
			if cb.state.CompareAndSwap(int32(CircuitOpen), int32(CircuitHalfOpen)) {
				cb.halfOpenReqs.Store(0)
			}
			return cb.halfOpenReqs.Add(1) <= int32(cb.halfOpenLimit)
		}
		return false

	case CircuitHalfOpen:
		return cb.halfOpenReqs.Add(1) <= int32(cb.halfOpenLimit)
	}

	return false
}

// Success records a successful request.
func (cb *CircuitBreaker) Success() {
	state := CircuitState(cb.state.Load())

	switch state {
	case CircuitClosed:
		cb.failures.Store(0)

	case CircuitHalfOpen:
		// Successful request in half-open state closes the circuit
		cb.state.Store(int32(CircuitClosed))
		cb.failures.Store(0)
	}
}

// Failure records a failed request.
func (cb *CircuitBreaker) Failure() {
	cb.lastFailure.Store(time.Now().UnixNano())
	state := CircuitState(cb.state.Load())

	switch state {
	case CircuitClosed:
		failures := cb.failures.Add(1)
		if int(failures) >= cb.maxFailures {
			cb.state.Store(int32(CircuitOpen))
		}

	case CircuitHalfOpen:
		// Failure in half-open state opens the circuit again
		cb.state.Store(int32(CircuitOpen))
	}
}

// State returns the current state of the circuit breaker.
func (cb *CircuitBreaker) State() CircuitState {
	return CircuitState(cb.state.Load())
}

// ==================== SLIDING WINDOW RATE LIMITER ====================

// SlidingWindowRateLimiter implements a precise sliding window rate limiter.
type SlidingWindowRateLimiter struct {
	windows sync.Map // key -> *slidingWindow
	limit   int
	window  time.Duration
}

type slidingWindow struct {
	mu         sync.Mutex
	timestamps []int64
	limit      int
	window     time.Duration
}

// NewSlidingWindowRateLimiter creates a new sliding window rate limiter.
func NewSlidingWindowRateLimiter(limit int, window time.Duration) *SlidingWindowRateLimiter {
	rl := &SlidingWindowRateLimiter{
		limit:  limit,
		window: window,
	}
	// Start cleanup goroutine
	go rl.cleanup()
	return rl
}

// Allow checks if a request is allowed and records it.
func (r *SlidingWindowRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error) {
	now := time.Now().UnixNano()
	windowStart := now - window.Nanoseconds()

	val, _ := r.windows.LoadOrStore(key, &slidingWindow{
		timestamps: make([]int64, 0, limit),
		limit:      limit,
		window:     window,
	})
	sw := val.(*slidingWindow)

	sw.mu.Lock()
	defer sw.mu.Unlock()

	// Remove expired timestamps
	valid := sw.timestamps[:0]
	for _, ts := range sw.timestamps {
		if ts > windowStart {
			valid = append(valid, ts)
		}
	}
	sw.timestamps = valid

	// Check limit
	if len(sw.timestamps) >= limit {
		remaining := 0
		return false, remaining, nil
	}

	// Add current request
	sw.timestamps = append(sw.timestamps, now)
	remaining := limit - len(sw.timestamps)
	return true, remaining, nil
}

func (r *SlidingWindowRateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		now := time.Now().UnixNano()
		r.windows.Range(func(key, val any) bool {
			sw := val.(*slidingWindow)
			sw.mu.Lock()
			windowStart := now - sw.window.Nanoseconds()
			valid := sw.timestamps[:0]
			for _, ts := range sw.timestamps {
				if ts > windowStart {
					valid = append(valid, ts)
				}
			}
			sw.timestamps = valid
			if len(sw.timestamps) == 0 {
				r.windows.Delete(key)
			}
			sw.mu.Unlock()
			return true
		})
	}
}

// ==================== REQUEST DEDUPLICATION ====================

// RequestDeduplicator prevents duplicate requests within a time window.
type RequestDeduplicator struct {
	requests sync.Map // hash -> *pendingRequest
	ttl      time.Duration
}

type pendingRequest struct {
	result chan any
	err    chan error
	done   chan struct{}
}

// NewRequestDeduplicator creates a new request deduplicator.
func NewRequestDeduplicator(ttl time.Duration) *RequestDeduplicator {
	rd := &RequestDeduplicator{ttl: ttl}
	go rd.cleanup()
	return rd
}

// Do executes a function only if no identical request is pending.
// Identical requests share the result.
func (d *RequestDeduplicator) Do(key string, fn func() (any, error)) (any, error, bool) {
	pending := &pendingRequest{
		result: make(chan any, 1),
		err:    make(chan error, 1),
		done:   make(chan struct{}),
	}

	actual, loaded := d.requests.LoadOrStore(key, pending)
	if loaded {
		// Wait for existing request
		existing := actual.(*pendingRequest)
		select {
		case res := <-existing.result:
			return res, nil, true // shared result
		case err := <-existing.err:
			return nil, err, true
		case <-existing.done:
			return nil, nil, true
		}
	}

	// Execute function
	result, err := fn()
	if err != nil {
		pending.err <- err
	} else {
		pending.result <- result
	}
	close(pending.done)

	// Schedule cleanup
	go func() {
		time.Sleep(d.ttl)
		d.requests.Delete(key)
	}()

	return result, err, false
}

func (d *RequestDeduplicator) cleanup() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		d.requests.Range(func(key, val any) bool {
			pending := val.(*pendingRequest)
			select {
			case <-pending.done:
				d.requests.Delete(key)
			default:
			}
			return true
		})
	}
}

// ==================== CONNECTION POOL ====================

// HTTPClientPool provides a pool of HTTP clients for external services.
type HTTPClientPool struct {
	clients    sync.Map // service -> *http.Client
	transport  *http.Transport
}

// NewHTTPClientPool creates a new HTTP client pool.
func NewHTTPClientPool() *HTTPClientPool {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		MaxConnsPerHost:     100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		ForceAttemptHTTP2:   true,
	}

	return &HTTPClientPool{
		transport: transport,
	}
}

// GetClient returns an HTTP client for a service.
func (p *HTTPClientPool) GetClient(service string, timeout time.Duration) *http.Client {
	if val, ok := p.clients.Load(service); ok {
		return val.(*http.Client)
	}

	client := &http.Client{
		Transport: p.transport,
		Timeout:   timeout,
	}

	actual, _ := p.clients.LoadOrStore(service, client)
	return actual.(*http.Client)
}
