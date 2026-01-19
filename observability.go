package goauth

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// ==================== HEALTH CHECK ====================

// HealthStatus represents the health of the service.
type HealthStatus struct {
	Status       string                   `json:"status"`
	Version      string                   `json:"version"`
	Uptime       string                   `json:"uptime"`
	Checks       map[string]ComponentHealth `json:"checks,omitempty"`
	Timestamp    time.Time                `json:"timestamp"`
}

// ComponentHealth represents the health of a component.
type ComponentHealth struct {
	Status  string `json:"status"`
	Latency string `json:"latency,omitempty"`
	Error   string `json:"error,omitempty"`
}

var startTime = time.Now()

// handleHealthCheck returns the health status of the service.
func (s *AuthService) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	detailed := r.URL.Query().Get("detailed") == "true"

	status := HealthStatus{
		Status:    "healthy",
		Version:   "2.0.0",
		Uptime:    time.Since(startTime).Round(time.Second).String(),
		Timestamp: time.Now(),
	}

	if detailed {
		status.Checks = make(map[string]ComponentHealth)

		// Check database
		dbHealth := s.checkDatabase(ctx)
		status.Checks["database"] = dbHealth
		if dbHealth.Status != "healthy" {
			status.Status = "degraded"
		}

		// Check Redis (if configured)
		if redisHealth := s.checkRedis(ctx); redisHealth.Status != "" {
			status.Checks["redis"] = redisHealth
			if redisHealth.Status != "healthy" && redisHealth.Status != "not_configured" {
				status.Status = "degraded"
			}
		}

		// Check external services
		if s.captcha != nil {
			status.Checks["captcha"] = ComponentHealth{Status: "configured"}
		}

		// Check OAuth providers
		oauthCount := len(s.oauth)
		if oauthCount > 0 {
			status.Checks["oauth"] = ComponentHealth{Status: "configured", Latency: strconv.Itoa(oauthCount) + " providers"}
		}
	}

	if status.Status == "healthy" {
		writeJSON(w, http.StatusOK, status)
	} else {
		writeJSON(w, http.StatusServiceUnavailable, status)
	}
}

func (s *AuthService) checkDatabase(ctx context.Context) ComponentHealth {
	start := time.Now()
	
	if checker, ok := s.store.(HealthChecker); ok {
		if err := checker.Ping(ctx); err != nil {
			return ComponentHealth{
				Status: "unhealthy",
				Error:  err.Error(),
			}
		}
	}

	return ComponentHealth{
		Status:  "healthy",
		Latency: time.Since(start).Round(time.Microsecond).String(),
	}
}

func (s *AuthService) checkRedis(ctx context.Context) ComponentHealth {
	if s.limiter == nil {
		return ComponentHealth{Status: "not_configured"}
	}

	// Try a rate limit check to verify Redis
	start := time.Now()
	_, _, err := s.limiter.Allow(ctx, "health:check", 1000, time.Second)
	if err != nil {
		return ComponentHealth{
			Status: "unhealthy",
			Error:  err.Error(),
		}
	}

	return ComponentHealth{
		Status:  "healthy",
		Latency: time.Since(start).Round(time.Microsecond).String(),
	}
}

// HealthChecker is implemented by stores that support health checks.
type HealthChecker interface {
	Ping(ctx context.Context) error
}

// ==================== METRICS ====================

// Metrics provides Prometheus-compatible metrics.
type Metrics struct {
	requestsTotal    atomic.Int64
	requestsSuccess  atomic.Int64
	requestsFailed   atomic.Int64
	loginSuccess     atomic.Int64
	loginFailed      atomic.Int64
	registerSuccess  atomic.Int64
	tokensIssued     atomic.Int64
	tokensRevoked    atomic.Int64
	rateLimitHits    atomic.Int64
	activeUsers      atomic.Int64
}

var globalMetrics = &Metrics{}

// IncrementLoginSuccess increments the login success counter.
func (m *Metrics) IncrementLoginSuccess() {
	m.loginSuccess.Add(1)
	m.requestsSuccess.Add(1)
}

// IncrementLoginFailed increments the login failed counter.
func (m *Metrics) IncrementLoginFailed() {
	m.loginFailed.Add(1)
	m.requestsFailed.Add(1)
}

// IncrementRegisterSuccess increments the register success counter.
func (m *Metrics) IncrementRegisterSuccess() {
	m.registerSuccess.Add(1)
	m.requestsSuccess.Add(1)
}

// IncrementRateLimitHit increments the rate limit hit counter.
func (m *Metrics) IncrementRateLimitHit() {
	m.rateLimitHits.Add(1)
}

// handleMetrics returns Prometheus-formatted metrics.
func (s *AuthService) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")

	metrics := []string{
		"# HELP goauth_requests_total Total number of requests",
		"# TYPE goauth_requests_total counter",
		formatMetric("goauth_requests_total", globalMetrics.requestsTotal.Load()),
		
		"# HELP goauth_login_success_total Successful login attempts",
		"# TYPE goauth_login_success_total counter",
		formatMetric("goauth_login_success_total", globalMetrics.loginSuccess.Load()),
		
		"# HELP goauth_login_failed_total Failed login attempts",
		"# TYPE goauth_login_failed_total counter",
		formatMetric("goauth_login_failed_total", globalMetrics.loginFailed.Load()),
		
		"# HELP goauth_register_success_total Successful registrations",
		"# TYPE goauth_register_success_total counter",
		formatMetric("goauth_register_success_total", globalMetrics.registerSuccess.Load()),
		
		"# HELP goauth_tokens_issued_total Tokens issued",
		"# TYPE goauth_tokens_issued_total counter",
		formatMetric("goauth_tokens_issued_total", globalMetrics.tokensIssued.Load()),
		
		"# HELP goauth_rate_limit_hits_total Rate limit hits",
		"# TYPE goauth_rate_limit_hits_total counter",
		formatMetric("goauth_rate_limit_hits_total", globalMetrics.rateLimitHits.Load()),
	}

	for _, m := range metrics {
		w.Write([]byte(m + "\n"))
	}
}

func formatMetric(name string, value int64) string {
	return name + " " + itoa(value)
}

func itoa(i int64) string {
	if i == 0 {
		return "0"
	}
	s := ""
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		s = string(rune('0'+i%10)) + s
		i /= 10
	}
	if neg {
		s = "-" + s
	}
	return s
}

// ==================== GRACEFUL SHUTDOWN ====================

// GracefulShutdown handles graceful shutdown of the auth service.
type GracefulShutdown struct {
	svc       *AuthService
	wg        sync.WaitGroup
	stopCh    chan struct{}
	stopped   atomic.Bool
	callbacks []func(context.Context)
}

// NewGracefulShutdown creates a new graceful shutdown handler.
func (s *AuthService) NewGracefulShutdown() *GracefulShutdown {
	return &GracefulShutdown{
		svc:    s,
		stopCh: make(chan struct{}),
	}
}

// OnShutdown registers a callback to be called during shutdown.
func (g *GracefulShutdown) OnShutdown(fn func(context.Context)) {
	g.callbacks = append(g.callbacks, fn)
}

// Shutdown gracefully shuts down the service.
func (g *GracefulShutdown) Shutdown(ctx context.Context) error {
	if g.stopped.Swap(true) {
		return nil // Already stopped
	}

	close(g.stopCh)

	// Wait for in-flight requests
	done := make(chan struct{})
	go func() {
		g.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		g.svc.logger.Warn("shutdown timeout, forcing close")
		return ctx.Err()
	}

	// Run shutdown callbacks
	for _, cb := range g.callbacks {
		cb(ctx)
	}

	// Stop background jobs
	if g.svc.jobs != nil {
		g.svc.jobs.Stop(ctx)
	}

	g.svc.logger.Info("shutdown complete")
	return nil
}

// ==================== REQUEST TRACKER ====================

// RequestTracker tracks in-flight requests for graceful shutdown.
type RequestTracker struct {
	gs *GracefulShutdown
}

// Track wraps an HTTP handler to track requests.
func (g *GracefulShutdown) Track() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if g.stopped.Load() {
				writeError(w, http.StatusServiceUnavailable, "SERVICE_SHUTTING_DOWN", "service is shutting down")
				return
			}
			g.wg.Add(1)
			defer g.wg.Done()
			globalMetrics.requestsTotal.Add(1)
			next.ServeHTTP(w, r)
		})
	}
}
