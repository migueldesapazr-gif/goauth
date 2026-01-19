package goauth

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ==================== BACKGROUND JOBS ====================

// BackgroundJobs manages all background tasks for the auth service.
type BackgroundJobs struct {
	svc      *AuthService
	emailCh  chan emailJob
	stopCh   chan struct{}
	wg       sync.WaitGroup
	running  bool
	mu       sync.Mutex
}

type emailJob struct {
	jobType string // "verification", "password_reset", "welcome", "security_alert"
	to      string
	data    map[string]string
}

// StartBackgroundJobs starts all background workers.
// Call this after creating the AuthService.
func (s *AuthService) StartBackgroundJobs(opts ...JobOption) *BackgroundJobs {
	cfg := &jobConfig{
		emailWorkers:    3,
		emailQueueSize:  1000,
		cleanupInterval: 1 * time.Hour,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	jobs := &BackgroundJobs{
		svc:     s,
		emailCh: make(chan emailJob, cfg.emailQueueSize),
		stopCh:  make(chan struct{}),
		running: true,
	}

	// Start email workers
	for i := 0; i < cfg.emailWorkers; i++ {
		jobs.wg.Add(1)
		go jobs.emailWorker(i)
	}

	// Start cleanup worker
	jobs.wg.Add(1)
	go jobs.cleanupWorker(cfg.cleanupInterval)

	// Start token refresh worker (for token blacklist cleanup)
	jobs.wg.Add(1)
	go jobs.tokenCleanupWorker()

	s.logger.Info("background jobs started",
		zap.Int("email_workers", cfg.emailWorkers),
		zap.Duration("cleanup_interval", cfg.cleanupInterval))

	return jobs
}

// Stop gracefully stops all background workers.
func (j *BackgroundJobs) Stop(ctx context.Context) error {
	j.mu.Lock()
	if !j.running {
		j.mu.Unlock()
		return nil
	}
	j.running = false
	j.mu.Unlock()

	close(j.stopCh)

	done := make(chan struct{})
	go func() {
		j.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// QueueEmail queues an email for async sending.
func (j *BackgroundJobs) QueueEmail(jobType, to string, data map[string]string) bool {
	j.mu.Lock()
	if !j.running {
		j.mu.Unlock()
		return false
	}
	j.mu.Unlock()

	select {
	case j.emailCh <- emailJob{jobType: jobType, to: to, data: data}:
		return true
	default:
		// Queue full
		j.svc.logger.Warn("email queue full, dropping email",
			zap.String("type", jobType), zap.String("to", to))
		return false
	}
}

func (j *BackgroundJobs) emailWorker(id int) {
	defer j.wg.Done()

	for {
		select {
		case <-j.stopCh:
			// Drain remaining emails before stopping
			for {
				select {
				case job := <-j.emailCh:
					j.processEmail(job)
				default:
					return
				}
			}
		case job := <-j.emailCh:
			j.processEmail(job)
		}
	}
}

func (j *BackgroundJobs) processEmail(job emailJob) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var err error
	switch job.jobType {
	case "verification":
		err = j.svc.mailer.SendVerification(ctx, job.to, job.data["code"], job.data["link"])
	case "password_reset":
		err = j.svc.mailer.SendPasswordReset(ctx, job.to, job.data["link"])
	case "welcome":
		if wm, ok := j.svc.mailer.(WelcomeMailer); ok {
			err = wm.SendWelcome(ctx, job.to, job.data["name"])
		}
	case "security_alert":
		if sam, ok := j.svc.mailer.(SecurityAlertMailer); ok {
			err = sam.SendSecurityAlert(ctx, job.to, job.data["event"], job.data["details"])
		}
	}

	if err != nil {
		j.svc.logger.Error("email send failed",
			zap.String("type", job.jobType),
			zap.String("to", job.to),
			zap.Error(err))
	}
}

func (j *BackgroundJobs) cleanupWorker(interval time.Duration) {
	defer j.wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run immediately on start
	j.runCleanup()

	for {
		select {
		case <-j.stopCh:
			return
		case <-ticker.C:
			j.runCleanup()
		}
	}
}

func (j *BackgroundJobs) runCleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Cleanup expired tokens
	if cleaner, ok := j.svc.store.(StoreCleaner); ok {
		deleted, err := cleaner.CleanupExpiredTokens(ctx)
		if err != nil {
			j.svc.logger.Error("token cleanup failed", zap.Error(err))
		} else if deleted > 0 {
			j.svc.logger.Info("cleaned up expired tokens", zap.Int64("deleted", deleted))
		}

		// Cleanup old audit logs based on retention
		deleted, err = cleaner.CleanupOldAuditLogs(ctx, j.svc.config.AuditLogRetention)
		if err != nil {
			j.svc.logger.Error("audit log cleanup failed", zap.Error(err))
		} else if deleted > 0 {
			j.svc.logger.Info("cleaned up old audit logs", zap.Int64("deleted", deleted))
		}

		// Cleanup unverified accounts past deadline
		deleted, err = cleaner.CleanupUnverifiedAccounts(ctx)
		if err != nil {
			j.svc.logger.Error("unverified account cleanup failed", zap.Error(err))
		} else if deleted > 0 {
			j.svc.logger.Info("cleaned up unverified accounts", zap.Int64("deleted", deleted))
		}
	}
}

func (j *BackgroundJobs) tokenCleanupWorker() {
	defer j.wg.Done()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-j.stopCh:
			return
		case <-ticker.C:
			if j.svc.tokenBlacklist != nil {
				j.svc.tokenBlacklist.Cleanup()
			}
		}
	}
}

// ==================== JOB OPTIONS ====================

type jobConfig struct {
	emailWorkers    int
	emailQueueSize  int
	cleanupInterval time.Duration
}

// JobOption configures background jobs.
type JobOption func(*jobConfig)

// WithEmailWorkers sets the number of email worker goroutines.
func WithEmailWorkers(n int) JobOption {
	return func(c *jobConfig) {
		if n > 0 {
			c.emailWorkers = n
		}
	}
}

// WithEmailQueueSize sets the email queue buffer size.
func WithEmailQueueSize(n int) JobOption {
	return func(c *jobConfig) {
		if n > 0 {
			c.emailQueueSize = n
		}
	}
}

// WithCleanupInterval sets how often cleanup runs.
func WithCleanupInterval(d time.Duration) JobOption {
	return func(c *jobConfig) {
		if d > 0 {
			c.cleanupInterval = d
		}
	}
}

// ==================== STORE CLEANER INTERFACE ====================

// StoreCleaner is an optional interface for stores that support cleanup.
type StoreCleaner interface {
	// CleanupExpiredTokens removes all expired tokens.
	CleanupExpiredTokens(ctx context.Context) (int64, error)
	// CleanupOldAuditLogs removes audit logs older than retention period.
	CleanupOldAuditLogs(ctx context.Context, retention time.Duration) (int64, error)
	// CleanupUnverifiedAccounts removes unverified accounts past deadline.
	CleanupUnverifiedAccounts(ctx context.Context) (int64, error)
}

// ==================== EXTENDED MAILER INTERFACES ====================

// WelcomeMailer sends welcome emails.
type WelcomeMailer interface {
	SendWelcome(ctx context.Context, to, name string) error
}

// SecurityAlertMailer sends security alert emails.
type SecurityAlertMailer interface {
	SendSecurityAlert(ctx context.Context, to, event, details string) error
}

// PasswordChangeMailer sends password change notifications.
type PasswordChangeMailer interface {
	SendPasswordChanged(ctx context.Context, to string) error
}

// EmailChangeMailer sends email change confirmation links.
type EmailChangeMailer interface {
	SendEmailChange(ctx context.Context, to, link string) error
}

// EmailChangedMailer sends notifications when email changes are completed.
type EmailChangedMailer interface {
	SendEmailChanged(ctx context.Context, to, newEmail string) error
}
