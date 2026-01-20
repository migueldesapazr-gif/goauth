package goauth

import (
	"github.com/redis/go-redis/v9"

	"github.com/migueldesapazr-gif/goauth/mailers/mailgun"
	"github.com/migueldesapazr-gif/goauth/mailers/resend"
	"github.com/migueldesapazr-gif/goauth/mailers/sendgrid"
	"github.com/migueldesapazr-gif/goauth/mailers/smtp"
	"github.com/migueldesapazr-gif/goauth/ratelimit/memory"
	redisrl "github.com/migueldesapazr-gif/goauth/ratelimit/redis"
)

// Store adapter functions have been moved to their respective packages.
// Import the store package directly and use its helper functions:
//
//   import "github.com/migueldesapazr-gif/goauth/stores/postgres"
//   goauth.New(postgres.WithDatabase(pool), ...)
//
// Or use WithStore with the generic interface:
//
//   store := postgres.New(usersPool, auditPool)
//   goauth.New(goauth.WithStore(store), ...)

// WithPostgresStore is deprecated. Use stores/postgres.WithDatabase instead.
func WithPostgresStore(usersPool, auditPool interface{}) Option {
	return func(s *AuthService) error {
		return ErrStoreRequired
	}
}

// WithMySQLStore is deprecated. Use stores/mysql.WithDatabase instead.
func WithMySQLStore(usersDB, auditDB interface{}) Option {
	return func(s *AuthService) error {
		return ErrStoreRequired
	}
}

// WithSQLiteStore is deprecated. Use stores/sqlite.WithDatabase instead.
func WithSQLiteStore(usersDB, auditDB interface{}) Option {
	return func(s *AuthService) error {
		return ErrStoreRequired
	}
}

// WithMongoStore is deprecated. Use stores/mongodb.WithDatabase instead.
func WithMongoStore(client interface{}, dbName string) Option {
	return func(s *AuthService) error {
		return ErrStoreRequired
	}
}

// WithResendEmail configures the Resend email provider.
func WithResendEmail(apiKey, fromEmail, fromName string) Option {
	return func(s *AuthService) error {
		s.mailer = resend.New(apiKey, fromEmail, fromName)
		return nil
	}
}

// WithSMTPEmail configures SMTP email provider.
func WithSMTPEmail(cfg smtp.Config) Option {
	return func(s *AuthService) error {
		s.mailer = smtp.New(cfg)
		return nil
	}
}

// WithSendGridEmail configures SendGrid email provider.
func WithSendGridEmail(apiKey, fromEmail, fromName string) Option {
	return func(s *AuthService) error {
		s.mailer = sendgrid.New(apiKey, fromEmail, fromName)
		return nil
	}
}

// WithMailgunEmail configures Mailgun email provider.
func WithMailgunEmail(apiKey, domain, fromEmail, fromName string) Option {
	return func(s *AuthService) error {
		s.mailer = mailgun.New(apiKey, domain, fromEmail, fromName)
		return nil
	}
}

// WithRedisRateLimiter configures Redis-based rate limiting.
func WithRedisRateLimiter(client *redis.Client) Option {
	return func(s *AuthService) error {
		s.limiter = redisrl.New(client)
		return nil
	}
}

// WithMemoryRateLimiter configures in-memory rate limiting.
// Note: Only suitable for single-instance deployments or development.
func WithMemoryRateLimiter() Option {
	return func(s *AuthService) error {
		s.limiter = memory.New()
		return nil
	}
}

