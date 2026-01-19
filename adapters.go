package goauth

import (
	"database/sql"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/mongo"

	"github.com/migueldesapazr-gif/goauth/mailers/mailgun"
	"github.com/migueldesapazr-gif/goauth/mailers/resend"
	"github.com/migueldesapazr-gif/goauth/mailers/sendgrid"
	"github.com/migueldesapazr-gif/goauth/mailers/smtp"
	"github.com/migueldesapazr-gif/goauth/ratelimit/memory"
	redisrl "github.com/migueldesapazr-gif/goauth/ratelimit/redis"
	"github.com/migueldesapazr-gif/goauth/stores/mongodb"
	"github.com/migueldesapazr-gif/goauth/stores/mysql"
	"github.com/migueldesapazr-gif/goauth/stores/postgres"
	"github.com/migueldesapazr-gif/goauth/stores/sqlite"
)

// WithPostgresStore configures PostgreSQL storage.
// usersPool is used for user data, auditPool is used for audit logs.
// They can be the same pool if using a single database.
func WithPostgresStore(usersPool, auditPool *pgxpool.Pool) Option {
	return func(s *AuthService) error {
		store := postgres.New(usersPool, auditPool)
		s.store = store
		setOptionalStores(s, store)
		return nil
	}
}

// WithMySQLStore configures MySQL storage.
func WithMySQLStore(usersDB, auditDB *sql.DB) Option {
	return func(s *AuthService) error {
		store := mysql.NewWithAudit(usersDB, auditDB)
		s.store = store
		setOptionalStores(s, store)
		return nil
	}
}

// WithSQLiteStore configures SQLite storage.
func WithSQLiteStore(usersDB, auditDB *sql.DB) Option {
	return func(s *AuthService) error {
		store := sqlite.NewWithAudit(usersDB, auditDB)
		s.store = store
		setOptionalStores(s, store)
		return nil
	}
}

// WithMongoStore configures MongoDB storage.
func WithMongoStore(client *mongo.Client, dbName string) Option {
	return func(s *AuthService) error {
		store := mongodb.New(client, dbName)
		s.store = store
		setOptionalStores(s, store)
		return nil
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

