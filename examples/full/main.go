// Example: Full Setup with OAuth, Email, CAPTCHA
//
// Complete configuration example with all features enabled.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/migueldesapazr-gif/goauth"
	"github.com/migueldesapazr-gif/goauth/stores/postgres"
)

func main() {
	// Setup logger
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// Connect to database
	db, err := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Connect to Redis (optional, for rate limiting)
	redis := redis.NewClient(&redis.Options{
		Addr: os.Getenv("REDIS_URL"),
	})

	// Create auth service with full configuration
	auth, err := goauth.New(
		// === REQUIRED ===
		postgres.WithDatabase(db),
		goauth.WithSecretsFromEnv(),

		// === APP INFO ===
		goauth.WithAppName("My Awesome App"),
		goauth.WithAppURL("https://myapp.com"),
		goauth.WithLogger(logger),

		// === OAUTH PROVIDERS ===
		goauth.WithGoogle(os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET")),
		goauth.WithDiscord(os.Getenv("DISCORD_CLIENT_ID"), os.Getenv("DISCORD_CLIENT_SECRET")),
		goauth.WithGitHub(os.Getenv("GITHUB_CLIENT_ID"), os.Getenv("GITHUB_CLIENT_SECRET")),

		// === EMAIL ===
		goauth.WithResend(
			os.Getenv("RESEND_API_KEY"),
			"noreply@myapp.com",
			"My App",
		),

		// === CAPTCHA ===
		goauth.WithTurnstile(os.Getenv("TURNSTILE_SECRET")),

		// === RATE LIMITING ===
		goauth.WithRedis(redis),

		// === SECURITY ===
		goauth.WithPasswordPolicy(10, true, 5),       // min 10 chars, complexity, 5 history
		goauth.WithLockout(5, 30*time.Minute),        // lock after 5 fails for 30 min
		goauth.WithEmailVerification(true),           // require email verification
		goauth.WithEmailDomainCheck(true),            // validate MX records
		goauth.WithHIBP(),                            // check breached passwords
		goauth.WithUsername(true),                    // allow usernames
		goauth.WithUsernamePolicy(3, 32),
		goauth.WithRequireVerifiedEmailForAuth(true),
		goauth.WithNotifyOnPasswordChange(true),
		goauth.WithNotifyOnEmailChange(true),
		goauth.WithEmailChangeTTL(30*time.Minute),

		// === RATE LIMITS + IP BLOCK ===
		goauth.WithRateLimits(goauth.RateLimitConfig{
			LoginLimit:          10,
			LoginWindow:         time.Minute,
			TwoFALimit:          5,
			TwoFAWindow:         time.Minute,
			RegisterLimit:       5,
			RegisterWindow:      time.Hour,
			PasswordResetLimit:  3,
			PasswordResetWindow: time.Hour,
			MagicLinkLimit:      3,
			MagicLinkWindow:     time.Hour,
		}),
		goauth.WithIPBlock(goauth.IPBlockConfig{
			Enabled:          true,
			FailureThreshold: 10,
			FailureWindow:    15 * time.Minute,
			BlockDuration:    30 * time.Minute,
		}),

		// === PRIVACY ===
		goauth.WithIPPrivacy(goauth.IPPrivacyConfig{
			StoreIP:         true,
			EncryptIP:       true,
			HashIPInLogs:    true,
			IPRetentionDays: 90,
		}),
		goauth.WithAuditRetention(365 * 24 * time.Hour),

		// === TOKENS ===
		goauth.WithTokenTTL(15*time.Minute, 7*24*time.Hour),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Setup router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(securityHeaders)
	r.Use(cors("https://myapp.com"))

	// Mount auth endpoints
	r.Mount("/auth", auth.Handler())

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(auth.RequireAuth())

		r.Get("/api/profile", func(w http.ResponseWriter, r *http.Request) {
			user, _ := goauth.GetUserFromContext(r.Context())
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"user_id":"` + user.ID + `"}`))
		})

		r.Get("/api/settings", func(w http.ResponseWriter, r *http.Request) {
			// Protected route
			w.Write([]byte(`{"settings": {}}`))
		})
	})

	// Public routes
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Welcome to My App!"))
	})

	// Start server
	log.Println("Server starting on :8080")
	http.ListenAndServe(":8080", r)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}

func cors(origin string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

