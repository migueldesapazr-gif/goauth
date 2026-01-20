// Package main provides a comprehensive test server for GoAuth authentication testing.
package main

import (
	"context"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"go.uber.org/zap"

	"github.com/migueldesapazr-gif/goauth"
	"github.com/migueldesapazr-gif/goauth/stores/postgres"
)

var (
	logger *zap.Logger
	auth   *goauth.AuthService
)

func main() {
	// Load .env
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found, using environment variables")
	}

	// Setup logger
	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		log.Fatal("Failed to create logger:", err)
	}
	defer logger.Sync()

	logger.Info("🚀 Starting GoAuth Test Server",
		zap.String("app_url", os.Getenv("TEST_APP_URL")),
		zap.String("app_name", os.Getenv("GOAUTH_APP_NAME")),
	)

	// Connect to database
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		logger.Fatal("DATABASE_URL is required")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		logger.Fatal("Failed to connect to database", zap.Error(err))
	}
	defer pool.Close()
	logger.Info("✓ Database connected")

	// Create auth service
	auth, err = createAuthService(pool)
	if err != nil {
		logger.Fatal("Failed to create auth service", zap.Error(err))
	}
	logger.Info("✓ Auth service initialized")

	// Setup router
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// Static pages
	r.Get("/", handleHome)
	r.Get("/login", handleLoginPage)
	r.Get("/register", handleRegisterPage)
	r.Get("/dashboard", handleDashboard)
	r.Get("/test", handleTestPage)

	// API endpoints for testing
	r.Get("/api/health", handleHealth)
	r.Get("/api/config", handleConfig)

	// Mount GoAuth endpoints
	r.Mount("/auth", auth.Handler())

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	logger.Info("🌐 Server starting",
		zap.String("port", port),
		zap.String("url", "http://localhost:"+port),
	)

	if err := http.ListenAndServe(":"+port, r); err != nil {
		logger.Fatal("Server failed", zap.Error(err))
	}
}

func createAuthService(pool *pgxpool.Pool) (*goauth.AuthService, error) {
	appURL := os.Getenv("TEST_APP_URL")
	if appURL == "" {
		appURL = "http://localhost:8080"
	}

	options := []goauth.Option{
		postgres.WithDatabase(pool),
		goauth.WithSecretsFromEnv(),
		goauth.WithAppName(os.Getenv("GOAUTH_APP_NAME")),
		goauth.WithAppURL(appURL),
		goauth.WithSecurityMode(goauth.SecurityModeBalanced),

		// Email/Password
		goauth.WithEmailPassword(true),
		goauth.WithEmailVerification(true),
		goauth.WithPasswordPolicy(8, true, 5),

		// Username
		goauth.WithUsername(true),
		goauth.WithUsernameRequired(false),

		// TOTP 2FA
		goauth.WithTOTP(true),
		goauth.WithTOTPDigits(6),
		goauth.WithBackupCodeLength(8),
		goauth.WithBackupCodeDigitsOnly(true),

		// Magic Links
		goauth.WithMagicLinks(),

		// Tokens
		goauth.WithTokenTTL(15*time.Minute, 7*24*time.Hour),
		goauth.WithRotateRefreshTokens(true),
	}

	// OAuth Providers (only configured ones)
	if id := os.Getenv("GOOGLE_CLIENT_ID"); id != "" {
		options = append(options, goauth.WithGoogle(id, os.Getenv("GOOGLE_CLIENT_SECRET")))
		logger.Info("✓ Google OAuth configured")
	}

	if id := os.Getenv("DISCORD_CLIENT_ID"); id != "" {
		options = append(options, goauth.WithDiscord(id, os.Getenv("DISCORD_CLIENT_SECRET")))
		logger.Info("✓ Discord OAuth configured")
	}

	if id := os.Getenv("GITHUB_CLIENT_ID"); id != "" {
		options = append(options, goauth.WithGitHub(id, os.Getenv("GITHUB_CLIENT_SECRET")))
		logger.Info("✓ GitHub OAuth configured")
	}

	// CAPTCHA (Turnstile)
	if secret := os.Getenv("TURNSTILE_SECRET_KEY"); secret != "" {
		options = append(options, goauth.WithTurnstile(secret))
		options = append(options, goauth.WithCaptchaRequired(true))
		logger.Info("✓ Cloudflare Turnstile configured")
	}

	// Email (Resend)
	if apiKey := os.Getenv("RESEND_API_KEY"); apiKey != "" {
		options = append(options, goauth.WithResend(
			apiKey,
			os.Getenv("EMAIL_FROM"),
			os.Getenv("EMAIL_FROM_NAME"),
		))
		logger.Info("✓ Resend email configured",
			zap.String("from", os.Getenv("EMAIL_FROM")),
		)
	}

	return goauth.New(options...)
}

// Handlers

func handleHome(w http.ResponseWriter, r *http.Request) {
	logger.Info("📄 Home page accessed", zap.String("ip", r.RemoteAddr))
	tmpl := template.Must(template.New("home").Parse(homeHTML))
	tmpl.Execute(w, map[string]interface{}{
		"AppName":        os.Getenv("GOAUTH_APP_NAME"),
		"AppURL":         os.Getenv("TEST_APP_URL"),
		"TurnstileSite":  os.Getenv("TURNSTILE_SITE_KEY"),
		"RecaptchaSite":  os.Getenv("RECAPTCHA_SITE_KEY"),
		"HcaptchaSite":   os.Getenv("HCAPTCHA_SITE_KEY"),
		"HasGoogle":      os.Getenv("GOOGLE_CLIENT_ID") != "",
		"HasDiscord":     os.Getenv("DISCORD_CLIENT_ID") != "",
		"HasGitHub":      os.Getenv("GITHUB_CLIENT_ID") != "",
	})
}

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	logger.Info("📄 Login page accessed", zap.String("ip", r.RemoteAddr))
	tmpl := template.Must(template.New("login").Parse(loginHTML))
	tmpl.Execute(w, map[string]interface{}{
		"AppName":       os.Getenv("GOAUTH_APP_NAME"),
		"TurnstileSite": os.Getenv("TURNSTILE_SITE_KEY"),
		"HasGoogle":     os.Getenv("GOOGLE_CLIENT_ID") != "",
		"HasDiscord":    os.Getenv("DISCORD_CLIENT_ID") != "",
		"HasGitHub":     os.Getenv("GITHUB_CLIENT_ID") != "",
	})
}

func handleRegisterPage(w http.ResponseWriter, r *http.Request) {
	logger.Info("📄 Register page accessed", zap.String("ip", r.RemoteAddr))
	tmpl := template.Must(template.New("register").Parse(registerHTML))
	tmpl.Execute(w, map[string]interface{}{
		"AppName":       os.Getenv("GOAUTH_APP_NAME"),
		"TurnstileSite": os.Getenv("TURNSTILE_SITE_KEY"),
	})
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	logger.Info("📄 Dashboard accessed", zap.String("ip", r.RemoteAddr))
	tmpl := template.Must(template.New("dashboard").Parse(dashboardHTML))
	tmpl.Execute(w, map[string]interface{}{
		"AppName": os.Getenv("GOAUTH_APP_NAME"),
	})
}

func handleTestPage(w http.ResponseWriter, r *http.Request) {
	logger.Info("📄 Test page accessed", zap.String("ip", r.RemoteAddr))
	tmpl := template.Must(template.New("test").Parse(testPageHTML))
	tmpl.Execute(w, map[string]interface{}{
		"AppName":       os.Getenv("GOAUTH_APP_NAME"),
		"TurnstileSite": os.Getenv("TURNSTILE_SITE_KEY"),
		"RecaptchaSite": os.Getenv("RECAPTCHA_SITE_KEY"),
		"HcaptchaSite":  os.Getenv("HCAPTCHA_SITE_KEY"),
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

func handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"app_name":     os.Getenv("GOAUTH_APP_NAME"),
		"app_url":      os.Getenv("TEST_APP_URL"),
		"has_google":   os.Getenv("GOOGLE_CLIENT_ID") != "",
		"has_discord":  os.Getenv("DISCORD_CLIENT_ID") != "",
		"has_github":   os.Getenv("GITHUB_CLIENT_ID") != "",
		"has_turnstile": os.Getenv("TURNSTILE_SECRET_KEY") != "",
		"has_resend":   os.Getenv("RESEND_API_KEY") != "",
	})
}
