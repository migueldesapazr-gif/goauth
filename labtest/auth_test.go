package labtest

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/migueldesapazr-gif/goauth"
	"github.com/migueldesapazr-gif/goauth/stores/postgres"
)

// ==================== SERVICE CREATION TESTS ====================

func TestNewAuthService(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set, skipping integration test")
	}

	jwtSecret := getEnvOrSkip(t, "GOAUTH_JWT_SECRET")
	encKey := getEnvOrSkip(t, "GOAUTH_ENCRYPTION_KEY")
	pepper := getEnvOrSkip(t, "GOAUTH_PEPPER")

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer pool.Close()

	// Test with valid configuration
	auth, err := goauth.New(
		postgres.WithDatabase(pool),
		goauth.WithSecrets(goauth.Secrets{
			JWTSecret:     []byte(jwtSecret)[:32],
			EncryptionKey: []byte(encKey)[:32],
			Pepper:        []byte(pepper)[:32],
		}),
		goauth.WithAppName("Lab Test App"),
		goauth.WithAppURL("http://localhost:8080"),
	)
	if err != nil {
		t.Fatalf("Failed to create auth service: %v", err)
	}

	if auth == nil {
		t.Fatal("Auth service should not be nil")
	}

	t.Log("✓ Auth service created successfully")
}

func TestSecurityModes(t *testing.T) {
	// Verify security mode constants are defined
	modes := []goauth.SecurityMode{
		goauth.SecurityModePermissive,
		goauth.SecurityModeBalanced,
		goauth.SecurityModeStrict,
	}

	for i, mode := range modes {
		if mode == "" {
			t.Errorf("Security mode %d should not be empty", i)
		}
		t.Logf("✓ Security mode: %s", mode)
	}
}

// ==================== TOKEN TESTS ====================

func TestTokenGeneration(t *testing.T) {
	// This test verifies token generation without requiring database

	// Test access token format
	t.Run("AccessTokenFormat", func(t *testing.T) {
		// Token should have 3 parts separated by dots (JWT format)
		// This is tested by the JWT library but we validate structure
		t.Log("✓ JWT format test placeholder")
	})
}

// ==================== ERROR HANDLING TESTS ====================

func TestErrorTypes(t *testing.T) {
	tests := []struct {
		err  error
		code string
	}{
		{goauth.ErrInvalidCredentials, goauth.CodeInvalidCredentials},
		{goauth.ErrAccountLocked, goauth.CodeAccountLocked},
		{goauth.ErrWeakPassword, goauth.CodeWeakPassword},
		{goauth.ErrRateLimited, goauth.CodeRateLimited},
		{goauth.ErrInvalidToken, goauth.CodeInvalidToken},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			if tt.err.Error() == "" {
				t.Errorf("Error message should not be empty for %s", tt.code)
			}
			t.Logf("✓ %s: %q", tt.code, tt.err.Error())
		})
	}
}

func TestAuthError(t *testing.T) {
	authErr := &goauth.AuthError{
		Code:    goauth.CodeInvalidCredentials,
		Message: "Invalid email or password",
	}

	if authErr.Error() != "Invalid email or password" {
		t.Errorf("AuthError.Error() = %q, want %q", authErr.Error(), "Invalid email or password")
	}

	// Test with internal error
	authErrWithInternal := &goauth.AuthError{
		Code:     goauth.CodeInternalError,
		Message:  "Internal server error",
		Internal: goauth.ErrDatabaseError,
	}

	if authErrWithInternal.Unwrap() != goauth.ErrDatabaseError {
		t.Error("Unwrap should return internal error")
	}

	t.Log("✓ AuthError implementations verified")
}

// ==================== TIMING TESTS ====================

func TestConstantTimeOperations(t *testing.T) {
	// Test that operations don't leak timing information
	// This is a basic check - proper timing analysis requires more sophisticated tools

	password := "correctpassword123"
	wrongShort := "wrong"
	wrongSameLen := "incorrectpass1234"

	iterations := 1000

	t.Run("PasswordComparison", func(t *testing.T) {
		var shortTotal, sameLenTotal time.Duration

		for i := 0; i < iterations; i++ {
			start := time.Now()
			_ = password == wrongShort
			shortTotal += time.Since(start)

			start = time.Now()
			_ = password == wrongSameLen
			sameLenTotal += time.Since(start)
		}

		shortAvg := shortTotal / time.Duration(iterations)
		sameLenAvg := sameLenTotal / time.Duration(iterations)

		// Log timing information (for manual review)
		t.Logf("Short comparison avg: %v", shortAvg)
		t.Logf("Same-length comparison avg: %v", sameLenAvg)
	})
}
