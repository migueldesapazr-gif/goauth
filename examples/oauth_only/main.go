// Example: OAuth Only
//
// Use GoAuth for OAuth authentication only (no email/password).
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"login"
)

func main() {
	db, err := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// OAuth-only configuration
	auth, err := goauth.New(
		goauth.WithDatabase(db),
		goauth.WithSecretsFromEnv(),

		// Disable email/password
		goauth.WithEmailPassword(false),
		goauth.WithPasswordReset(false),

		// Enable OAuth providers
		goauth.WithGoogle(os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET")),
		goauth.WithDiscord(os.Getenv("DISCORD_CLIENT_ID"), os.Getenv("DISCORD_CLIENT_SECRET")),
		goauth.WithGitHub(os.Getenv("GITHUB_CLIENT_ID"), os.Getenv("GITHUB_CLIENT_SECRET")),

		goauth.WithAppURL("http://localhost:8080"),
	)
	if err != nil {
		log.Fatal(err)
	}

	r := chi.NewRouter()
	r.Mount("/auth", auth.Handler())

	// Available endpoints:
	// GET /auth/google         -> Redirect to Google
	// GET /auth/google/callback -> Handle callback
	// GET /auth/discord        -> Redirect to Discord
	// GET /auth/discord/callback
	// GET /auth/github         -> Redirect to GitHub
	// GET /auth/github/callback
	// POST /auth/refresh       -> Refresh tokens
	// POST /auth/logout        -> Logout

	log.Println("Server starting on :8080")
	log.Println("Login URLs:")
	log.Println("  - http://localhost:8080/auth/google")
	log.Println("  - http://localhost:8080/auth/discord")
	log.Println("  - http://localhost:8080/auth/github")
	http.ListenAndServe(":8080", r)
}

