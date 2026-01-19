// Example: Privacy-Focused
//
// Minimal data collection, GDPR-friendly configuration.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

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

	// Privacy-focused configuration
	auth, err := goauth.New(
		goauth.WithDatabase(db),
		goauth.WithSecretsFromEnv(),

		// Additional privacy settings
		goauth.WithoutIPStorage(),                       // Don't store IPs at all
		goauth.WithAuditRetention(30 * 24 * time.Hour),  // Only 30 days audit logs
		goauth.WithEmailVerification(false),             // Don't force verification

		// Minimal OAuth (no Google tracking)
		goauth.WithGitHub(os.Getenv("GITHUB_CLIENT_ID"), os.Getenv("GITHUB_CLIENT_SECRET")),

		goauth.WithAppName("Privacy App"),
		goauth.WithAppURL("http://localhost:8080"),
	)
	if err != nil {
		log.Fatal(err)
	}

	r := chi.NewRouter()
	r.Mount("/auth", auth.Handler())

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Privacy-focused authentication"))
	})

	log.Println("Server starting on :8080")
	http.ListenAndServe(":8080", r)
}

