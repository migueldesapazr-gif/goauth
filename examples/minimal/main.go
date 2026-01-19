// Example: Minimal Setup
//
// The simplest way to get GoAuth running with just database and secrets.
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"login"
)

func main() {
	// Connect to database
	db, err := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create auth service - minimal config!
	auth, err := goauth.New(
		goauth.WithDatabase(db),
		goauth.WithSecretsFromEnv(), // Reads GOAUTH_JWT_SECRET, GOAUTH_ENCRYPTION_KEY, GOAUTH_PEPPER
	)
	if err != nil {
		log.Fatal(err)
	}

	// Setup router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Mount auth endpoints
	r.Mount("/auth", auth.Handler())

	// Health check
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	// Start server
	log.Println("Server starting on :8080")
	http.ListenAndServe(":8080", r)
}

