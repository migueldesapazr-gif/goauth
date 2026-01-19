# Quick Start Guide

Get GoAuth running in 5 minutes.

## 1. Install

```bash
go get github.com/yourusername/goauth
```

## 2. Set Environment Variables

```bash
# Generate secrets (32 bytes each, base64 encoded)
openssl rand -base64 32  # GOAUTH_JWT_SECRET
openssl rand -base64 32  # GOAUTH_ENCRYPTION_KEY
openssl rand -base64 32  # GOAUTH_PEPPER
```

Create `.env`:
```env
# Required
GOAUTH_JWT_SECRET=your-jwt-secret-here
GOAUTH_ENCRYPTION_KEY=your-encryption-key-here
GOAUTH_PEPPER=your-pepper-here

# Optional
GOAUTH_APP_NAME=My App
GOAUTH_APP_URL=http://localhost:8080

# OAuth (optional)
GOAUTH_GOOGLE_CLIENT_ID=xxx
GOAUTH_GOOGLE_CLIENT_SECRET=xxx
GOAUTH_DISCORD_CLIENT_ID=xxx
GOAUTH_DISCORD_CLIENT_SECRET=xxx

# Email (optional)
GOAUTH_RESEND_API_KEY=xxx
GOAUTH_RESEND_FROM_EMAIL=noreply@myapp.com
GOAUTH_RESEND_FROM_NAME=My App

# CAPTCHA (optional)
GOAUTH_TURNSTILE_SECRET=xxx

# Security presets (optional)
GOAUTH_SECURITY_MODE=balanced
GOAUTH_BLOCK_DISPOSABLE_EMAILS=true

# Optional username support
GOAUTH_USERNAME_ENABLED=true
```

## 3. Create Database

```sql
-- See docs/schema.sql for full schema
-- MySQL: docs/schema.mysql.sql
-- SQLite: docs/schema.sqlite.sql
CREATE TABLE users (...);
CREATE TABLE email_verification_tokens (...);
-- etc.
```

### Other Databases

```go
// MySQL / SQLite (database/sql)
goauth.WithMySQLStore(usersDB, auditDB)
goauth.WithSQLiteStore(usersDB, auditDB)

// MongoDB
goauth.WithMongoStore(mongoClient, "goauth")
```

## 4. Write Code

```go
package main

import (
    "context"
    "net/http"
    "os"

    "github.com/go-chi/chi/v5"
    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/joho/godotenv"
    
    "github.com/yourusername/goauth"
)

func main() {
    // Load .env file (optional, use godotenv)
    godotenv.Load()
    
    // Connect to database
    db, err := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))
    if err != nil {
        panic(err)
    }
    
    // Create auth service
    auth, err := goauth.New(
        goauth.WithDatabase(db), // Postgres
        goauth.WithSecretsFromEnv(),
        // Auto-configure from env (OAuth, email, captcha)
        goauth.ConfigFromEnv()...,
    )
    if err != nil {
        panic(err)
    }
    
    // Setup router
    r := chi.NewRouter()
    r.Mount("/auth", auth.Handler())
    
    // Your routes
    r.Group(func(r chi.Router) {
        r.Use(auth.RequireAuth())
        r.Get("/profile", profileHandler)
    })
    
    http.ListenAndServe(":8080", r)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
    user, _ := goauth.GetUserFromContext(r.Context())
    // Use user.ID, user.EmailVerified, etc.
}
```

## 5. Test It

```bash
# Register
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "MyPassword123"}'

# Login
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "MyPassword123"}'
```

## Next Steps

- [Environment Variables](env.md)
- [Security and Privacy](security.md)
- [UI Pages](ui-pages.md)
- [OAuth Setup](oauth.md)
