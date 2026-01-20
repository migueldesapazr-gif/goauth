# Quick Start

Get GoAuth running in a few minutes.

## 1) Install

```bash
go get github.com/migueldesapazr-gif/goauth
```

## 2) Secrets

Generate secrets (32 bytes each, base64):
```bash
openssl rand -base64 32  # GOAUTH_JWT_SECRET
openssl rand -base64 32  # GOAUTH_ENCRYPTION_KEY
openssl rand -base64 32  # GOAUTH_PEPPER
```

Create `.env`:
```env
GOAUTH_JWT_SECRET=...
GOAUTH_ENCRYPTION_KEY=...
GOAUTH_PEPPER=...
GOAUTH_APP_NAME=My App
GOAUTH_APP_URL=http://localhost:8080
```

## 3) Database

Run the schema in `docs/schema.sql` (or MySQL/SQLite variants).

## 4) Code

```go
package main

import (
	"context"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/migueldesapazr-gif/goauth"
)

func main() {
	db, err := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		panic(err)
	}

	auth, err := goauth.New(
		goauth.WithDatabase(db),
		goauth.WithSecretsFromEnv(),
		goauth.ConfigFromEnv()...,
	)
	if err != nil {
		panic(err)
	}

	r := chi.NewRouter()
	r.Mount("/auth", auth.Handler())
	http.ListenAndServe(":8080", r)
}
```

## 5) Test

```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"MyPassword123"}'
```

Next steps:
- `env.md`
- `CONFIGURATION.md`
- `security.md`
