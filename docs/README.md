# GoAuth Documentation

GoAuth is a security-first authentication library for Go.

## Table of Contents

1. `quickstart.md`
2. `CONFIGURATION.md`
3. `API.md`
4. `flows.md`
5. `oauth.md`
6. `captcha.md`
7. `env.md`
8. `security.md`
9. `schema.sql` (Postgres)
10. `schema.mysql.sql`
11. `schema.sqlite.sql`
12. `docker.md`
13. `ui-pages.md`

## Quick Install

```bash
go get github.com/migueldesapazr-gif/goauth
```

## Minimal Example

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
	db, _ := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))

	auth, _ := goauth.New(
		goauth.WithDatabase(db),
		goauth.WithSecretsFromEnv(),
	)

	r := chi.NewRouter()
	r.Mount("/auth", auth.Handler())
	http.ListenAndServe(":8080", r)
}
```

## Key Features

- Email/password auth with Argon2id
- OAuth providers + WebAuthn/passkeys
- TOTP 2FA + backup codes
- CAPTCHA, rate limits, IP blocking
- Privacy controls (IP encryption, hashing, retention)
