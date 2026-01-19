# GoAuth Documentation

Welcome to the GoAuth documentation. GoAuth is a secure, flexible authentication library for Go.

## Table of Contents

1. [Quick Start](quickstart.md)
2. [OAuth Providers](oauth.md)
3. [CAPTCHA Integration](captcha.md)
4. [Environment Variables](env.md)
5. [Security and Privacy](security.md)
6. [Database Schema (Postgres)](schema.sql)
7. [Database Schema (MySQL)](schema.mysql.sql)
8. [Database Schema (SQLite)](schema.sqlite.sql)
9. [Docker Quickstart](docker.md)
10. [UI Pages](ui-pages.md)

## Quick Install

```bash
go get github.com/yourusername/goauth
```

## Minimal Example

```go
package main

import (
    "github.com/go-chi/chi/v5"
    "github.com/jackc/pgx/v5/pgxpool"
    "github.com/yourusername/goauth"
)

func main() {
    db, _ := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))

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

- **Email/Password** authentication with Argon2id hashing
- **OAuth** support for Google, Discord, GitHub, Microsoft, Twitch
- **2FA/TOTP** with backup codes
- **CAPTCHA** integration (Turnstile, reCAPTCHA, hCaptcha)
- **Privacy controls** (optional IP storage, configurable retention)
- **Security controls** (rate limits, lockouts, IP blocks)
