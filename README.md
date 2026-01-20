# GoAuth

[![Go Reference](https://pkg.go.dev/badge/github.com/migueldesapazr-gif/goauth.svg)](https://pkg.go.dev/github.com/migueldesapazr-gif/goauth)
[![Go Report Card](https://goreportcard.com/badge/github.com/migueldesapazr-gif/goauth)](https://goreportcard.com/report/github.com/migueldesapazr-gif/goauth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Security-first authentication for Go apps, designed for SaaS and enterprise scale.

## Features

- Email/password with Argon2id, breach checks (HIBP)
- OAuth providers (Google, Discord, GitHub, Microsoft, Twitch, custom)
- WebAuthn/passkeys with optional limits and role gating
- TOTP 2FA with backup codes (digits-only by default)
- Magic links, API keys, device sessions, RBAC
- Privacy controls (IP encryption, hashing, retention)
- Rate limiting, IP blocking, CAPTCHA, token blacklist

## Installation

```bash
go get github.com/migueldesapazr-gif/goauth
```

## Database Setup

Initialize your PostgreSQL database with the provided schema:

```bash
psql -d your_database -f schema/postgres.sql
```

## Quick Start

```go
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/migueldesapazr-gif/goauth"
	"github.com/migueldesapazr-gif/goauth/stores/postgres"
)

func main() {
	db, err := pgxpool.New(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	auth, err := goauth.New(
		postgres.WithDatabase(db),
		goauth.WithSecretsFromEnv(),
		goauth.WithSecurityMode(goauth.SecurityModeBalanced),
	)
	if err != nil {
		log.Fatal(err)
	}

	r := chi.NewRouter()
	r.Mount("/auth", auth.Handler())

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
```

## OAuth Configuration

Configure OAuth providers with customizable scopes:

```go
goauth.WithGoogle(clientID, clientSecret, goauth.WithGoogleScopes("email", "profile", "openid"))
goauth.WithDiscord(clientID, clientSecret, goauth.WithDiscordScopes("identify", "email", "guilds"))
goauth.WithGitHub(clientID, clientSecret, goauth.WithGitHubScopes("user:email", "read:user"))
```

## CAPTCHA

Choose your provider:

```go
// Cloudflare Turnstile
goauth.WithTurnstile(secret)

// Google reCAPTCHA v2 (checkbox)
goauth.WithReCaptcha(secret)

// Google reCAPTCHA v3 (invisible, score-based)
goauth.WithReCaptchaV3(secret, 0.5)

// hCaptcha
goauth.WithHCaptcha(secret)
```

## Environment Variables

```env
GOAUTH_JWT_SECRET=base64-32-bytes
GOAUTH_ENCRYPTION_KEY=base64-32-bytes
GOAUTH_PEPPER=base64-32-bytes
DATABASE_URL=postgres://user:pass@localhost/db
```

OAuth providers (optional):
```env
GOOGLE_CLIENT_ID=xxx
GOOGLE_CLIENT_SECRET=xxx
DISCORD_CLIENT_ID=xxx
DISCORD_CLIENT_SECRET=xxx
GITHUB_CLIENT_ID=xxx
GITHUB_CLIENT_SECRET=xxx
```

Proxy deployments (Cloudflare, load balancers):
```env
GOAUTH_TRUST_PROXY_HEADERS=true
GOAUTH_TRUSTED_PROXIES=10.0.0.0/8,192.168.0.0/16
```

## Documentation

- `docs/QUICK_START.md`
- `docs/CONFIGURATION.md`
- `docs/API.md`
- `docs/security.md`
- `docs/flows.md`

## License

MIT License - see `LICENSE`

