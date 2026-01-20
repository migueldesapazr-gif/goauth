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

## Environment Variables

```env
GOAUTH_JWT_SECRET=base64-32-bytes
GOAUTH_ENCRYPTION_KEY=base64-32-bytes
GOAUTH_PEPPER=base64-32-bytes
DATABASE_URL=postgres://user:pass@localhost/db
```

Proxy deployments (Cloudflare, load balancers):
```
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
