# GoAuth

[![Go Reference](https://pkg.go.dev/badge/github.com/YOURUSERNAME/goauth.svg)](https://pkg.go.dev/github.com/YOURUSERNAME/goauth)
[![Go Report Card](https://goreportcard.com/badge/github.com/YOURUSERNAME/goauth)](https://goreportcard.com/report/github.com/YOURUSERNAME/goauth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A production-ready, enterprise-grade authentication library for Go with security-first design.

## Features

### Authentication
- **Email/Password** - Argon2id hashing, breach detection (HIBP)
- **OAuth** - Google, Discord, GitHub, Microsoft, Twitch, Custom
- **WebAuthn/Passkeys** - FIDO2 passwordless authentication
- **Magic Links** - Email-based passwordless login
- **2FA/TOTP** - Time-based codes with backup recovery

### Security
- **AES-256-GCM** encryption for PII
- **Argon2id** password hashing (OWASP recommended)
- **Rate limiting** with sliding window
- **IP blocking** for brute force protection
- **Token blacklist** for immediate revocation
- **CAPTCHA** - Turnstile, reCAPTCHA, hCaptcha
- **Disposable email blocking**

### Enterprise
- **Multi-tenancy** support
- **RBAC** - Role-based access control
- **Webhooks** for events
- **Audit logging** with retention
- **Device management**
- **API keys** for service auth
- **Prometheus metrics**
- **Health checks**

### Privacy & Compliance
- Configurable IP storage/hashing
- Data export (GDPR)
- Account deletion
- Consent management hooks

## Installation

```bash
go get github.com/YOURUSERNAME/goauth
```

## Quick Start

```go
package main

import (
    "log"
    "net/http"

    "github.com/YOURUSERNAME/goauth"
    "github.com/YOURUSERNAME/goauth/stores/postgres"
)

func main() {
    // Connect to database
    store, err := postgres.New("postgres://user:pass@localhost/db")
    if err != nil {
        log.Fatal(err)
    }

    // Create auth service
    auth, err := goauth.New(
        goauth.WithStore(store),
        goauth.WithJWTSecret([]byte("your-32-byte-secret-key-here!!")),
        goauth.WithMEK([]byte("your-32-byte-master-key-here!!")),
        goauth.WithPepper([]byte("your-32-byte-pepper-here-too!!")),
        goauth.WithSecurityMode(goauth.SecurityModeBalanced),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Mount auth routes
    http.Handle("/auth/", auth.Handler())
    
    log.Println("Server running on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## Configuration

### Security Modes

```go
// Development - minimal security
goauth.WithSecurityMode(goauth.SecurityModePermissive)

// Production - balanced security (recommended)
goauth.WithSecurityMode(goauth.SecurityModeBalanced)

// High security - banks, healthcare
goauth.WithSecurityMode(goauth.SecurityModeStrict)
```

### OAuth Providers

```go
goauth.WithOAuthProvider(goauth.NewGoogleProvider(clientID, clientSecret)),
goauth.WithOAuthProvider(goauth.NewDiscordProvider(clientID, clientSecret)),
goauth.WithOAuthProvider(goauth.NewGitHubProvider(clientID, clientSecret)),
goauth.WithOAuthProvider(goauth.NewMicrosoftProvider(clientID, clientSecret)),
goauth.WithOAuthProvider(goauth.NewTwitchProvider(clientID, clientSecret)),
```

### WebAuthn/Passkeys

```go
goauth.WithWebAuthn(goauth.WebAuthnConfig{
    RPDisplayName: "My App",
    RPID:          "example.com",
    RPOrigins:     []string{"https://example.com"},
}),
```

### CAPTCHA

```go
goauth.WithCaptcha(goauth.NewTurnstile(secret)),
// or
goauth.WithCaptcha(goauth.NewReCaptchaV3(secret, 0.5)),
// or
goauth.WithCaptcha(goauth.NewHCaptcha(secret)),
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/register` | Create account |
| POST | `/auth/login` | Email/password login |
| POST | `/auth/logout` | Revoke tokens |
| POST | `/auth/refresh` | Refresh access token |
| POST | `/auth/verify-email` | Verify email |
| POST | `/auth/password/reset` | Request password reset |
| POST | `/auth/password/reset/confirm` | Confirm password reset |
| POST | `/auth/2fa/setup` | Begin 2FA setup |
| POST | `/auth/2fa/verify` | Complete 2FA setup |
| POST | `/auth/2fa/validate` | Validate 2FA code |
| GET | `/auth/{provider}` | OAuth redirect |
| GET | `/auth/{provider}/callback` | OAuth callback |
| POST | `/auth/webauthn/register/begin` | Start passkey registration |
| POST | `/auth/webauthn/register/finish` | Complete passkey registration |
| POST | `/auth/webauthn/login/begin` | Start passkey login |
| POST | `/auth/webauthn/login/finish` | Complete passkey login |
| GET | `/auth/me` | Get current user |
| GET | `/health` | Health check |
| GET | `/metrics` | Prometheus metrics |

## Database Support

- **PostgreSQL** (recommended)
- **MySQL**
- **MongoDB**
- **SQLite** (development)

See [docs/SCHEMA.md](docs/SCHEMA.md) for database schemas.

## Documentation

- [Quick Start Guide](docs/QUICK_START.md)
- [Configuration](docs/CONFIGURATION.md)
- [Security Guide](docs/SECURITY.md)
- [API Reference](docs/API.md)
- [Examples](examples/)

## Environment Variables

```bash
# Required
GOAUTH_JWT_SECRET=your-32-byte-secret
GOAUTH_MEK=your-32-byte-master-encryption-key
GOAUTH_PEPPER=your-32-byte-pepper

# Database
DATABASE_URL=postgres://user:pass@localhost/db

# Optional
GOAUTH_APP_NAME=MyApp
GOAUTH_APP_URL=https://example.com
GOAUTH_SECURITY_MODE=balanced

# OAuth (optional)
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
DISCORD_CLIENT_ID=...
DISCORD_CLIENT_SECRET=...

# CAPTCHA (optional)
TURNSTILE_SECRET=...
```

## License

MIT License - see [LICENSE](LICENSE)
