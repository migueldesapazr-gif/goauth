# GoAuth Lab Test Suite

A comprehensive test suite to verify each feature of the GoAuth library.

## Setup

1. Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and add your API keys and configuration

3. Start a PostgreSQL database (local or Docker):
   ```bash
   docker run -d --name goauth-test-db \
     -e POSTGRES_USER=user \
     -e POSTGRES_PASSWORD=password \
     -e POSTGRES_DB=goauth_test \
     -p 5432:5432 \
     postgres:16
   ```

4. Run the schema:
   ```bash
   psql $DATABASE_URL < ../docs/schema.sql
   ```

## Running Tests

### Run all tests:
```bash
go test -v ./...
```

### Run specific feature tests:
```bash
# Crypto tests
go test -v ./crypto_test.go

# Auth flow tests
go test -v ./auth_test.go

# Token tests
go test -v ./tokens_test.go

# 2FA tests
go test -v ./totp_test.go

# Password tests
go test -v ./password_test.go
```

## Test Categories

| File | Tests |
|------|-------|
| `crypto_test.go` | Encryption, hashing, key derivation |
| `auth_test.go` | Registration, login, logout flows |
| `tokens_test.go` | JWT, refresh tokens, blacklist |
| `totp_test.go` | 2FA setup, verification, backup codes |
| `password_test.go` | Password hashing, validation, HIBP |
| `oauth_test.go` | OAuth provider flows |
| `email_test.go` | Email verification, change, reset |
| `ratelimit_test.go` | Rate limiting, IP blocking |
