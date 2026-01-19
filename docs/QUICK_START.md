# Quick Start Guide

Get GoAuth running in your project in 5 minutes.

## Prerequisites

- Go 1.22+
- PostgreSQL, MySQL, MongoDB, or SQLite

## Installation

```bash
go get github.com/YOURUSERNAME/goauth
```

## Basic Setup

### 1. Create Database Schema

```sql
-- PostgreSQL example
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email_hash BYTEA NOT NULL UNIQUE,
    email_encrypted BYTEA,
    email_nonce BYTEA,
    password_hash BYTEA,
    password_salt BYTEA,
    username VARCHAR(50),
    username_normalized VARCHAR(50) UNIQUE,
    email_verified BOOLEAN DEFAULT FALSE,
    totp_enabled BOOLEAN DEFAULT FALSE,
    totp_secret_encrypted BYTEA,
    totp_nonce BYTEA,
    account_status VARCHAR(20) DEFAULT 'active',
    failed_login_attempts INT DEFAULT 0,
    role VARCHAR(50) DEFAULT 'user',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    last_login_ip BYTEA,
    last_login_ip_nonce BYTEA
);

CREATE INDEX idx_users_email_hash ON users(email_hash);
CREATE INDEX idx_users_username_normalized ON users(username_normalized);
```

### 2. Initialize GoAuth

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
    store, err := postgres.New("postgres://user:pass@localhost/myapp")
    if err != nil {
        log.Fatal(err)
    }

    // Create auth service with minimal config
    auth, err := goauth.New(
        goauth.WithStore(store),
        goauth.WithJWTSecret([]byte("change-this-to-32-bytes-secret!")),
        goauth.WithMEK([]byte("change-this-master-encryption-k")),
        goauth.WithPepper([]byte("change-this-to-32-bytes-pepper!")),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Mount auth routes at /auth
    http.Handle("/auth/", auth.Handler())

    // Your protected routes
    http.Handle("/api/", auth.RequireAuth(apiHandler()))

    log.Println("Server running on :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func apiHandler() http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        user, _ := goauth.GetUserFromContext(r.Context())
        w.Write([]byte("Hello, " + user.ID))
    })
}
```

### 3. Frontend Integration

```javascript
// Register
const response = await fetch('/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        email: 'user@example.com',
        password: 'SecurePassword123!'
    })
});

// Login
const loginResponse = await fetch('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        email: 'user@example.com',
        password: 'SecurePassword123!'
    })
});

const { access_token, refresh_token } = await loginResponse.json();

// Use access token for API calls
const apiResponse = await fetch('/api/data', {
    headers: { 'Authorization': `Bearer ${access_token}` }
});
```

## Next Steps

- [Configuration Guide](CONFIGURATION.md)
- [Security Best Practices](SECURITY.md)
- [API Reference](API.md)
