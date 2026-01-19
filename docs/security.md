# Security Guide

GoAuth implements security best practices by default. This guide explains the security features and recommendations.

## Password Security

### Argon2id Hashing

GoAuth uses Argon2id with OWASP-recommended parameters:

- Memory: 64 MB
- Iterations: 3
- Parallelism: 4
- Key length: 32 bytes

```go
// These are the defaults, but can be customized:
goauth.WithArgon2Params(goauth.Argon2Params{
    Memory:   64 * 1024,
    Time:     3,
    Threads:  4,
    KeyLen:   32,
})
```

### Password Policies

```go
goauth.WithPasswordPolicy(goauth.PasswordPolicy{
    MinLength:            12,
    RequireUppercase:     true,
    RequireLowercase:     true,
    RequireNumber:        true,
    RequireSpecial:       true,
    MaxRepeatingChars:    3,
    BlockCommonPasswords: true,
    CheckHIBP:            true, // Check against known breaches
})
```

### Password History

Prevent password reuse:

```go
goauth.WithPasswordHistorySize(5)
```

## Encryption

### AES-256-GCM

All sensitive data is encrypted at rest:

- Email addresses
- TOTP secrets
- IP addresses (optional)

### Key Derivation

GoAuth uses HKDF to derive purpose-specific keys from a Master Encryption Key:

```go
// Single MEK generates:
// - Email encryption key
// - TOTP encryption key
// - Token encryption key
// - IP encryption key
```

**Never reuse the MEK as the JWT secret or pepper.**

## Token Security

### JWT Configuration

```go
goauth.WithAccessTokenTTL(15 * time.Minute)  // Short-lived
goauth.WithRefreshTokenTTL(7 * 24 * time.Hour)
goauth.WithRotateRefreshTokens(true)         // One-time use
```

### Token Blacklist

Immediate revocation support:

```go
goauth.WithTokenBlacklist(redisBlacklist)
```

## Brute Force Protection

### Rate Limiting

```go
goauth.WithRateLimits(goauth.RateLimits{
    LoginLimit:   5,
    LoginWindow:  time.Minute,
})
```

### IP Blocking

```go
goauth.WithIPBlocking(goauth.IPBlockConfig{
    Enabled:          true,
    FailureThreshold: 5,
    FailureWindow:    10 * time.Minute,
    BlockDuration:    1 * time.Hour,
})
```

### Account Lockout

```go
goauth.WithMaxLoginAttempts(5)
goauth.WithLockoutDuration(30 * time.Minute)
```

## Two-Factor Authentication

### TOTP

- RFC 6238 compliant
- 30-second window with ±1 step tolerance
- SHA-1 algorithm (compatible with Google Authenticator)

### Backup Codes

- 10 one-time codes
- Hashed with SHA-256
- Each code can only be used once

### WebAuthn/Passkeys

FIDO2-compliant passwordless authentication.

## CAPTCHA Integration

Protect against automated attacks:

```go
goauth.WithCaptcha(goauth.NewTurnstile(secret))
goauth.WithCaptchaOnRegister(true)
goauth.WithCaptchaOnLogin(true)
goauth.WithCaptchaOnPasswordReset(true)
```

## Timing Attack Prevention

GoAuth includes protections against timing attacks:

1. **Constant-time comparison** for all token/password verification
2. **Dummy hash computation** when user doesn't exist
3. **Consistent response times** regardless of outcome

## Security Headers

Recommended HTTP headers (not set by GoAuth, add to your server):

```go
w.Header().Set("X-Content-Type-Options", "nosniff")
w.Header().Set("X-Frame-Options", "DENY")
w.Header().Set("X-XSS-Protection", "1; mode=block")
w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
w.Header().Set("Content-Security-Policy", "default-src 'self'")
```

## Audit Logging

All security events are logged:

- Login success/failure
- Password changes
- 2FA setup/disable
- Account lockouts
- Suspicious activity

```go
goauth.WithAuditStore(auditStore)
goauth.WithAuditLogRetention(90 * 24 * time.Hour)
```

## Security Modes

Quick security presets:

| Feature | Permissive | Balanced | Strict |
|---------|------------|----------|--------|
| Email Verification | ❌ | ✅ | ✅ |
| 2FA Required | ❌ | ❌ | ✅ |
| CAPTCHA | ❌ | ✅ | ✅ |
| IP Blocking | ❌ | ✅ | ✅ |
| Disposable Email Block | ❌ | ✅ | ✅ |
| Min Password Length | 8 | 10 | 12 |
| Login Attempts | ∞ | 10 | 3 |

## Recommendations

1. **Always use HTTPS** in production
2. **Rotate secrets** periodically
3. **Monitor audit logs** for suspicious activity
4. **Enable 2FA** for admin accounts
5. **Use security mode `balanced`** or `strict` in production
6. **Keep dependencies updated**
