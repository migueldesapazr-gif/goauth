# Security Guide

GoAuth ships with secure defaults and configurable controls for high-risk deployments.

## Passwords

- Argon2id with OWASP-recommended parameters
- Optional breach checks with HIBP

```go
goauth.WithPasswordPolicy(10, true, 5) // min length, complexity, history size
goauth.WithHIBP()
```

## Tokens

```go
goauth.WithTokenTTL(15*time.Minute, 7*24*time.Hour)
goauth.WithRotateRefreshTokens(true)
goauth.WithRedisBlacklist(redisClient) // immediate access token revocation
```

## 2FA (TOTP)

```go
goauth.WithTOTP(true)
goauth.WithTOTPDigits(6)
goauth.WithTOTPQRCode(true)
```

Backup codes:
- Digits-only by default
- HMAC-SHA256 with pepper
- One-time use

```go
goauth.WithBackupCodeLength(8)
goauth.WithBackupCodeDigitsOnly(true)
goauth.WithBackupCodeCount(10)
```

## OAuth + 2FA

By default, OAuth logins require 2FA when the user has 2FA enabled:
```go
goauth.WithRequire2FAForOAuth(true)
```

## Passkeys

```go
goauth.WithWebAuthn(goauth.WebAuthnConfig{
    MaxPasskeysPerUser: 5,
    AllowPasskeysForRoles: []goauth.Role{goauth.RoleAdmin},
})
```

## CAPTCHA

```go
goauth.WithTurnstile(secret)
goauth.WithCaptchaRequired(true)
goauth.WithCaptchaFailOpen(false) // recommended
```

If CAPTCHA is required but no provider is configured, GoAuth logs a warning on startup.

## Rate Limiting and IP Blocking

```go
goauth.WithRateLimits(...)
goauth.WithIPBlock(...)
```

At scale, use Redis-backed rate limiting and token blacklists to avoid per-instance bypass.

## Privacy and Enumeration

- Login errors are generic to avoid account enumeration.
- IPs can be encrypted or hashed in logs.

```go
goauth.WithIPPrivacy(goauth.IPPrivacyConfig{
    StoreIP:         true,
    EncryptIP:       true,
    HashIPInLogs:    true,
    IPRetentionDays: 90,
})
```

## Proxies and TLS Termination

If you run behind Cloudflare or a load balancer, enable trusted proxy parsing:
```go
goauth.WithTrustProxyHeaders(true)
goauth.WithTrustedProxies([]string{"10.0.0.0/8"})
```

This ensures correct IP logging and secure cookie handling for OAuth state.
