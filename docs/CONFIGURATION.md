# Configuration Guide

Complete reference for all GoAuth configuration options.

## Required Options

These must be set for GoAuth to function:

```go
goauth.WithStore(store)              // Database adapter
goauth.WithJWTSecret([]byte{...})    // 32-byte JWT signing key
goauth.WithMEK([]byte{...})          // 32-byte Master Encryption Key
goauth.WithPepper([]byte{...})       // 32-byte password pepper
```

## Security Modes

Predefined security configurations:

```go
// Permissive - minimal security for development
goauth.WithSecurityMode(goauth.SecurityModePermissive)
// - No email verification required
// - No 2FA required
// - No CAPTCHA
// - No IP blocking
// - Min password: 8 chars

// Balanced - recommended for production
goauth.WithSecurityMode(goauth.SecurityModeBalanced)
// - Email verification required
// - CAPTCHA on register/login
// - IP blocking enabled
// - Disposable email blocking
// - Min password: 10 chars

// Strict - high security (banks, healthcare)
goauth.WithSecurityMode(goauth.SecurityModeStrict)
// - Everything in Balanced, plus:
// - 2FA required for all actions
// - CAPTCHA on all sensitive actions
// - Aggressive rate limiting
// - Min password: 12 chars
```

## Authentication Options

### Email/Password

```go
goauth.WithEmailPasswordEnabled(true)
goauth.WithEmailVerificationRequired(true)
goauth.WithPasswordPolicy(goauth.PasswordPolicy{
    MinLength:          12,
    RequireUppercase:   true,
    RequireLowercase:   true,
    RequireNumber:      true,
    RequireSpecial:     true,
    MaxRepeatingChars:  3,
    BlockCommonPasswords: true,
    CheckHIBP:          true,
})
```

### Username

```go
goauth.WithUsernameEnabled(true)
goauth.WithUsernameRequired(false)
goauth.WithUsernamePolicy(goauth.UsernamePolicy{
    MinLength: 3,
    MaxLength: 30,
    AllowedChars: "a-zA-Z0-9_-",
})
```

### OAuth Providers

```go
goauth.WithOAuthProvider(goauth.NewGoogleProvider(id, secret))
goauth.WithOAuthProvider(goauth.NewDiscordProvider(id, secret))
goauth.WithOAuthProvider(goauth.NewGitHubProvider(id, secret))
goauth.WithOAuthProvider(goauth.NewMicrosoftProvider(id, secret))
goauth.WithOAuthProvider(goauth.NewTwitchProvider(id, secret))

// Custom provider
goauth.WithOAuthProvider(goauth.NewCustomProvider(
    "myapp",
    clientID, clientSecret,
    "https://myapp.com/oauth/authorize",
    "https://myapp.com/oauth/token",
    "https://myapp.com/api/user",
    []string{"email", "profile"},
    myUserParser,
))
```

### WebAuthn/Passkeys

```go
goauth.WithWebAuthn(goauth.WebAuthnConfig{
    RPDisplayName:          "My Application",
    RPID:                   "example.com",
    RPOrigins:              []string{"https://example.com"},
    Timeout:                60000,
    AttestationPreference:  "none",
    UserVerification:       "preferred",
    ResidentKeyRequirement: "preferred",
})
```

### Magic Links

```go
goauth.WithMagicLinkEnabled(true)
goauth.WithMagicLinkTTL(15 * time.Minute)
```

### 2FA/TOTP

```go
goauth.With2FAEnabled(true)
goauth.WithRequire2FAForAuth(false)
goauth.WithBackupCodeCount(10)
```

## Token Configuration

```go
goauth.WithAccessTokenTTL(15 * time.Minute)
goauth.WithRefreshTokenTTL(7 * 24 * time.Hour)
goauth.WithRotateRefreshTokens(true)
```

## Rate Limiting

```go
goauth.WithRateLimiter(limiter)
goauth.WithRateLimits(goauth.RateLimits{
    LoginLimit:          10,
    LoginWindow:         time.Minute,
    RegisterLimit:       5,
    RegisterWindow:      time.Hour,
    PasswordResetLimit:  3,
    PasswordResetWindow: time.Hour,
})
```

## IP Blocking

```go
goauth.WithIPBlocking(goauth.IPBlockConfig{
    Enabled:          true,
    FailureThreshold: 10,
    FailureWindow:    15 * time.Minute,
    BlockDuration:    30 * time.Minute,
})
```

## CAPTCHA

```go
// Cloudflare Turnstile (recommended)
goauth.WithCaptcha(goauth.NewTurnstile(secret))

// Google reCAPTCHA v2
goauth.WithCaptcha(goauth.NewReCaptchaV2(secret))

// Google reCAPTCHA v3
goauth.WithCaptcha(goauth.NewReCaptchaV3(secret, 0.5))

// hCaptcha
goauth.WithCaptcha(goauth.NewHCaptcha(secret))

// Enable for specific actions
goauth.WithCaptchaRequired(true)
goauth.WithCaptchaOnRegister(true)
goauth.WithCaptchaOnLogin(true)
goauth.WithCaptchaOnPasswordReset(true)
```

## Privacy Options

```go
goauth.WithIPPrivacy(goauth.IPPrivacyConfig{
    StoreIP:       false,      // Don't store IPs
    EncryptIP:     true,       // Encrypt if storing
    HashIPInLogs:  true,       // Hash in audit logs
    IPRetention:   30 * 24 * time.Hour,
})
```

## Email Configuration

```go
goauth.WithMailer(myMailer)
goauth.WithAppName("My Application")
goauth.WithAppBaseURL("https://example.com")
```

## Logging

```go
goauth.WithLogger(zapLogger)
goauth.WithAuditLogRetention(90 * 24 * time.Hour)
```

## Environment Variables

Load configuration from environment:

```go
auth, err := goauth.NewFromEnv()
```

Required variables:
- `GOAUTH_JWT_SECRET`
- `GOAUTH_MEK`
- `GOAUTH_PEPPER`
- `DATABASE_URL`

Optional variables:
- `GOAUTH_APP_NAME`
- `GOAUTH_APP_URL`
- `GOAUTH_SECURITY_MODE`
- `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`
- `DISCORD_CLIENT_ID` / `DISCORD_CLIENT_SECRET`
- `TURNSTILE_SECRET`
