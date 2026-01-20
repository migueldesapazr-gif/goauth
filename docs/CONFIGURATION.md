# Configuration Guide

Reference for GoAuth configuration options.

## Required Options

```go
goauth.WithStore(store)          // custom store (any DB)
// or
goauth.WithDatabase(pgxPool)     // postgres pgx pool

goauth.WithSecrets(goauth.Secrets{
    JWTSecret:     jwtSecret,     // 32 bytes
    EncryptionKey: mek,           // 32 bytes
    Pepper:        pepper,        // 32 bytes
})
```

Use env loading:
```go
goauth.WithSecretsFromEnv()
```

## Security Modes

```go
goauth.WithSecurityMode(goauth.SecurityModePermissive)
goauth.WithSecurityMode(goauth.SecurityModeBalanced) // recommended
goauth.WithSecurityMode(goauth.SecurityModeStrict)
```

Notes:
- Balanced enables CAPTCHA and IP blocking, and requires 2FA after OAuth when the user has 2FA enabled.
- `CaptchaFailOpen` defaults to false.

## App Info

```go
goauth.WithAppName("My App")
goauth.WithAppURL("https://myapp.com")
goauth.WithCallbackPath("/auth") // mounted path for OAuth callbacks
```

## Email/Password

```go
goauth.WithEmailPassword(true)
goauth.WithEmailVerification(true)
goauth.WithEmailDomainCheck(true)
goauth.WithBlockDisposableEmails(true)
goauth.WithDisposableEmailDomains([]string{"mailinator.com"})
goauth.WithPasswordPolicy(10, true, 5) // min, complexity, history
goauth.WithHIBP()
```

## Username

```go
goauth.WithUsername(true)
goauth.WithUsernameRequired(false)
goauth.WithUsernamePolicy(3, 32)
goauth.WithUsernamePattern("^[a-z0-9._-]+$")
goauth.WithUsernameReserved([]string{"admin", "support"})
goauth.WithUsernameAllowNumericOnly(false)
```

## OAuth Providers

```go
goauth.WithGoogle(id, secret)
goauth.WithDiscord(id, secret)
goauth.WithGitHub(id, secret)
goauth.WithMicrosoft(id, secret)
goauth.WithTwitch(id, secret)
```

Custom provider:
```go
goauth.WithOAuth(goauth.NewCustomProvider(
    "gitlab",
    clientID, clientSecret,
    "https://gitlab.com/oauth/authorize",
    "https://gitlab.com/oauth/token",
    "https://gitlab.com/api/v4/user",
    []string{"read_user"},
    nil,
))
```

OAuth behavior:
```go
goauth.WithOAuthEmailLinking(true, false)
goauth.WithRequire2FAForOAuth(true)
```

## WebAuthn/Passkeys

```go
goauth.WithWebAuthn(goauth.WebAuthnConfig{
    RPDisplayName: "My App",
    RPID:          "example.com",
    RPOrigins:     []string{"https://example.com"},
    MaxPasskeysPerUser: 5,
    AllowPasskeysForRoles: []goauth.Role{goauth.RoleUser, goauth.RoleAdmin},
})
goauth.WithWebAuthnStore(myWebAuthnStore)
```

## Magic Links

```go
goauth.WithMagicLinks()
goauth.WithMagicLinkTTL(15 * time.Minute)
```

## 2FA/TOTP and Backup Codes

```go
goauth.WithTOTP(true)
goauth.WithTOTPDigits(6)               // 6 or 8
goauth.WithTOTPAccountName("My App")
goauth.WithTOTPUseUsername(true)
goauth.WithTOTPQRCode(true)
goauth.WithTOTPQRCodeSize(256)

goauth.WithBackupCodeLength(8)
goauth.WithBackupCodeDigitsOnly(true)
goauth.WithBackupCodeCount(10)

goauth.WithRequire2FAForAuth(false)
goauth.WithRequire2FAForMagicLink(false)
goauth.WithRequire2FAForSDK(false)
goauth.WithRequire2FAForEmailChange(true)
```

## Tokens

```go
goauth.WithTokenTTL(15*time.Minute, 7*24*time.Hour)
goauth.WithRotateRefreshTokens(true)
```

## Rate Limiting and IP Blocking

```go
goauth.WithRateLimits(goauth.RateLimitConfig{
    LoginLimit:          10,
    LoginWindow:         time.Minute,
    TwoFALimit:          5,
    TwoFAWindow:         time.Minute,
    RegisterLimit:       5,
    RegisterWindow:      time.Hour,
    PasswordResetLimit:  3,
    PasswordResetWindow: time.Hour,
})

goauth.WithIPBlock(goauth.IPBlockConfig{
    Enabled:          true,
    FailureThreshold: 10,
    FailureWindow:    15 * time.Minute,
    BlockDuration:    30 * time.Minute,
})
```

Use Redis in multi-instance deployments:
```go
goauth.WithRedis(redisClient)
goauth.WithRedisBlacklist(redisClient)
```

## CAPTCHA

CAPTCHA providers require **two keys**:
- **Site Key** (public): Used in the frontend to render the CAPTCHA widget
- **Secret Key** (private): Used in the backend to verify the response

### Environment Variables

Store keys in environment variables (recommended):

```env
# Cloudflare Turnstile
TURNSTILE_SITE_KEY=0x4AAAAAAxxxxxxxxxxxxxx
TURNSTILE_SECRET_KEY=0x4AAAAAAxxxxxxxxxxxxxx

# Google reCAPTCHA
RECAPTCHA_SITE_KEY=6Lcxxxxxxxxxxxxxxxxx
RECAPTCHA_SECRET_KEY=6Lcxxxxxxxxxxxxxxxxx
RECAPTCHA_V3_THRESHOLD=0.5

# hCaptcha
HCAPTCHA_SITE_KEY=00000000-0000-0000-0000-000000000000
HCAPTCHA_SECRET_KEY=0x0000000000000000000000000000000000000000
```

### Configuration

```go
// Using environment variables
goauth.WithTurnstile(os.Getenv("TURNSTILE_SECRET_KEY"))
goauth.WithReCaptcha(os.Getenv("RECAPTCHA_SECRET_KEY"))
goauth.WithReCaptchaV3(os.Getenv("RECAPTCHA_SECRET_KEY"), 0.5)
goauth.WithHCaptcha(os.Getenv("HCAPTCHA_SECRET_KEY"))

// CAPTCHA behavior
goauth.WithCaptchaRequired(true)
goauth.WithCaptchaFailOpen(false)  // Block if CAPTCHA service unavailable
goauth.WithCaptchaOnRegister(true)
goauth.WithCaptchaOnLogin(true)
goauth.WithCaptchaOnPasswordReset(true)
```

> **Note**: The site key is used in your frontend code to render the CAPTCHA widget. 
> Pass it to your templates or frontend configuration.

## Privacy and Retention

```go
goauth.WithIPPrivacy(goauth.IPPrivacyConfig{
    StoreIP:         true,
    EncryptIP:       true,
    HashIPInLogs:    true,
    IPRetentionDays: 90,
})
goauth.WithAuditRetention(365 * 24 * time.Hour)
goauth.WithUnverifiedAccountTTL(24 * time.Hour)
goauth.WithUserAgentHashInLogs(true)
```

## Proxies and Load Balancers

```go
goauth.WithTrustProxyHeaders(true)
goauth.WithTrustedProxies([]string{"10.0.0.0/8", "192.168.0.0/16"})
```

## Notifications

```go
goauth.WithNotifyOnPasswordChange(true)
goauth.WithNotifyOnEmailChange(true)
goauth.WithEmailChangeTTL(30 * time.Minute)
```
