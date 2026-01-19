# Environment Variables

GoAuth can be configured through environment variables via `ConfigFromEnv()`.

## Required Secrets

```env
# 32 bytes each, base64 or hex
GOAUTH_JWT_SECRET=your-jwt-secret
GOAUTH_ENCRYPTION_KEY=your-encryption-key
GOAUTH_PEPPER=your-pepper
```

Generate with:
```bash
openssl rand -base64 32
```

## Secrets Loading Options

### .env File
```go
secrets, _ := goauth.SecretsFromEnvFile(".env")
```

### Raw File (3 lines)
```go
secrets, _ := goauth.SecretsFromRawFile("/run/secrets/goauth")
```

### Separate Files
```go
secrets, _ := goauth.SecretsFromFiles("jwt.key", "enc.key", "pepper.key")
```

### JSON File
```go
secrets, _ := goauth.SecretsFromJSONFile("secrets.json", map[string]string{
    "jwt": "jwt_secret",
    "encryption": "encryption_key",
    "pepper": "pepper",
})
```

### HashiCorp Vault
```go
secrets, _ := goauth.SecretsFromVaultEnv(ctx)
```

### AWS Secrets Manager / SSM
```go
secrets, _ := goauth.SecretsFromAWSSecretsManager(ctx, goauth.AWSSecretsConfig{
    SecretName: "goauth/secrets",
    Region:     "us-east-1",
})
```

```go
secrets, _ := goauth.SecretsFromAWSSSM(ctx, goauth.AWSSSMConfig{
    JWTParameter:        "/goauth/jwt",
    EncryptionParameter: "/goauth/encryption",
    PepperParameter:     "/goauth/pepper",
    Region:              "us-east-1",
})
```

## App Configuration

```env
GOAUTH_APP_NAME=My Application
GOAUTH_APP_URL=https://myapp.com
GOAUTH_SECURITY_MODE=balanced   # permissive|balanced|strict
```
Security mode sets a preset baseline and can be overridden by the flags below.

## Feature Toggles

```env
GOAUTH_EMAIL_PASSWORD_ENABLED=true
GOAUTH_EMAIL_VERIFICATION_REQUIRED=true
GOAUTH_TOTP_ENABLED=true
GOAUTH_PASSWORD_RESET_ENABLED=true
GOAUTH_MAGIC_LINKS_ENABLED=false
GOAUTH_EMAIL_DOMAIN_CHECK=true
GOAUTH_BLOCK_DISPOSABLE_EMAILS=true
GOAUTH_DISPOSABLE_EMAIL_DOMAINS=mailinator.com,10minutemail.com   # enables blocking if not set above
```

## Username

```env
GOAUTH_USERNAME_ENABLED=true
GOAUTH_USERNAME_REQUIRED=false
GOAUTH_USERNAME_MIN=3
GOAUTH_USERNAME_MAX=32
```

## Password Policy + Lockout

```env
GOAUTH_MIN_PASSWORD_LENGTH=10
GOAUTH_PASSWORD_COMPLEXITY=true
GOAUTH_PASSWORD_HISTORY=5
GOAUTH_MAX_LOGIN_ATTEMPTS=5
GOAUTH_LOCKOUT_DURATION=15m
```

## Route Requirements

```env
GOAUTH_REQUIRE_VERIFIED_EMAIL_FOR_AUTH=true
GOAUTH_REQUIRE_2FA_FOR_AUTH=false
GOAUTH_REQUIRE_2FA_FOR_OAUTH=false
GOAUTH_REQUIRE_2FA_FOR_MAGIC_LINK=false
GOAUTH_REQUIRE_2FA_FOR_SDK=false
GOAUTH_REQUIRE_2FA_FOR_EMAIL_CHANGE=true
```

## OAuth Email Linking

```env
GOAUTH_ALLOW_OAUTH_EMAIL_LINKING=true
GOAUTH_ALLOW_UNVERIFIED_OAUTH_EMAIL_LINKING=false
```

## Rate Limits

```env
GOAUTH_RATE_LOGIN_LIMIT=10
GOAUTH_RATE_LOGIN_WINDOW=1m
GOAUTH_RATE_2FA_LIMIT=5
GOAUTH_RATE_2FA_WINDOW=1m
GOAUTH_RATE_REGISTER_LIMIT=5
GOAUTH_RATE_REGISTER_WINDOW=1h
GOAUTH_RATE_PASSWORD_RESET_LIMIT=3
GOAUTH_RATE_PASSWORD_RESET_WINDOW=1h
GOAUTH_RATE_MAGIC_LINK_LIMIT=3
GOAUTH_RATE_MAGIC_LINK_WINDOW=1h
```

## IP Blocking

```env
GOAUTH_IP_BLOCK_ENABLED=true
GOAUTH_IP_BLOCK_FAILURE_THRESHOLD=10
GOAUTH_IP_BLOCK_FAILURE_WINDOW=15m
GOAUTH_IP_BLOCK_DURATION=30m
```

## Privacy and Retention

```env
GOAUTH_IP_STORE=true
GOAUTH_IP_ENCRYPT=true
GOAUTH_IP_HASH_IN_LOGS=true
GOAUTH_IP_RETENTION_DAYS=90
GOAUTH_AUDIT_RETENTION=8760h
GOAUTH_UNVERIFIED_ACCOUNT_TTL=24h
GOAUTH_USER_AGENT_HASH=true
```

## Notifications

```env
GOAUTH_NOTIFY_PASSWORD_CHANGE=true
GOAUTH_NOTIFY_EMAIL_CHANGE=true
GOAUTH_EMAIL_CHANGE_TTL=30m
```

## OAuth Providers

```env
GOAUTH_GOOGLE_CLIENT_ID=xxx.apps.googleusercontent.com
GOAUTH_GOOGLE_CLIENT_SECRET=xxx

GOAUTH_DISCORD_CLIENT_ID=xxx
GOAUTH_DISCORD_CLIENT_SECRET=xxx

GOAUTH_GITHUB_CLIENT_ID=xxx
GOAUTH_GITHUB_CLIENT_SECRET=xxx

GOAUTH_MICROSOFT_CLIENT_ID=xxx
GOAUTH_MICROSOFT_CLIENT_SECRET=xxx
```

## Email Providers

Choose a provider with `GOAUTH_EMAIL_PROVIDER` or set only one provider's variables.

```env
GOAUTH_EMAIL_PROVIDER=resend   # resend|sendgrid|mailgun|smtp
```

Resend:
```env
GOAUTH_RESEND_API_KEY=re_xxx
GOAUTH_RESEND_FROM_EMAIL=noreply@myapp.com
GOAUTH_RESEND_FROM_NAME=My App
```

SendGrid:
```env
GOAUTH_SENDGRID_API_KEY=SG.xxx
GOAUTH_SENDGRID_FROM_EMAIL=noreply@myapp.com
GOAUTH_SENDGRID_FROM_NAME=My App
```

Mailgun:
```env
GOAUTH_MAILGUN_API_KEY=key-xxx
GOAUTH_MAILGUN_DOMAIN=mg.myapp.com
GOAUTH_MAILGUN_FROM_EMAIL=noreply@myapp.com
GOAUTH_MAILGUN_FROM_NAME=My App
```

SMTP:
```env
GOAUTH_SMTP_HOST=smtp.myapp.com
GOAUTH_SMTP_PORT=465
GOAUTH_SMTP_USERNAME=user
GOAUTH_SMTP_PASSWORD=pass
GOAUTH_SMTP_FROM_EMAIL=noreply@myapp.com
GOAUTH_SMTP_FROM_NAME=My App
GOAUTH_SMTP_TLS=true
```

## CAPTCHA

```env
GOAUTH_CAPTCHA_PROVIDER=turnstile   # turnstile|recaptcha|recaptcha_v3|hcaptcha
GOAUTH_TURNSTILE_SECRET=xxx
GOAUTH_RECAPTCHA_SECRET=xxx
GOAUTH_RECAPTCHA_V3_SECRET=xxx
GOAUTH_RECAPTCHA_MIN_SCORE=0.5
GOAUTH_HCAPTCHA_SECRET=xxx

GOAUTH_CAPTCHA_REQUIRED=true
GOAUTH_CAPTCHA_ON_REGISTER=true
GOAUTH_CAPTCHA_ON_LOGIN=true
GOAUTH_CAPTCHA_ON_PASSWORD_RESET=true
GOAUTH_CAPTCHA_ON_MAGIC_LINK=false
GOAUTH_CAPTCHA_FAIL_OPEN=true
```

## HIBP

```env
GOAUTH_HIBP_ENABLED=true
GOAUTH_HIBP_API_URL=https://api.pwnedpasswords.com/range/
```

## Trusted Proxies

```env
GOAUTH_TRUST_PROXY_HEADERS=true
GOAUTH_TRUSTED_PROXIES=10.0.0.0/8,192.168.0.0/16
```

## Using in Code

```go
auth, _ := goauth.New(
    goauth.WithDatabase(db),
    goauth.WithSecretsFromEnv(),
    goauth.ConfigFromEnv()..., // OAuth, email, captcha, security settings
)
```
