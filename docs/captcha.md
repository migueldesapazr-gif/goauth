# CAPTCHA Integration

GoAuth supports multiple CAPTCHA providers for bot protection.

## Supported Providers

| Provider | Function | Notes |
|----------|----------|-------|
| Cloudflare Turnstile | `WithTurnstile(secret)` | Privacy-focused, free |
| Google reCAPTCHA v2 | `WithReCaptcha(secret)` | Classic checkbox |
| Google reCAPTCHA v3 | `WithReCaptchaV3(secret, minScore)` | Invisible, score-based |
| hCaptcha | `WithHCaptcha(secret)` | Privacy-focused |

## Quick Setup

### Cloudflare Turnstile (Recommended)

1. Get keys from [Cloudflare Dashboard](https://dash.cloudflare.com/turnstile)
2. Add to your app:

```go
goauth.WithTurnstile(os.Getenv("GOAUTH_TURNSTILE_SECRET"))
```

Frontend:
```html
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<div class="cf-turnstile" data-sitekey="YOUR_SITE_KEY"></div>
```

### Google reCAPTCHA v2

1. Get keys from [reCAPTCHA Admin](https://www.google.com/recaptcha/admin)

```go
goauth.WithReCaptcha(os.Getenv("GOAUTH_RECAPTCHA_SECRET"))
```

Frontend:
```html
<script src="https://www.google.com/recaptcha/api.js" async defer></script>
<div class="g-recaptcha" data-sitekey="YOUR_SITE_KEY"></div>
```

### Google reCAPTCHA v3 (Invisible)

```go
goauth.WithReCaptchaV3(secret, 0.5) // 0.5 = minimum score
```

### hCaptcha

1. Get keys from [hCaptcha Dashboard](https://dashboard.hcaptcha.com/)

```go
goauth.WithHCaptcha(os.Getenv("GOAUTH_HCAPTCHA_SECRET"))
```

## Environment Variables

```env
# Optional provider selector
GOAUTH_CAPTCHA_PROVIDER=turnstile

# Cloudflare Turnstile
GOAUTH_TURNSTILE_SECRET=xxx

# Google reCAPTCHA
GOAUTH_RECAPTCHA_SECRET=xxx
GOAUTH_RECAPTCHA_V3_SECRET=xxx
GOAUTH_RECAPTCHA_MIN_SCORE=0.5

# hCaptcha
GOAUTH_HCAPTCHA_SECRET=xxx
```

With `ConfigFromEnv()`:
```go
auth, _ := goauth.New(
    goauth.WithDatabase(db),
    goauth.WithSecretsFromEnv(),
    goauth.ConfigFromEnv()..., // Auto-configures CAPTCHA from env
)
```

## API Request Format

When CAPTCHA is enabled, include the token in requests:

```json
{
    "email": "user@example.com",
    "password": "password123",
    "captcha_token": "the-captcha-response-token"
}
```

## Custom Provider

```go
type MyCaptcha struct{}

func (m *MyCaptcha) Name() string { return "mycaptcha" }
func (m *MyCaptcha) Verify(ctx context.Context, token, ip string) (bool, error) {
    // Your verification logic
    return true, nil
}

goauth.WithCaptcha(&MyCaptcha{})
```
