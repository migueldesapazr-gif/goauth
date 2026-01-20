package goauth

import (
	"errors"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/migueldesapazr-gif/goauth/crypto"
	"github.com/migueldesapazr-gif/goauth/mailers/mailgun"
	"github.com/migueldesapazr-gif/goauth/mailers/resend"
	"github.com/migueldesapazr-gif/goauth/mailers/sendgrid"
	smtpmailer "github.com/migueldesapazr-gif/goauth/mailers/smtp"
	redislimiter "github.com/migueldesapazr-gif/goauth/ratelimit/redis"
)

// Option configures the AuthService.
type Option func(*AuthService) error

func setOptionalStores(s *AuthService, store Store) {
	if store == nil {
		return
	}
	if s.store == nil {
		s.store = store
		return
	}
	// Add other storage checks here if needed
}

// ==================== REQUIRED ====================

// ErrStoreRequired is returned when using deprecated WithDatabase without a store.
var ErrStoreRequired = errors.New("WithDatabase is deprecated; use stores/postgres.WithDatabase or WithStore")

// WithDatabase is deprecated. Use stores/postgres.WithDatabase instead.
// This stub remains for documentation purposes.
func WithDatabase(db interface{}) Option {
	return func(s *AuthService) error {
		return ErrStoreRequired
	}
}

// WithDatabases is deprecated. Use stores/postgres.WithDatabases instead.
func WithDatabases(users, audit interface{}) Option {
	return func(s *AuthService) error {
		return ErrStoreRequired
	}
}

// WithStore sets a custom store implementation.
func WithStore(store Store) Option {
	return func(s *AuthService) error {
		s.store = store
		setOptionalStores(s, store)
		return nil
	}
}

// WithProfileStore sets a custom profile store.
func WithProfileStore(store ProfileStore) Option {
	return func(s *AuthService) error {
		s.profileStore = store
		return nil
	}
}

// WithSecrets sets the cryptographic secrets.
func WithSecrets(secrets Secrets) Option {
	return func(s *AuthService) error {
		if len(secrets.JWTSecret) != 32 {
			return ErrInvalidSecretLength
		}
		if len(secrets.EncryptionKey) != 32 {
			return ErrInvalidSecretLength
		}
		if len(secrets.Pepper) != 32 {
			return ErrInvalidSecretLength
		}

		s.jwtSecret = secrets.JWTSecret
		s.pepper = secrets.Pepper

		keys, err := crypto.DeriveKeys(secrets.EncryptionKey)
		if err != nil {
			return err
		}
		s.keys = &keys
		return nil
	}
}

// ==================== OPTIONAL PROVIDERS ====================

// WithLogger sets a custom logger.
func WithLogger(logger *zap.Logger) Option {
	return func(s *AuthService) error {
		s.logger = logger
		return nil
	}
}

// WithMailer sets a custom mailer.
func WithMailer(mailer Mailer) Option {
	return func(s *AuthService) error {
		s.mailer = mailer
		return nil
	}
}

// WithResend sets up Resend email provider.
func WithResend(apiKey, fromEmail, fromName string) Option {
	return func(s *AuthService) error {
		s.mailer = resend.New(apiKey, fromEmail, fromName)
		return nil
	}
}

// WithSMTP sets up SMTP email provider.
func WithSMTP(cfg smtpmailer.Config) Option {
	return func(s *AuthService) error {
		s.mailer = smtpmailer.New(cfg)
		return nil
	}
}

// WithSendGrid sets up SendGrid email provider.
func WithSendGrid(apiKey, fromEmail, fromName string) Option {
	return func(s *AuthService) error {
		s.mailer = sendgrid.New(apiKey, fromEmail, fromName)
		return nil
	}
}

// WithMailgun sets up Mailgun email provider.
func WithMailgun(apiKey, domain, fromEmail, fromName string) Option {
	return func(s *AuthService) error {
		s.mailer = mailgun.New(apiKey, domain, fromEmail, fromName)
		return nil
	}
}

// WithRateLimiter sets a custom rate limiter.
func WithRateLimiter(limiter RateLimiter) Option {
	return func(s *AuthService) error {
		s.limiter = limiter
		return nil
	}
}

// WithRedis sets up Redis for rate limiting.
func WithRedis(client *redis.Client) Option {
	return func(s *AuthService) error {
		s.limiter = redislimiter.New(client)
		return nil
	}
}

// ==================== OAUTH PROVIDERS ====================

// WithGoogle adds Google OAuth provider.
func WithGoogle(clientID, clientSecret string) Option {
	return func(s *AuthService) error {
		s.oauth["google"] = NewGoogleProvider(clientID, clientSecret)
		return nil
	}
}

// WithDiscord adds Discord OAuth provider.
func WithDiscord(clientID, clientSecret string) Option {
	return func(s *AuthService) error {
		s.oauth["discord"] = NewDiscordProvider(clientID, clientSecret)
		return nil
	}
}

// WithGitHub adds GitHub OAuth provider.
func WithGitHub(clientID, clientSecret string) Option {
	return func(s *AuthService) error {
		s.oauth["github"] = NewGitHubProvider(clientID, clientSecret)
		return nil
	}
}

// WithMicrosoft adds Microsoft OAuth provider.
func WithMicrosoft(clientID, clientSecret string) Option {
	return func(s *AuthService) error {
		s.oauth["microsoft"] = NewMicrosoftProvider(clientID, clientSecret)
		return nil
	}
}

// WithTwitch adds Twitch OAuth provider.
func WithTwitch(clientID, clientSecret string) Option {
	return func(s *AuthService) error {
		s.oauth["twitch"] = NewTwitchProvider(clientID, clientSecret)
		return nil
	}
}

// WithOAuth adds a custom OAuth provider.
func WithOAuth(provider OAuthProvider) Option {
	return func(s *AuthService) error {
		s.oauth[provider.Name()] = provider
		return nil
	}
}

// WithOAuthSuccessHandler sets a custom handler for successful OAuth authentication.
func WithOAuthSuccessHandler(handler func(http.ResponseWriter, *http.Request, string, *OAuthUser, *OAuthTokens) bool) Option {
	return func(s *AuthService) error {
		s.config.OAuthSuccessHandler = handler
		return nil
	}
}

// ==================== CONFIGURATION ====================

// WithConfig sets a complete configuration.
func WithConfig(cfg Config) Option {
	return func(s *AuthService) error {
		s.config = cfg
		return nil
	}
}

// WithAppName sets the application name.
func WithAppName(name string) Option {
	return func(s *AuthService) error {
		s.config.AppName = name
		return nil
	}
}

// WithAppURL sets the application base URL.
func WithAppURL(url string) Option {
	return func(s *AuthService) error {
		s.config.AppBaseURL = url
		return nil
	}
}

// WithCallbackPath sets the OAuth callback base path (mounted path for /{provider}/callback).
func WithCallbackPath(path string) Option {
	return func(s *AuthService) error {
		s.config.CallbackPath = path
		return nil
	}
}

// ==================== FEATURE TOGGLES ====================

// WithEmailPassword enables/disables email+password auth.
func WithEmailPassword(enabled bool) Option {
	return func(s *AuthService) error {
		s.config.EmailPasswordEnabled = enabled
		return nil
	}
}

// WithEmailVerification enables/disables email verification requirement.
func WithEmailVerification(required bool) Option {
	return func(s *AuthService) error {
		s.config.EmailVerificationRequired = required
		return nil
	}
}

// WithEmailDomainCheck enables or disables MX validation for email domains.
func WithEmailDomainCheck(enabled bool) Option {
	return func(s *AuthService) error {
		s.config.EmailDomainCheck = enabled
		return nil
	}
}

// WithUsername enables/disables username support.
func WithUsername(enabled bool) Option {
	return func(s *AuthService) error {
		s.config.UsernameEnabled = enabled
		return nil
	}
}

// WithUsernameRequired enforces username on registration.
func WithUsernameRequired(required bool) Option {
	return func(s *AuthService) error {
		s.config.UsernameRequired = required
		return nil
	}
}

// WithUsernamePolicy configures username length rules.
func WithUsernamePolicy(minLength, maxLength int) Option {
	return func(s *AuthService) error {
		s.config.MinUsernameLength = minLength
		s.config.MaxUsernameLength = maxLength
		return nil
	}
}

// WithUsernamePattern enforces a regex pattern for usernames.
func WithUsernamePattern(pattern string) Option {
	return func(s *AuthService) error {
		s.config.UsernamePattern = pattern
		return nil
	}
}

// WithUsernameReserved configures reserved usernames.
func WithUsernameReserved(reserved []string) Option {
	return func(s *AuthService) error {
		s.config.UsernameReserved = reserved
		return nil
	}
}

// WithUsernameAllowNumericOnly allows usernames that are only digits.
func WithUsernameAllowNumericOnly(allowed bool) Option {
	return func(s *AuthService) error {
		s.config.UsernameAllowNumericOnly = allowed
		return nil
	}
}

// WithTOTP enables/disables 2FA.
func WithTOTP(enabled bool) Option {
	return func(s *AuthService) error {
		s.config.TOTPEnabled = enabled
		return nil
	}
}

// WithTOTPDigits sets the number of digits for TOTP (6 or 8).
func WithTOTPDigits(digits int) Option {
	return func(s *AuthService) error {
		s.config.TOTPDigits = digits
		return nil
	}
}

// WithTOTPAccountName sets a fixed account name for TOTP entries.
func WithTOTPAccountName(name string) Option {
	return func(s *AuthService) error {
		s.config.TOTPAccountName = name
		return nil
	}
}

// WithTOTPUseUsername uses the username (when present) for TOTP account name.
func WithTOTPUseUsername(enabled bool) Option {
	return func(s *AuthService) error {
		s.config.TOTPUseUsername = enabled
		return nil
	}
}

// WithTOTPQRCode enables or disables QR code generation in setup responses.
func WithTOTPQRCode(enabled bool) Option {
	return func(s *AuthService) error {
		s.config.TOTPQRCodeEnabled = enabled
		return nil
	}
}

// WithTOTPQRCodeSize sets the QR code size in pixels.
func WithTOTPQRCodeSize(size int) Option {
	return func(s *AuthService) error {
		s.config.TOTPQRCodeSize = size
		return nil
	}
}

// WithBackupCodeLength sets the length of backup codes.
func WithBackupCodeLength(length int) Option {
	return func(s *AuthService) error {
		s.config.BackupCodeLength = length
		return nil
	}
}

// WithBackupCodeDigitsOnly controls whether backup codes are numeric only.
func WithBackupCodeDigitsOnly(enabled bool) Option {
	return func(s *AuthService) error {
		s.config.BackupCodeDigitsOnly = enabled
		return nil
	}
}

// WithBackupCodeCount sets how many backup codes to generate.
func WithBackupCodeCount(count int) Option {
	return func(s *AuthService) error {
		s.config.BackupCodeCount = count
		return nil
	}
}

// WithPasswordReset enables/disables password reset.
func WithPasswordReset(enabled bool) Option {
	return func(s *AuthService) error {
		s.config.PasswordResetEnabled = enabled
		return nil
	}
}

// ==================== SECURITY ====================

// WithPasswordPolicy configures password requirements.
func WithPasswordPolicy(minLength int, requireComplexity bool, historySize int) Option {
	return func(s *AuthService) error {
		s.config.MinPasswordLength = minLength
		s.config.RequirePasswordComplexity = requireComplexity
		s.config.PasswordHistorySize = historySize
		return nil
	}
}

// WithBlockDisposableEmails enables or disables disposable email blocking.
func WithBlockDisposableEmails(enabled bool) Option {
	return func(s *AuthService) error {
		s.config.BlockDisposableEmails = enabled
		return nil
	}
}

// WithDisposableEmailDomains overrides the disposable email domain list.
func WithDisposableEmailDomains(domains []string) Option {
	return func(s *AuthService) error {
		s.config.DisposableEmailDomains = normalizeDomainList(domains)
		return nil
	}
}

// WithLockout configures account lockout.
func WithLockout(maxAttempts int, duration time.Duration) Option {
	return func(s *AuthService) error {
		s.config.MaxLoginAttempts = maxAttempts
		s.config.LockoutDuration = duration
		return nil
	}
}

// WithRateLimits sets rate limits for auth endpoints.
func WithRateLimits(cfg RateLimitConfig) Option {
	return func(s *AuthService) error {
		s.config.RateLimits = cfg
		return nil
	}
}

// WithIPBlock configures IP blocking behavior.
func WithIPBlock(cfg IPBlockConfig) Option {
	return func(s *AuthService) error {
		s.config.IPBlock = cfg
		return nil
	}
}

// WithRotateRefreshTokens enables refresh token rotation.
func WithRotateRefreshTokens(enabled bool) Option {
	return func(s *AuthService) error {
		s.config.RotateRefreshTokens = enabled
		return nil
	}
}

// WithRequireVerifiedEmailForAuth enforces verified email on protected routes.
func WithRequireVerifiedEmailForAuth(required bool) Option {
	return func(s *AuthService) error {
		s.config.RequireVerifiedEmailForAuth = required
		return nil
	}
}

// WithRequire2FAForAuth enforces 2FA on protected routes.
func WithRequire2FAForAuth(required bool) Option {
	return func(s *AuthService) error {
		s.config.Require2FAForAuth = required
		return nil
	}
}

// WithRequire2FAForOAuth enforces 2FA after OAuth login.
func WithRequire2FAForOAuth(required bool) Option {
	return func(s *AuthService) error {
		s.config.Require2FAForOAuth = required
		return nil
	}
}

// WithRequire2FAForMagicLink enforces 2FA after magic link login.
func WithRequire2FAForMagicLink(required bool) Option {
	return func(s *AuthService) error {
		s.config.Require2FAForMagicLink = required
		return nil
	}
}

// WithRequire2FAForSDK enforces 2FA before issuing SDK tokens.
func WithRequire2FAForSDK(required bool) Option {
	return func(s *AuthService) error {
		s.config.Require2FAForSDK = required
		return nil
	}
}

// WithRequire2FAForEmailChange enforces 2FA for email change requests.
func WithRequire2FAForEmailChange(required bool) Option {
	return func(s *AuthService) error {
		s.config.Require2FAForEmailChange = required
		return nil
	}
}

// WithOAuthEmailLinking configures OAuth email linking behavior.
func WithOAuthEmailLinking(allow bool, allowUnverified bool) Option {
	return func(s *AuthService) error {
		s.config.AllowOAuthEmailLinking = allow
		s.config.AllowUnverifiedOAuthEmailLinking = allowUnverified
		return nil
	}
}

// WithTrustedProxies enables trusted proxy parsing for client IPs.
func WithTrustedProxies(proxies []string) Option {
	return func(s *AuthService) error {
		s.config.TrustProxyHeaders = true
		s.config.TrustedProxies = proxies
		return nil
	}
}

// WithTrustProxyHeaders enables or disables proxy header parsing.
func WithTrustProxyHeaders(enabled bool) Option {
	return func(s *AuthService) error {
		s.config.TrustProxyHeaders = enabled
		return nil
	}
}

// WithUserAgentHashInLogs toggles user-agent hashing in audit logs.
func WithUserAgentHashInLogs(enabled bool) Option {
	return func(s *AuthService) error {
		s.config.StoreUserAgentHash = enabled
		return nil
	}
}

// WithMaxPasskeysPerUser limits the number of passkeys per user (0 = unlimited).
func WithMaxPasskeysPerUser(limit int) Option {
	return func(s *AuthService) error {
		s.config.WebAuthn.MaxPasskeysPerUser = limit
		return nil
	}
}

// WithAllowPasskeysForRoles restricts passkey registration to specific roles.
func WithAllowPasskeysForRoles(roles ...Role) Option {
	return func(s *AuthService) error {
		s.config.WebAuthn.AllowPasskeysForRoles = roles
		return nil
	}
}

// WithNotifyOnPasswordChange enables password change notifications.
func WithNotifyOnPasswordChange(enabled bool) Option {
	return func(s *AuthService) error {
		s.config.NotifyOnPasswordChange = enabled
		return nil
	}
}

// WithNotifyOnEmailChange enables email change notifications.
func WithNotifyOnEmailChange(enabled bool) Option {
	return func(s *AuthService) error {
		s.config.NotifyOnEmailChange = enabled
		return nil
	}
}

// WithEmailChangeTTL sets the email change token TTL.
func WithEmailChangeTTL(ttl time.Duration) Option {
	return func(s *AuthService) error {
		s.config.EmailChangeTTL = ttl
		return nil
	}
}

// WithHIBP enables password breach checking.
func WithHIBP() Option {
	return func(s *AuthService) error {
		s.config.HIBPEnabled = true
		return nil
	}
}

// WithHIBPAPIURL overrides the Have I Been Pwned API URL.
func WithHIBPAPIURL(url string) Option {
	return func(s *AuthService) error {
		s.config.HIBPAPIURL = url
		return nil
	}
}

// ==================== PRIVACY ====================

// WithIPPrivacy configures IP address handling.
func WithIPPrivacy(cfg IPPrivacyConfig) Option {
	return func(s *AuthService) error {
		s.config.IPPrivacy = cfg
		return nil
	}
}

// WithoutIPStorage disables IP storage entirely.
func WithoutIPStorage() Option {
	return func(s *AuthService) error {
		s.config.IPPrivacy.StoreIP = false
		return nil
	}
}

// WithIPRetention sets IP retention period in days.
func WithIPRetention(days int) Option {
	return func(s *AuthService) error {
		s.config.IPPrivacy.IPRetentionDays = days
		return nil
	}
}

// CaptchaPolicy controls where CAPTCHA is enforced.
type CaptchaPolicy struct {
	Required       bool
	OnRegister     bool
	OnLogin        bool
	OnPasswordReset bool
	OnMagicLink    bool
}

// WithCaptchaPolicy configures CAPTCHA enforcement.
func WithCaptchaPolicy(policy CaptchaPolicy) Option {
	return func(s *AuthService) error {
		s.config.CaptchaRequired = policy.Required
		s.config.CaptchaOnRegister = policy.OnRegister
		s.config.CaptchaOnLogin = policy.OnLogin
		s.config.CaptchaOnPasswordReset = policy.OnPasswordReset
		s.config.CaptchaOnMagicLink = policy.OnMagicLink
		return nil
	}
}

// WithAuditRetention sets audit log retention period.
func WithAuditRetention(d time.Duration) Option {
	return func(s *AuthService) error {
		s.config.AuditLogRetention = d
		return nil
	}
}

// WithUnverifiedAccountTTL sets how long unverified accounts can remain.
func WithUnverifiedAccountTTL(ttl time.Duration) Option {
	return func(s *AuthService) error {
		s.config.UnverifiedAccountTTL = ttl
		return nil
	}
}

// ==================== TOKENS ====================

// WithTokenTTL sets token lifetimes.
func WithTokenTTL(access, refresh time.Duration) Option {
	return func(s *AuthService) error {
		s.config.AccessTokenTTL = access
		s.config.RefreshTokenTTL = refresh
		return nil
	}
}

// ==================== ENTERPRISE FEATURES ====================

// All enterprise options are defined in enterprise.go:
// - WithMultiTenant(store TenantStore)
// - WithDeviceManagement(store DeviceStore)
// - WithWebhooks(store WebhookStore)
// - WithAPIKeys(store APIKeyStore)
// - WithMagicLinks()

// Token blacklist options are defined in blacklist.go:
// - WithTokenBlacklist(bl TokenBlacklist)
// - WithRedisBlacklist(client *redis.Client)
// - WithMemoryBlacklist()

// CAPTCHA options are defined in captcha.go:
// - WithCaptcha(provider CaptchaProvider)
// - WithTurnstile(secret string)
// - WithReCaptcha(secret string)
// - WithReCaptchaV3(secret string, minScore float64)
// - WithHCaptcha(secret string)
// - WithCaptchaRequired(required bool)
// - WithCaptchaFailOpen(enabled bool)

// Environment options are defined in env.go:
// - WithSecretsFromEnv()
// - WithSecretsFromVault(cfg VaultConfig)
// - WithSecretsFromVaultEnv()

// RBAC options are defined in rbac.go:
// - WithRolePermissions(rp map[Role][]Permission)

// Security options are defined in security.go:
// - WithSecurityMonitor(monitor SecurityMonitor)
// - WithIPIntelligence(provider IPIntelligence)

