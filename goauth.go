// Package goauth provides a secure, flexible authentication library for Go.
//
// Version: 1.0.0
//
// GoAuth is designed for:
//   - Web applications (browsers)
//   - Mobile apps (iOS, Android)
//   - Desktop apps (Electron, native)
//   - API services (service-to-service)
//   - Enterprise deployments (multi-tenant, RBAC)
//   - Startups (quick setup, sensible defaults)
//   - Privacy-focused applications (minimal data collection)
//
// Features:
//   - Email/password authentication with Argon2id hashing
//   - OAuth providers (Google, Discord, Microsoft, GitHub, etc.)
//   - Magic links (passwordless login)
//   - Two-factor authentication (TOTP with backup codes)
//   - API keys for service clients
//   - Device/session management
//   - Role-based access control (RBAC)
//   - Multi-tenant support
//   - Webhooks for event notifications
//   - GDPR compliance (data export, deletion)
//   - Configurable privacy settings
//   - Docker/Kubernetes ready
//
// Quick Start:
//
//	auth, _ := goauth.New(
//	    goauth.WithDatabase(db),
//	    goauth.WithSecrets(secrets),
//	)
//	r.Mount("/auth", auth.Handler())
//	jobs := auth.StartBackgroundJobs()
//	defer jobs.Stop(ctx)
package goauth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/migueldesapazr-gif/goauth/crypto"
)

// AuthService is the main entry point for the authentication library.
type AuthService struct {
	// Core dependencies
	store   Store
	mailer  Mailer
	limiter RateLimiter
	logger  *zap.Logger

	// Cryptographic material
	keys      *crypto.DerivedKeys
	jwtSecret []byte
	pepper    []byte

	// Configuration
	config Config

	// OAuth providers
	oauth map[string]OAuthProvider
	oauthTokenManager *OAuthTokenManager

	// Optional features
	tokenBlacklist  TokenBlacklist
	deviceStore     DeviceStore
	apiKeyStore     APIKeyStore
	tenantStore     TenantStore
	webhookStore    WebhookStore
	rolePermissions map[Role][]Permission
	captcha         CaptchaProvider
	securityMonitor SecurityMonitor
	ipIntel         IPIntelligence
	ipBlocker       IPBlocker
	profileStore    ProfileStore
	webauthnStore   WebAuthnStore

	trustedProxyNets []*net.IPNet

	// Background jobs
	jobs *BackgroundJobs
}

// Config holds the authentication service configuration.
type Config struct {
	// ==================== APP INFO ====================
	AppName      string
	AppBaseURL   string
	CallbackPath string

	// ==================== FEATURE TOGGLES ====================
	EmailPasswordEnabled      bool
	EmailVerificationRequired bool
	TOTPEnabled               bool
	PasswordResetEnabled      bool
	MagicLinksEnabled         bool
	APIKeysEnabled            bool
	DeviceManagementEnabled   bool

	// ==================== USERNAME ====================
	UsernameEnabled   bool
	UsernameRequired  bool
	MinUsernameLength int
	MaxUsernameLength int
	UsernamePattern   string
	UsernameReserved  []string
	UsernameAllowNumericOnly bool

	// ==================== TOKEN SETTINGS ====================
	AccessTokenTTL      time.Duration
	RefreshTokenTTL     time.Duration
	VerificationCodeTTL time.Duration
	PasswordResetTTL    time.Duration
	MagicLinkTTL        time.Duration
	EmailChangeTTL      time.Duration

	// ==================== 2FA/TOTP ====================
	TOTPDigits         int
	TOTPAccountName    string
	TOTPUseUsername    bool
	TOTPQRCodeEnabled  bool
	TOTPQRCodeSize     int
	BackupCodeLength   int
	BackupCodeDigitsOnly bool
	BackupCodeCount    int

	// ==================== SECURITY ====================
	MaxLoginAttempts          int
	LockoutDuration           time.Duration
	MaxVerificationAttempts   int
	PasswordHistorySize       int
	MinPasswordLength         int
	RequirePasswordComplexity bool
	RotateRefreshTokens       bool
	BlockDisposableEmails     bool
	DisposableEmailDomains    []string

	RequireVerifiedEmailForAuth bool
	Require2FAForAuth           bool
	Require2FAForOAuth          bool
	Require2FAForMagicLink      bool
	Require2FAForSDK            bool
	Require2FAForEmailChange    bool

	AllowOAuthEmailLinking           bool
	AllowUnverifiedOAuthEmailLinking bool

	TrustProxyHeaders bool
	TrustedProxies    []string

	RateLimits RateLimitConfig
	IPBlock    IPBlockConfig

	// ==================== PRIVACY ====================
	IPPrivacy            IPPrivacyConfig
	AuditLogRetention    time.Duration
	UnverifiedAccountTTL time.Duration
	StoreUserAgentHash   bool
	NotifyOnPasswordChange bool
	NotifyOnEmailChange    bool

	// ==================== EXTERNAL SERVICES ====================
	TurnstileEnabled   bool
	TurnstileSecret    string
	TurnstileVerifyURL string
	HIBPEnabled        bool
	HIBPAPIURL         string
	EmailDomainCheck   bool
	CaptchaFailOpen    bool
	CaptchaRequired    bool
	CaptchaOnRegister  bool
	CaptchaOnLogin     bool
	CaptchaOnPasswordReset bool
	CaptchaOnMagicLink bool

	// ==================== WEBAUTHN ====================
	WebAuthnEnabled bool
	WebAuthn        WebAuthnConfig

	// ==================== CLIENT TYPES ====================
	// Configure behavior for different client types
	WebClientConfig    ClientConfig
	MobileClientConfig ClientConfig
	APIClientConfig    ClientConfig
}

// ClientConfig holds configuration specific to client types.
type ClientConfig struct {
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	AllowRememberMe bool
	MaxDevices      int // 0 = unlimited
}

// IPPrivacyConfig controls how IP addresses are stored.
type IPPrivacyConfig struct {
	StoreIP         bool
	EncryptIP       bool
	HashIPInLogs    bool
	IPRetentionDays int
}

// Secrets holds cryptographic secrets.
type Secrets struct {
	JWTSecret     []byte
	EncryptionKey []byte
	Pepper        []byte
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		AppName:      "GoAuth",
		CallbackPath: "",

		// Features
		EmailPasswordEnabled:      true,
		EmailVerificationRequired: false,
		TOTPEnabled:               true,
		PasswordResetEnabled:      true,
		MagicLinksEnabled:         false,
		APIKeysEnabled:            false,
		DeviceManagementEnabled:   false,

		UsernameEnabled:   false,
		UsernameRequired:  false,
		MinUsernameLength: 3,
		MaxUsernameLength: 32,
		UsernamePattern:   "",
		UsernameReserved:  []string{"admin", "root", "support", "help", "staff", "system", "security", "api", "account", "billing"},
		UsernameAllowNumericOnly: false,

		// Tokens
		AccessTokenTTL:      15 * time.Minute,
		RefreshTokenTTL:     7 * 24 * time.Hour,
		VerificationCodeTTL: 15 * time.Minute,
		PasswordResetTTL:    1 * time.Hour,
		MagicLinkTTL:        15 * time.Minute,
		EmailChangeTTL:      30 * time.Minute,

		// 2FA/TOTP
		TOTPDigits:         6,
		TOTPAccountName:    "",
		TOTPUseUsername:    false,
		TOTPQRCodeEnabled:  true,
		TOTPQRCodeSize:     256,
		BackupCodeLength:   8,
		BackupCodeDigitsOnly: true,
		BackupCodeCount:    10,

		// Security
		MaxLoginAttempts:          5,
		LockoutDuration:           15 * time.Minute,
		MaxVerificationAttempts:   5,
		PasswordHistorySize:       0,
		MinPasswordLength:         8,
		RequirePasswordComplexity: true,
		RotateRefreshTokens:       true,
		BlockDisposableEmails:     false,
		DisposableEmailDomains:    nil,

		RequireVerifiedEmailForAuth: false,
		Require2FAForAuth:           false,
		Require2FAForOAuth:          true,
		Require2FAForMagicLink:      false,
		Require2FAForSDK:            false,
		Require2FAForEmailChange:    false,

		AllowOAuthEmailLinking:           true,
		AllowUnverifiedOAuthEmailLinking: false,

		TrustProxyHeaders: false,
		TrustedProxies:    nil,

		RateLimits: RateLimitConfig{
			LoginLimit:          10,
			LoginWindow:         time.Minute,
			TwoFALimit:          5,
			TwoFAWindow:         time.Minute,
			RegisterLimit:       5,
			RegisterWindow:      time.Hour,
			PasswordResetLimit:  3,
			PasswordResetWindow: time.Hour,
			MagicLinkLimit:      3,
			MagicLinkWindow:     time.Hour,
		},
		IPBlock: IPBlockConfig{
			Enabled:          false,
			FailureThreshold: 10,
			FailureWindow:    15 * time.Minute,
			BlockDuration:    30 * time.Minute,
		},

		// Privacy
		IPPrivacy: IPPrivacyConfig{
			StoreIP:         true,
			EncryptIP:       true,
			HashIPInLogs:    true,
			IPRetentionDays: 90,
		},
		AuditLogRetention:    365 * 24 * time.Hour,
		UnverifiedAccountTTL: 24 * time.Hour,
		StoreUserAgentHash:   true,
		NotifyOnPasswordChange: false,
		NotifyOnEmailChange:    false,

		// External
		TurnstileVerifyURL: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
		HIBPAPIURL:         "https://api.pwnedpasswords.com/range/",
		CaptchaRequired:    false,
		CaptchaFailOpen:    false,
		CaptchaOnRegister:  true,
		CaptchaOnLogin:     true,
		CaptchaOnPasswordReset: true,
		CaptchaOnMagicLink: false,

		// Client-specific defaults
		WebClientConfig: ClientConfig{
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 7 * 24 * time.Hour,
			AllowRememberMe: true,
			MaxDevices:      10,
		},
		MobileClientConfig: ClientConfig{
			AccessTokenTTL:  1 * time.Hour,
			RefreshTokenTTL: 30 * 24 * time.Hour,
			AllowRememberMe: true,
			MaxDevices:      5,
		},
		APIClientConfig: ClientConfig{
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 0, // API keys don't use refresh tokens
			AllowRememberMe: false,
			MaxDevices:      0,
		},
	}
}

// New creates a new AuthService.
func New(opts ...Option) (*AuthService, error) {
	svc := &AuthService{
		config: DefaultConfig(),
		oauth:  make(map[string]OAuthProvider),
	}

	for _, opt := range opts {
		if err := opt(svc); err != nil {
			return nil, err
		}
	}

	// Validate
	if svc.store == nil {
		return nil, errors.New("goauth: store is required (use WithStore or WithDatabase)")
	}
	if svc.keys == nil || len(svc.jwtSecret) == 0 {
		return nil, errors.New("goauth: secrets are required (use WithSecrets)")
	}

	// Defaults
	if svc.limiter == nil {
		svc.limiter = newMemoryRateLimiter()
	}
	if svc.ipBlocker == nil {
		svc.ipBlocker = newMemoryIPBlocker()
	}
	if svc.logger == nil {
		svc.logger, _ = zap.NewProduction()
	}
	if svc.mailer == nil {
		svc.mailer = &noopMailer{logger: svc.logger}
	}
	if svc.captcha == nil && svc.config.TurnstileEnabled {
		if svc.config.TurnstileSecret == "" {
			return nil, errors.New("goauth: turnstile enabled without secret")
		}
		svc.captcha = NewTurnstile(svc.config.TurnstileSecret)
	}
	if svc.captcha == nil && svc.config.CaptchaRequired {
		svc.logger.Warn("captcha required but no provider configured")
	}
	if svc.securityMonitor == nil {
		svc.securityMonitor = &defaultSecurityMonitor{logger: svc.logger, svc: svc}
	}
	if svc.oauthTokenManager == nil {
		svc.oauthTokenManager = svc.NewOAuthTokenManager()
	}

	if svc.config.TrustProxyHeaders && len(svc.config.TrustedProxies) > 0 {
		nets, err := parseTrustedProxies(svc.config.TrustedProxies)
		if err != nil {
			return nil, err
		}
		svc.trustedProxyNets = nets
	}

	return svc, nil
}

func parseTrustedProxies(values []string) ([]*net.IPNet, error) {
	if len(values) == 0 {
		return nil, nil
	}
	var nets []*net.IPNet
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, cidr, err := net.ParseCIDR(v); err == nil {
			nets = append(nets, cidr)
			continue
		}
		ip := net.ParseIP(v)
		if ip == nil {
			return nil, errors.New("goauth: invalid trusted proxy: " + v)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		mask := net.CIDRMask(bits, bits)
		nets = append(nets, &net.IPNet{IP: ip, Mask: mask})
	}
	return nets, nil
}

// Handler returns the HTTP handler with all routes.
func (s *AuthService) Handler() http.Handler {
	r := chi.NewRouter()

	// Health
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": "2.0"})
	})
	r.Get("/metrics", s.handleMetrics)

	// Email/Password
	if s.config.EmailPasswordEnabled {
		r.Post("/register", s.handleRegister)
		r.Post("/login", s.handleLogin)
		r.Post("/login/2fa", s.handleLogin2FA)
		r.Get("/email/change/confirm", s.handleEmailChangeConfirm)

		if s.config.EmailVerificationRequired {
			r.Post("/verify/code", s.handleVerifyCode)
			r.Get("/verify/link", s.handleVerifyLink)
		}

		if s.config.PasswordResetEnabled {
			r.Post("/password/reset/request", s.handlePasswordResetRequest)
			r.Post("/password/reset/confirm", s.handlePasswordResetConfirm)
		}
	}

	// Magic Links
	if s.config.MagicLinksEnabled {
		r.Post("/magic/request", s.handleMagicLinkRequest)
		r.Get("/magic", s.handleMagicLinkVerify)
	}

	// Token management
	r.Post("/refresh", s.handleRefresh)

	// WebAuthn public routes (login doesn't require auth)
	if s.config.WebAuthnEnabled {
		r.Post("/webauthn/login/begin", s.handleWebAuthnLoginBegin)
		r.Post("/webauthn/login/finish", s.handleWebAuthnLoginFinish)
	}

		// OAuth
		for name, provider := range s.oauth {
			r.Get("/"+name, s.handleOAuthRedirect(name, provider))
			r.Get("/"+name+"/callback", s.handleOAuthCallback(name, provider))
		}

	// Authenticated routes
	r.Group(func(r chi.Router) {
		r.Use(s.requireAuth)
		r.Post("/logout", s.handleLogout)
		r.Get("/me", s.handleMe)

		if s.config.EmailVerificationRequired {
			r.Post("/verify/send", s.handleVerifySend)
		}
		r.Post("/email/change/request", s.handleEmailChangeRequest)

		// 2FA
		if s.config.TOTPEnabled {
			r.Post("/2fa/setup", s.handleTwoFASetup)
			r.Post("/2fa/verify", s.handleTwoFAVerify)
			r.Post("/2fa/disable", s.handleTwoFADisable)
			r.Post("/2fa/backup-codes", s.handleBackupCodesRegenerate)
			r.Get("/2fa/backup-codes.txt", s.handleBackupCodesDownload)
		}

		// Devices
		if s.deviceStore != nil {
			r.Get("/devices", s.handleDevices)
			r.Post("/devices/revoke", s.handleRevokeDevice)
			r.Post("/devices/revoke-all", s.handleRevokeAllDevices)
		}

		// API Keys
		if s.apiKeyStore != nil {
			r.Post("/api-keys", s.handleCreateAPIKey)
			r.Get("/api-keys", s.handleListAPIKeys)
			r.Delete("/api-keys", s.handleRevokeAPIKey)
		}

		// OAuth connections
		r.Get("/oauth/connections", s.handleOAuthConnections)
		r.Post("/oauth/revoke", s.handleOAuthRevoke)

		// GDPR
		r.Get("/export", s.handleExportData)
		r.Get("/audit-logs", s.handleExportAuditLogs)
		r.Post("/delete-account", s.handleDeleteAccount)

		// WebAuthn/Passkeys
		if s.config.WebAuthnEnabled {
			r.Post("/webauthn/register/begin", s.handleWebAuthnRegisterBegin)
			r.Post("/webauthn/register/finish", s.handleWebAuthnRegisterFinish)
			r.Get("/webauthn/list", s.handleWebAuthnList)
			r.Delete("/webauthn/delete", s.handleWebAuthnDelete)
			r.Post("/webauthn/rename", s.handleWebAuthnRename)
		}

		// Profile
		if s.profileStore != nil {
			r.Get("/profile", s.handleProfileGet)
			r.Put("/profile", s.handleProfileUpdate)
		}
	})

	return r
}

// RequireAuth returns authentication middleware.
func (s *AuthService) RequireAuth() func(http.Handler) http.Handler {
	return s.requireAuth
}

// Store returns the underlying store.
func (s *AuthService) Store() Store {
	return s.store
}

// Config returns the configuration.
func (s *AuthService) Config() Config {
	return s.config
}

// Logger returns the logger.
func (s *AuthService) Logger() *zap.Logger {
	return s.logger
}

// ==================== INTERNAL HELPERS ====================

type noopMailer struct {
	logger *zap.Logger
}

func (m *noopMailer) SendVerification(ctx context.Context, to, code, link string) error {
	m.logger.Warn("email not configured", zap.String("type", "verification"), zap.String("to", to))
	return nil
}

func (m *noopMailer) SendPasswordReset(ctx context.Context, to, link string) error {
	m.logger.Warn("email not configured", zap.String("type", "password_reset"), zap.String("to", to))
	return nil
}

type memoryRateLimiter struct {
	entries map[string]*rateLimitEntry
	mu      sync.RWMutex
}

type rateLimitEntry struct {
	count   int
	expires time.Time
}

func newMemoryRateLimiter() *memoryRateLimiter {
	rl := &memoryRateLimiter{entries: make(map[string]*rateLimitEntry)}
	go rl.cleanup()
	return rl
}

func (r *memoryRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	e, exists := r.entries[key]

	if !exists || now.After(e.expires) {
		r.entries[key] = &rateLimitEntry{count: 1, expires: now.Add(window)}
		return true, limit - 1, nil
	}

	e.count++
	remaining := limit - e.count
	if remaining < 0 {
		remaining = 0
	}
	return e.count <= limit, remaining, nil
}

func (r *memoryRateLimiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		r.mu.Lock()
		now := time.Now()
		for key, e := range r.entries {
			if now.After(e.expires) {
				delete(r.entries, key)
			}
		}
		r.mu.Unlock()
	}
}

