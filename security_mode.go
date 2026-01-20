package goauth

import (
	"errors"
	"strings"
	"time"
)

// SecurityMode defines preset security configurations.
type SecurityMode string

const (
	SecurityModePermissive SecurityMode = "permissive"
	SecurityModeBalanced   SecurityMode = "balanced"
	SecurityModeStrict     SecurityMode = "strict"
)

// WithSecurityMode applies a preset security configuration.
func WithSecurityMode(mode SecurityMode) Option {
	return func(s *AuthService) error {
		if mode == "" {
			return nil
		}
		return applySecurityMode(&s.config, mode)
	}
}

func applySecurityMode(cfg *Config, mode SecurityMode) error {
	switch strings.ToLower(strings.TrimSpace(string(mode))) {
	case string(SecurityModePermissive):
		cfg.EmailVerificationRequired = false
		cfg.RequireVerifiedEmailForAuth = false
		cfg.Require2FAForAuth = false
		cfg.Require2FAForOAuth = false
		cfg.Require2FAForMagicLink = false
		cfg.Require2FAForSDK = false
		cfg.Require2FAForEmailChange = false
		cfg.PasswordHistorySize = 0
		cfg.MinPasswordLength = 8
		cfg.RequirePasswordComplexity = false
		cfg.CaptchaRequired = false
		cfg.CaptchaFailOpen = true
		cfg.BlockDisposableEmails = false
		cfg.EmailDomainCheck = false
		cfg.IPBlock.Enabled = false
		return nil
	case string(SecurityModeBalanced):
		cfg.EmailVerificationRequired = true
		cfg.RequireVerifiedEmailForAuth = true
		cfg.Require2FAForOAuth = true
		cfg.MinPasswordLength = 10
		cfg.PasswordHistorySize = 3
		cfg.RequirePasswordComplexity = true
		cfg.RotateRefreshTokens = true
		cfg.CaptchaRequired = true
		cfg.CaptchaOnRegister = true
		cfg.CaptchaOnLogin = true
		cfg.CaptchaOnPasswordReset = true
		cfg.CaptchaOnMagicLink = false
		cfg.CaptchaFailOpen = false
		cfg.BlockDisposableEmails = true
		cfg.EmailDomainCheck = true
		cfg.IPBlock.Enabled = true
		cfg.IPBlock.FailureThreshold = 10
		cfg.IPBlock.FailureWindow = 15 * time.Minute
		cfg.IPBlock.BlockDuration = 30 * time.Minute
		return nil
	case string(SecurityModeStrict):
		cfg.EmailVerificationRequired = true
		cfg.RequireVerifiedEmailForAuth = true
		cfg.Require2FAForAuth = true
		cfg.Require2FAForOAuth = true
		cfg.Require2FAForMagicLink = true
		cfg.Require2FAForSDK = true
		cfg.Require2FAForEmailChange = true
		cfg.MinPasswordLength = 12
		cfg.PasswordHistorySize = 5
		cfg.RequirePasswordComplexity = true
		cfg.RotateRefreshTokens = true
		cfg.MaxLoginAttempts = 3
		cfg.LockoutDuration = 30 * time.Minute
		cfg.CaptchaRequired = true
		cfg.CaptchaOnRegister = true
		cfg.CaptchaOnLogin = true
		cfg.CaptchaOnPasswordReset = true
		cfg.CaptchaOnMagicLink = true
		cfg.CaptchaFailOpen = false
		cfg.BlockDisposableEmails = true
		cfg.EmailDomainCheck = true
		cfg.IPBlock.Enabled = true
		cfg.IPBlock.FailureThreshold = 5
		cfg.IPBlock.FailureWindow = 10 * time.Minute
		cfg.IPBlock.BlockDuration = 1 * time.Hour
		cfg.RateLimits.LoginLimit = 5
		cfg.RateLimits.LoginWindow = time.Minute
		cfg.RateLimits.RegisterLimit = 3
		cfg.RateLimits.RegisterWindow = time.Hour
		cfg.RateLimits.PasswordResetLimit = 2
		cfg.RateLimits.PasswordResetWindow = time.Hour
		cfg.RateLimits.MagicLinkLimit = 2
		cfg.RateLimits.MagicLinkWindow = time.Hour
		return nil
	default:
		return errors.New("goauth: unknown security mode: " + string(mode))
	}
}
