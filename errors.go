package goauth

import (
	"errors"
	"fmt"
)

// Configuration errors.
var (
	ErrInvalidJWTSecret = errors.New("goauth: JWT secret must be exactly 32 bytes")
	ErrInvalidMEK       = errors.New("goauth: MEK (Master Encryption Key) must be exactly 32 bytes")
	ErrInvalidPepper    = errors.New("goauth: pepper must be exactly 32 bytes")
	ErrInvalidSecretLength = errors.New("goauth: secrets must be exactly 32 bytes")
	ErrStoreNotConfigured = errors.New("goauth: store is required but not configured")
	ErrMailerNotConfigured = errors.New("goauth: mailer is required for this operation but not configured")
)

// Authentication errors - these are safe to show to users.
var (
	ErrInvalidCredentials    = errors.New("invalid email or password")
	ErrAccountLocked         = errors.New("account is locked due to too many failed attempts")
	ErrAccountNotVerified    = errors.New("email not verified")
	ErrAccountSuspended      = errors.New("account is suspended")
	ErrEmailAlreadyExists    = errors.New("email already registered")
	ErrUsernameAlreadyExists = errors.New("username already in use")
	ErrInvalidEmail          = errors.New("invalid email address")
	ErrDisposableEmail       = errors.New("disposable email addresses are not allowed")
	ErrInvalidUsername       = errors.New("invalid username")
	ErrWeakPassword          = errors.New("password does not meet security requirements")
	ErrPasswordBreached      = errors.New("password found in data breach, please choose another")
	ErrPasswordReused        = errors.New("cannot reuse recent passwords")
	ErrInvalidToken          = errors.New("invalid or expired token")
	ErrTokenExpired          = errors.New("token has expired")
	ErrTooManyAttempts       = errors.New("too many attempts, please try again later")
	ErrVerificationRequired  = errors.New("email verification required")
	Err2FARequired           = errors.New("two-factor authentication required")
	ErrInvalid2FACode        = errors.New("invalid verification code")
	Err2FAAlreadyEnabled     = errors.New("two-factor authentication is already enabled")
	Err2FANotEnabled         = errors.New("two-factor authentication is not enabled")
	ErrInvalidCaptcha        = errors.New("captcha verification failed")
	ErrRateLimited           = errors.New("rate limit exceeded, please try again later")
	ErrProfileNotFound       = errors.New("profile not found")
	ErrIPBlocked             = errors.New("ip temporarily blocked")
	ErrPasskeyLimitReached   = errors.New("maximum number of passkeys reached")
	ErrPasskeyNotAllowed     = errors.New("passkey registration not allowed for this role")
	ErrInvalidPasskey        = errors.New("invalid passkey")
	ErrMagicLinkExpired      = errors.New("magic link has expired")
	ErrMagicLinkUsed         = errors.New("magic link has already been used")
)

// Internal errors - these should be logged but not shown to users.
var (
	ErrInternal         = errors.New("internal server error")
	ErrDatabaseError    = errors.New("database error")
	ErrEncryptionError  = errors.New("encryption error")
	ErrEmailSendError   = errors.New("failed to send email")
	ErrCaptchaService   = errors.New("captcha service error")
)

// AuthError wraps an error with additional context for API responses.
type AuthError struct {
	// Code is a machine-readable error code
	Code string `json:"code"`
	// Message is a human-readable error message safe for users
	Message string `json:"message"`
	// Internal is the underlying error (not included in JSON)
	Internal error `json:"-"`
}

func (e *AuthError) Error() string {
	if e.Internal != nil {
		return e.Internal.Error()
	}
	return e.Message
}

func (e *AuthError) Unwrap() error {
	return e.Internal
}

// Is implements errors.Is for AuthError comparison.
func (e *AuthError) Is(target error) bool {
	t, ok := target.(*AuthError)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

// Error codes for API responses.
const (
	CodeInvalidCredentials   = "INVALID_CREDENTIALS"
	CodeAccountLocked        = "ACCOUNT_LOCKED"
	CodeAccountNotVerified   = "ACCOUNT_NOT_VERIFIED"
	CodeAccountSuspended     = "ACCOUNT_SUSPENDED"
	CodeEmailExists          = "EMAIL_EXISTS"
	CodeUsernameExists       = "USERNAME_EXISTS"
	CodeInvalidEmail         = "INVALID_EMAIL"
	CodeDisposableEmail      = "DISPOSABLE_EMAIL"
	CodeInvalidUsername      = "INVALID_USERNAME"
	CodeWeakPassword         = "WEAK_PASSWORD"
	CodePasswordBreached     = "PASSWORD_BREACHED"
	CodePasswordReused       = "PASSWORD_REUSED"
	CodeInvalidToken         = "INVALID_TOKEN"
	CodeTokenExpired         = "TOKEN_EXPIRED"
	CodeTooManyAttempts      = "TOO_MANY_ATTEMPTS"
	CodeVerificationRequired = "VERIFICATION_REQUIRED"
	Code2FARequired          = "2FA_REQUIRED"
	CodeInvalid2FACode       = "INVALID_2FA_CODE"
	Code2FAAlreadyEnabled    = "2FA_ALREADY_ENABLED"
	Code2FANotEnabled        = "2FA_NOT_ENABLED"
	CodeInvalidCaptcha       = "INVALID_CAPTCHA"
	CodeRateLimited          = "RATE_LIMITED"
	CodeIPBlocked            = "IP_BLOCKED"
	CodeInternalError        = "INTERNAL_ERROR"
	CodeBadRequest           = "BAD_REQUEST"
	CodePasskeyLimit         = "PASSKEY_LIMIT_REACHED"
	CodePasskeyNotAllowed    = "PASSKEY_NOT_ALLOWED"
	CodeInvalidPasskey       = "INVALID_PASSKEY"
	CodeMagicLinkExpired     = "MAGIC_LINK_EXPIRED"
	CodeMagicLinkUsed        = "MAGIC_LINK_USED"
)

// newAuthError creates a new AuthError.
func newAuthError(code string, message string, internal error) *AuthError {
	return &AuthError{
		Code:     code,
		Message:  message,
		Internal: internal,
	}
}

// wrapError wraps an error with additional context.
// Use this for internal error wrapping with context.
func wrapError(err error, context string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", context, err)
}

// isNotFoundError checks if an error indicates a "not found" condition.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return msg == "user not found" || msg == "token not found" || msg == "profile not found"
}
