package goauth

import (
	"context"
	"time"
)

// ==================== CORE INTERFACES ====================

// Store is the main storage interface.
type Store interface {
	Users() UserStore
	Tokens() TokenStore
	Audit() AuditStore
}

// UserStore handles user operations.
type UserStore interface {
	EmailExists(ctx context.Context, emailHash []byte) (bool, error)
	UsernameExists(ctx context.Context, usernameNormalized string) (bool, error)
	CreateUser(ctx context.Context, user User, verificationDeadline time.Time) (string, error)
	GetUserByEmailHash(ctx context.Context, emailHash []byte) (*User, error)
	GetUserByUsername(ctx context.Context, usernameNormalized string) (*User, error)
	GetUserByID(ctx context.Context, userID string) (*User, error)
	SetUserVerified(ctx context.Context, userID string) error
	IncrementLoginFailures(ctx context.Context, userID string) (int, error)
	LockUser(ctx context.Context, userID string) error
	UnlockUser(ctx context.Context, userID string) error
	ResetLoginFailures(ctx context.Context, userID string) error
	UpdateLastLogin(ctx context.Context, userID string, ipEnc, ipNonce []byte) error
	UpdateUsername(ctx context.Context, userID, username, usernameNormalized string) error
	UpdatePassword(ctx context.Context, userID string, hash, salt []byte) error
	UpdateEmail(ctx context.Context, userID string, emailHash, emailEnc, emailNonce []byte, verified bool) error
	RecentPasswordHistory(ctx context.Context, userID string, limit int) ([]PasswordHistory, error)
	UpdateTOTPSecret(ctx context.Context, userID string, secretEnc, secretNonce []byte) error
	EnableTOTP(ctx context.Context, userID string) error
	DisableTOTP(ctx context.Context, userID string) error
	ReplaceBackupCodes(ctx context.Context, userID string, hashes [][]byte) error
	UseBackupCode(ctx context.Context, userID string, codeHash []byte) (bool, error)
	UpdateUserRole(ctx context.Context, userID string, role string) error
}

// TokenStore handles token operations.
type TokenStore interface {
	CreateVerificationToken(ctx context.Context, token VerificationToken, ipEnc, ipNonce []byte) (string, error)
	GetActiveVerificationToken(ctx context.Context, userID string) (*VerificationToken, error)
	GetVerificationTokenByLinkHash(ctx context.Context, linkHash []byte) (*VerificationToken, error)
	IncrementVerificationAttempts(ctx context.Context, tokenID string) (int, error)
	MarkVerificationTokenUsed(ctx context.Context, tokenID string, ipEnc, ipNonce []byte) error
	CreatePasswordResetToken(ctx context.Context, token PasswordResetToken, ipEnc, ipNonce []byte) (string, error)
	GetPasswordResetTokenByHash(ctx context.Context, tokenHash []byte) (*PasswordResetToken, error)
	MarkPasswordResetUsed(ctx context.Context, tokenID string, ipEnc, ipNonce []byte) error
	CreateEmailChangeToken(ctx context.Context, token EmailChangeToken, ipEnc, ipNonce []byte) (string, error)
	GetEmailChangeTokenByHash(ctx context.Context, tokenHash []byte) (*EmailChangeToken, error)
	MarkEmailChangeUsed(ctx context.Context, tokenID string, ipEnc, ipNonce []byte) error
	StoreRefreshToken(ctx context.Context, userID, jti string, expiresAt time.Time, ipEnc, ipNonce []byte) error
	RefreshTokenValid(ctx context.Context, jti string) (bool, error)
	RevokeRefreshToken(ctx context.Context, jti string) error
	RevokeAllRefreshTokens(ctx context.Context, userID string) error
}

// AuditStore handles audit logging.
type AuditStore interface {
	InsertAuditLog(ctx context.Context, log AuditLog) error
	GetUserAuditLogs(ctx context.Context, userID string, limit int) ([]AuditLog, error)
}

// ProfileStore handles user profiles.
type ProfileStore interface {
	GetProfile(ctx context.Context, userID string) (*Profile, error)
	UpsertProfile(ctx context.Context, profile Profile) error
	DeleteProfile(ctx context.Context, userID string) error
}

// ProfileProvider exposes a profile store when supported.
type ProfileProvider interface {
	Profiles() ProfileStore
}

// OAuthConnectionStore manages OAuth provider links.
type OAuthConnectionStore interface {
	GetUserByOAuthProvider(ctx context.Context, provider, providerUserID string) (*User, error)
	LinkOAuthConnection(ctx context.Context, userID, provider, providerUserID string) error
	UnlinkOAuthConnection(ctx context.Context, userID, provider string) error
	GetUserOAuthConnections(ctx context.Context, userID string) ([]OAuthConnection, error)
}

// Mailer sends emails.
type Mailer interface {
	SendVerification(ctx context.Context, to, code, link string) error
	SendPasswordReset(ctx context.Context, to, link string) error
}

// RateLimiter provides rate limiting.
type RateLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (allowed bool, remaining int, err error)
}

// ==================== MODELS ====================

// User represents an authenticated user.
type User struct {
	ID                   string
	EmailHash            []byte
	EmailEncrypted       []byte
	EmailNonce           []byte
	Username             string
	UsernameNormalized   string
	PasswordHash         []byte
	PasswordSalt         []byte
	TOTPSecretEncrypted  []byte
	TOTPNonce            []byte
	TOTPEnabled          bool
	EmailVerified        bool
	AccountStatus        string
	Role                 string
	FailedLoginAttempts  int
	LockedAt             *time.Time
	LastLoginAt          *time.Time
	LastLoginIPEncrypted []byte
	LastLoginIPNonce     []byte
	CreatedAt            time.Time
	UpdatedAt            time.Time
	Metadata             map[string]any
}

// Profile represents user profile data stored separately from auth records.
type Profile struct {
	UserID           string
	DisplayName      string
	DisplayPhotoURL  string
	Bio              string
	Locale           string
	Timezone         string
	Metadata         map[string]any
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// Account statuses
const (
	StatusActive              = "active"
	StatusPendingVerification = "pending_verification"
	StatusLocked              = "locked"
	StatusSuspended           = "suspended"
	StatusDeleted             = "deleted"
)

// VerificationToken for email verification.
type VerificationToken struct {
	ID           string
	UserID       string
	CodeHash     []byte
	LinkHash     []byte
	EmailHash    []byte
	ExpiresAt    time.Time
	CodeAttempts int
	MaxAttempts  int
	Used         bool
}

// PasswordResetToken for password resets.
type PasswordResetToken struct {
	ID        string
	UserID    string
	TokenHash []byte
	ExpiresAt time.Time
	Used      bool
}

// EmailChangeToken for email change confirmation.
type EmailChangeToken struct {
	ID               string
	UserID           string
	TokenHash        []byte
	NewEmailHash     []byte
	NewEmailEncrypted []byte
	NewEmailNonce    []byte
	ExpiresAt        time.Time
	Used             bool
}

// PasswordHistory for preventing password reuse.
type PasswordHistory struct {
	Hash []byte
	Salt []byte
}

// AuditLog records security events.
type AuditLog struct {
	ID            string
	UserID        string
	TenantID      string
	EventType     string
	IPEncrypted   []byte
	IPNonce       []byte
	UserAgentHash []byte
	Metadata      map[string]any
	MetadataEnc   []byte
	MetadataNonce []byte
	ExpiresAt     time.Time
	CreatedAt     time.Time
}

// Audit event types
const (
	EventRegister             = "register"
	EventLoginSuccess         = "login_success"
	EventLoginFailed          = "login_failed"
	EventLogout               = "logout"
	EventPasswordChanged      = "password_changed"
	EventPasswordResetRequest = "password_reset_request"
	EventPasswordResetComplete= "password_reset_complete"
	EventEmailVerified        = "email_verified"
	EventEmailChanged         = "email_changed"
	Event2FAEnabled           = "2fa_enabled"
	Event2FADisabled          = "2fa_disabled"
	EventAccountLocked        = "account_locked"
	EventAccountUnlocked      = "account_unlocked"
	EventAPIKeyCreated        = "api_key_created"
	EventAPIKeyRevoked        = "api_key_revoked"
	EventDeviceRevoked        = "device_revoked"
	EventSuspiciousActivity   = "suspicious_activity"
)

// ==================== OAUTH ====================

// OAuthProvider interface for OAuth authentication.
type OAuthProvider interface {
	Name() string
	AuthURL(state, redirectURL string) string
	ExchangeCode(ctx context.Context, code, redirectURL string) (*OAuthTokens, error)
	GetUser(ctx context.Context, accessToken string) (*OAuthUser, error)
}

// OAuthTokens from provider.
type OAuthTokens struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int
	TokenType    string
}

// OAuthUser from provider.
type OAuthUser struct {
	ID            string
	Email         string
	EmailVerified bool
	Name          string
	Avatar        string
	Raw           map[string]any
}

// OAuthConnection links a user to an OAuth provider.
type OAuthConnection struct {
	ID           string
	UserID       string
	Provider     string
	ProviderID   string
	AccessToken  []byte // Encrypted
	RefreshToken []byte // Encrypted
	ExpiresAt    *time.Time
	CreatedAt    time.Time
}
