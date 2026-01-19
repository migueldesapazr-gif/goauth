package crypto

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenType represents the type of JWT token.
type TokenType string

const (
	TokenTypeAccess  TokenType = "access"
	TokenTypeRefresh TokenType = "refresh"
	TokenType2FA     TokenType = "2fa"
)

// Claims represents the JWT claims.
type Claims struct {
	jwt.RegisteredClaims
	EmailVerified bool      `json:"email_verified,omitempty"`
	TwoFAVerified bool      `json:"two_fa_verified,omitempty"`
	DeviceID      string    `json:"device_id,omitempty"`
	Scope         string    `json:"scope,omitempty"`
	TokenType     TokenType `json:"type,omitempty"`
}

// AccessTokenOptions configures optional access token claims.
type AccessTokenOptions struct {
	// JTI is the token identifier; if empty, a random value is generated.
	JTI string
	// DeviceID associates the token with a device/session.
	DeviceID string
	// Scope is a space-delimited scope string.
	Scope string
}

// NewAccessToken creates a new access token.
func NewAccessToken(secret []byte, userID string, emailVerified, twoFAVerified bool, ttl time.Duration) (string, error) {
	return NewAccessTokenWithOptions(secret, userID, emailVerified, twoFAVerified, ttl, AccessTokenOptions{})
}

// NewAccessTokenWithOptions creates a new access token with extra claims.
func NewAccessTokenWithOptions(secret []byte, userID string, emailVerified, twoFAVerified bool, ttl time.Duration, opts AccessTokenOptions) (string, error) {
	now := time.Now()
	jti := opts.JTI
	if jti == "" {
		var err error
		jti, err = RandomToken(16)
		if err != nil {
			return "", err
		}
	}
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		EmailVerified: emailVerified,
		TwoFAVerified: twoFAVerified,
		DeviceID:      opts.DeviceID,
		Scope:         opts.Scope,
		TokenType:     TokenTypeAccess,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// NewRefreshToken creates a new refresh token.
func NewRefreshToken(secret []byte, userID, jti string, ttl time.Duration) (string, error) {
	return NewRefreshTokenWithOptions(secret, userID, ttl, RefreshTokenOptions{JTI: jti})
}

// RefreshTokenOptions configures optional refresh token claims.
type RefreshTokenOptions struct {
	JTI           string
	EmailVerified bool
	TwoFAVerified bool
	DeviceID      string
	Scope         string
}

// NewRefreshTokenWithOptions creates a refresh token with extra claims.
func NewRefreshTokenWithOptions(secret []byte, userID string, ttl time.Duration, opts RefreshTokenOptions) (string, error) {
	now := time.Now()
	jti := opts.JTI
	if jti == "" {
		var err error
		jti, err = RandomToken(16)
		if err != nil {
			return "", err
		}
	}
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		EmailVerified: opts.EmailVerified,
		TwoFAVerified: opts.TwoFAVerified,
		DeviceID:      opts.DeviceID,
		Scope:         opts.Scope,
		TokenType: TokenTypeRefresh,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// NewTemp2FAToken creates a temporary token for 2FA flow.
func NewTemp2FAToken(secret []byte, userID string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		TokenType: TokenType2FA,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

// ParseToken parses and validates a JWT token.
func ParseToken(secret []byte, tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}
