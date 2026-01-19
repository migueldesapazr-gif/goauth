package goauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/migueldesapazr-gif/goauth/crypto"
)

// ==================== DEVICE MANAGEMENT ====================

// Device represents a user's authenticated device/session.
type Device struct {
	ID           string
	UserID       string
	Name         string    // "Chrome on Windows", "iPhone 15"
	DeviceType   string    // "browser", "mobile", "desktop", "api"
	LastIP       string    // Last seen IP (encrypted or hashed based on config)
	LastIPNonce  []byte
	LastActive   time.Time
	CreatedAt    time.Time
	RefreshToken string    // JTI of the associated refresh token
	TrustLevel   string    // "untrusted", "trusted", "remembered"
	Fingerprint  string    // Device fingerprint hash
}

// DeviceStore handles device/session management.
type DeviceStore interface {
	// CreateDevice creates a new device entry.
	CreateDevice(ctx context.Context, device Device) error
	// GetUserDevices returns all devices for a user.
	GetUserDevices(ctx context.Context, userID string) ([]Device, error)
	// GetDevice returns a specific device.
	GetDevice(ctx context.Context, deviceID string) (*Device, error)
	// UpdateDeviceActivity updates last active time and IP.
	UpdateDeviceActivity(ctx context.Context, deviceID string, ip []byte, ipNonce []byte) error
	// RevokeDevice removes a device and its associated tokens.
	RevokeDevice(ctx context.Context, deviceID string) error
	// RevokeAllDevices removes all devices for a user except current.
	RevokeAllDevices(ctx context.Context, userID, exceptDeviceID string) error
	// TrustDevice marks a device as trusted (skip 2FA).
	TrustDevice(ctx context.Context, deviceID string, trustLevel string) error
}

// handleDevices returns the user's devices.
func (s *AuthService) handleDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	if s.deviceStore == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "device management not enabled")
		return
	}

	devices, err := s.deviceStore.GetUserDevices(ctx, user.ID)
	if err != nil {
		s.logger.Error("get devices error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	// Sanitize for response
	result := make([]map[string]any, len(devices))
	for i, d := range devices {
		result[i] = map[string]any{
			"id":          d.ID,
			"name":        d.Name,
			"device_type": d.DeviceType,
			"last_active": d.LastActive,
			"created_at":  d.CreatedAt,
			"trust_level": d.TrustLevel,
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"devices": result})
}

// handleRevokeDevice revokes a specific device.
func (s *AuthService) handleRevokeDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	if s.deviceStore == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "device management not enabled")
		return
	}

	var req struct {
		DeviceID string `json:"device_id"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request")
		return
	}

	// Verify device belongs to user
	device, err := s.deviceStore.GetDevice(ctx, req.DeviceID)
	if err != nil || device.UserID != user.ID {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "device not found")
		return
	}

	if err := s.deviceStore.RevokeDevice(ctx, req.DeviceID); err != nil {
		s.logger.Error("revoke device error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	// Also revoke refresh token
	if device.RefreshToken != "" {
		s.store.Tokens().RevokeRefreshToken(ctx, device.RefreshToken)
	}

	s.logAudit(ctx, user.ID, "device_revoked", r, map[string]any{"device_id": req.DeviceID})
	writeJSON(w, http.StatusOK, map[string]any{"message": "device revoked"})
}

// handleRevokeAllDevices revokes all devices except current.
func (s *AuthService) handleRevokeAllDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)
	claims, _ := GetClaimsFromContext(ctx)

	if s.deviceStore == nil {
		// Fall back to just revoking all refresh tokens
		s.store.Tokens().RevokeAllRefreshTokens(ctx, user.ID)
		writeJSON(w, http.StatusOK, map[string]any{"message": "all sessions revoked"})
		return
	}

	// Keep current device
	currentDeviceID := ""
	if claims != nil {
		currentDeviceID = claims.DeviceID
	}

	if err := s.deviceStore.RevokeAllDevices(ctx, user.ID, currentDeviceID); err != nil {
		s.logger.Error("revoke all devices error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	s.logAudit(ctx, user.ID, "all_devices_revoked", r, nil)
	writeJSON(w, http.StatusOK, map[string]any{"message": "all other devices revoked"})
}

// ==================== MAGIC LINKS ====================

// MagicLinkToken represents a passwordless login token.
type MagicLinkToken struct {
	ID        string
	UserID    string
	TokenHash []byte
	ExpiresAt time.Time
	Used      bool
	IPCreated []byte
	IPNonce   []byte
}

// handleMagicLinkRequest sends a magic link for passwordless login.
func (s *AuthService) handleMagicLinkRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientIP := s.clientIP(r)

	if s.isIPBlocked(ctx, clientIP) {
		writeJSON(w, http.StatusOK, map[string]any{
			"message": "if the email exists, a magic link has been sent",
		})
		return
	}

	// Rate limiting
	allowed, _ := s.allowRateLimit(ctx, "magic:"+s.hashIP(clientIP), s.config.RateLimits.MagicLinkLimit, s.config.RateLimits.MagicLinkWindow)
	if !allowed {
		writeJSON(w, http.StatusOK, map[string]any{
			"message": "if the email exists, a magic link has been sent",
		})
		return
	}

	var req struct {
		Email          string `json:"email"`
		CaptchaToken   string `json:"captcha_token,omitempty"`
		TurnstileToken string `json:"cf_turnstile_token,omitempty"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request")
		return
	}

	captchaToken := req.CaptchaToken
	if captchaToken == "" {
		captchaToken = req.TurnstileToken
	}
	ok, err := s.verifyCaptcha(ctx, captchaToken, clientIP, "magic_link")
	if err != nil {
		s.logger.Error("captcha error", zap.Error(err))
		if s.config.CaptchaFailOpen {
			ok = true
		}
	}
	if !ok {
		writeError(w, http.StatusBadRequest, CodeInvalidCaptcha, ErrInvalidCaptcha.Error())
		return
	}

	// Always return success to prevent enumeration
	defer func() {
		writeJSON(w, http.StatusOK, map[string]any{
			"message": "if the email exists, a magic link has been sent",
		})
	}()

	email := normalizeEmail(req.Email)
	emailHash := crypto.HashWithPepper(email, s.pepper)

	user, err := s.store.Users().GetUserByEmailHash(ctx, emailHash)
	if err != nil {
		return // User not found
	}

	// Generate magic link token
	token, _ := generateSecureToken(32)
	tokenHash := crypto.HashToken(token)

	ipEnc, ipNonce, _ := s.encryptIP(clientIP)

	magicToken := MagicLinkToken{
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: time.Now().Add(s.config.MagicLinkTTL),
		IPCreated: ipEnc,
		IPNonce:   ipNonce,
	}

	if ml, ok := s.store.(MagicLinkStore); ok {
		if err := ml.CreateMagicLinkToken(ctx, magicToken); err != nil {
			s.logger.Error("create magic link error", zap.Error(err))
			return
		}
	}

	// Send magic link email
	link := s.config.AppBaseURL + "/auth/magic?token=" + token
	decryptedEmail, _ := crypto.Decrypt(user.EmailEncrypted, user.EmailNonce, s.keys.EmailKey)
	
	if mlm, ok := s.mailer.(MagicLinkMailer); ok {
		if err := mlm.SendMagicLink(ctx, string(decryptedEmail), link); err != nil {
			s.logger.Error("send magic link error", zap.Error(err))
		}
	}
}

// handleMagicLinkVerify verifies a magic link and logs in.
func (s *AuthService) handleMagicLinkVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	token := r.URL.Query().Get("token")

	if token == "" {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "missing token")
		return
	}

	tokenHash := crypto.HashToken(token)

	ml, ok := s.store.(MagicLinkStore)
	if !ok {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "magic links not enabled")
		return
	}

	magicToken, err := ml.GetMagicLinkToken(ctx, tokenHash)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidToken, "invalid or expired link")
		return
	}

	if magicToken.Used || time.Now().After(magicToken.ExpiresAt) {
		writeError(w, http.StatusBadRequest, CodeTokenExpired, "link expired")
		return
	}

	// Mark as used
	ipEnc, ipNonce, _ := s.encryptIP(s.clientIP(r))
	ml.MarkMagicLinkUsed(ctx, magicToken.ID, ipEnc, ipNonce)

	// Get user and issue tokens
	user, err := s.store.Users().GetUserByID(ctx, magicToken.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	switch user.AccountStatus {
	case StatusLocked:
		writeError(w, http.StatusForbidden, CodeAccountLocked, ErrAccountLocked.Error())
		return
	case StatusSuspended:
		writeError(w, http.StatusForbidden, CodeAccountSuspended, ErrAccountSuspended.Error())
		return
	case StatusDeleted:
		writeError(w, http.StatusForbidden, CodeAccountSuspended, "account deleted")
		return
	}

	if s.config.EmailVerificationRequired && !user.EmailVerified {
		if err := s.store.Users().SetUserVerified(ctx, user.ID); err == nil {
			user.EmailVerified = true
		}
	}

	if s.config.Require2FAForMagicLink && user.TOTPEnabled {
		tempToken, err := crypto.NewTemp2FAToken(s.jwtSecret, user.ID, 5*time.Minute)
		if err != nil {
			writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"requires_2fa": true,
			"temp_token":   tempToken,
		})
		return
	}

	accessToken, refreshToken, err := s.issueTokens(ctx, user, r, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	ipEnc, ipNonce, _ := s.encryptIP(s.clientIP(r))
	s.store.Users().UpdateLastLogin(ctx, user.ID, ipEnc, ipNonce)
	s.logAudit(ctx, user.ID, "magic_link_login", r, nil)
	s.CheckSuspiciousLogin(ctx, user, r)

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"user_id":       user.ID,
	})
}

// MagicLinkStore handles magic link tokens.
type MagicLinkStore interface {
	CreateMagicLinkToken(ctx context.Context, token MagicLinkToken) error
	GetMagicLinkToken(ctx context.Context, tokenHash []byte) (*MagicLinkToken, error)
	MarkMagicLinkUsed(ctx context.Context, tokenID string, ipUsed, ipNonce []byte) error
}

// MagicLinkMailer sends magic link emails.
type MagicLinkMailer interface {
	SendMagicLink(ctx context.Context, to, link string) error
}

// ==================== API KEYS ====================

// APIKey represents a long-lived API key for service/integration use.
type APIKey struct {
	ID          string
	UserID      string
	Name        string
	KeyPrefix   string    // First 8 chars for identification
	KeyHash     []byte    // SHA-256 hash of full key
	Scopes      []string
	ExpiresAt   *time.Time
	LastUsed    time.Time
	CreatedAt   time.Time
	RateLimit   int // Requests per minute, 0 = default
}

// APIKeyStore handles API key management.
type APIKeyStore interface {
	CreateAPIKey(ctx context.Context, key APIKey) error
	GetAPIKeyByHash(ctx context.Context, keyHash []byte) (*APIKey, error)
	GetUserAPIKeys(ctx context.Context, userID string) ([]APIKey, error)
	UpdateAPIKeyLastUsed(ctx context.Context, keyID string) error
	RevokeAPIKey(ctx context.Context, keyID string) error
}

// handleCreateAPIKey creates a new API key.
func (s *AuthService) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	if s.apiKeyStore == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "API keys not enabled")
		return
	}

	var req struct {
		Name      string   `json:"name"`
		Scopes    []string `json:"scopes"`
		ExpiresIn int      `json:"expires_in_days"` // 0 = no expiry
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request")
		return
	}

	// Generate key
	rawKey, err := generateAPIKey()
	if err != nil {
		s.logger.Error("generate api key error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}
	keyPrefix := rawKey[:8]
	keyHash := crypto.HashToken(rawKey)

	var expiresAt *time.Time
	if req.ExpiresIn > 0 {
		t := time.Now().AddDate(0, 0, req.ExpiresIn)
		expiresAt = &t
	}

	apiKey := APIKey{
		UserID:    user.ID,
		Name:      req.Name,
		KeyPrefix: keyPrefix,
		KeyHash:   keyHash,
		Scopes:    req.Scopes,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}

	if err := s.apiKeyStore.CreateAPIKey(ctx, apiKey); err != nil {
		s.logger.Error("create api key error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	s.logAudit(ctx, user.ID, "api_key_created", r, map[string]any{"name": req.Name})

	// Return the full key only once - it cannot be retrieved again
	writeJSON(w, http.StatusCreated, map[string]any{
		"key":        rawKey, // Only time the full key is shown
		"key_prefix": keyPrefix,
		"name":       req.Name,
		"expires_at": expiresAt,
		"warning":    "Save this key securely. It cannot be retrieved again.",
	})
}

// handleListAPIKeys lists user's API keys.
func (s *AuthService) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	if s.apiKeyStore == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "API keys not enabled")
		return
	}

	keys, err := s.apiKeyStore.GetUserAPIKeys(ctx, user.ID)
	if err != nil {
		s.logger.Error("list api keys error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	result := make([]map[string]any, len(keys))
	for i, k := range keys {
		result[i] = map[string]any{
			"id":         k.ID,
			"name":       k.Name,
			"key_prefix": k.KeyPrefix,
			"scopes":     k.Scopes,
			"expires_at": k.ExpiresAt,
			"last_used":  k.LastUsed,
			"created_at": k.CreatedAt,
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"api_keys": result})
}

// handleRevokeAPIKey revokes an API key.
func (s *AuthService) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	if s.apiKeyStore == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "API keys not enabled")
		return
	}

	var req struct {
		KeyID string `json:"key_id"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request")
		return
	}

	// Verify key belongs to user (done in store)
	if err := s.apiKeyStore.RevokeAPIKey(ctx, req.KeyID); err != nil {
		s.logger.Error("revoke api key error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	s.logAudit(ctx, user.ID, "api_key_revoked", r, map[string]any{"key_id": req.KeyID})
	writeJSON(w, http.StatusOK, map[string]any{"message": "API key revoked"})
}

// ==================== HELPERS ====================

func generateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func generateAPIKey() (string, error) {
	token, err := generateSecureToken(32)
	if err != nil {
		return "", err
	}
	return "sk_" + token, nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}



