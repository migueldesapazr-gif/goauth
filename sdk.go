package goauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"

	"github.com/migueldesapazr-gif/goauth/crypto"
)

// ==================== CLIENT TYPE DETECTION ====================

// ClientType identifies the type of client making the request.
type ClientType string

const (
	ClientTypeWeb     ClientType = "web"
	ClientTypeMobile  ClientType = "mobile"
	ClientTypeDesktop ClientType = "desktop"
	ClientTypeAPI     ClientType = "api"
	ClientTypeSDK     ClientType = "sdk"
)

// contextKeyClientType is the context key for client type.
const contextKeyClientType contextKey = "goauth_client_type"

// GetClientType detects the client type from the request.
func GetClientType(r *http.Request) ClientType {
	// Check explicit header first
	if ct := r.Header.Get("X-Client-Type"); ct != "" {
		switch strings.ToLower(ct) {
		case "web":
			return ClientTypeWeb
		case "mobile", "ios", "android":
			return ClientTypeMobile
		case "desktop", "electron", "macos", "windows", "linux":
			return ClientTypeDesktop
		case "api", "service":
			return ClientTypeAPI
		case "sdk":
			return ClientTypeSDK
		}
	}

	// Check for API key
	if r.Header.Get("X-API-Key") != "" || r.Header.Get("Authorization") != "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer sk_") {
			return ClientTypeAPI
		}
	}

	// Detect from User-Agent
	ua := strings.ToLower(r.UserAgent())
	
	// Mobile detection
	if strings.Contains(ua, "mobile") || 
	   strings.Contains(ua, "android") || 
	   strings.Contains(ua, "iphone") ||
	   strings.Contains(ua, "ipad") {
		return ClientTypeMobile
	}

	// Desktop app detection
	if strings.Contains(ua, "electron") ||
	   strings.Contains(ua, "goauth-sdk") {
		return ClientTypeDesktop
	}

	// API/Bot detection
	if strings.Contains(ua, "curl") ||
	   strings.Contains(ua, "httpie") ||
	   strings.Contains(ua, "postman") ||
	   !strings.Contains(ua, "mozilla") {
		return ClientTypeAPI
	}

	return ClientTypeWeb
}

// ClientTypeMiddleware adds client type to context.
func (s *AuthService) ClientTypeMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientType := GetClientType(r)
			ctx := context.WithValue(r.Context(), contextKeyClientType, clientType)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetClientTypeFromContext retrieves client type from context.
func GetClientTypeFromContext(ctx context.Context) ClientType {
	if ct, ok := ctx.Value(contextKeyClientType).(ClientType); ok {
		return ct
	}
	return ClientTypeWeb
}

// ==================== API KEY AUTHENTICATION ====================

// APIKeyMiddleware authenticates requests using API keys.
func (s *AuthService) APIKeyMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.apiKeyStore == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Try to get API key from header
			apiKey := r.Header.Get("X-API-Key")
			if apiKey == "" {
				// Try Bearer token
				auth := r.Header.Get("Authorization")
				if strings.HasPrefix(auth, "Bearer sk_") {
					apiKey = strings.TrimPrefix(auth, "Bearer ")
				}
			}

			if apiKey == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Validate API key
			keyHash := crypto.HashToken(apiKey)
			key, err := s.apiKeyStore.GetAPIKeyByHash(r.Context(), keyHash)
			if err != nil {
				writeError(w, http.StatusUnauthorized, CodeInvalidToken, "invalid API key")
				return
			}

			// Check expiry
			if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
				writeError(w, http.StatusUnauthorized, CodeTokenExpired, "API key expired")
				return
			}

			// Rate limit
			if key.RateLimit > 0 {
				allowed, _, err := s.limiter.Allow(r.Context(), "apikey:"+key.ID, key.RateLimit, time.Minute)
				if err != nil {
					s.logger.Error("rate limit error", zap.Error(err))
				}
				if !allowed {
					writeError(w, http.StatusTooManyRequests, CodeRateLimited, "rate limit exceeded")
					return
				}
			}

			// Get user
			user, err := s.store.Users().GetUserByID(r.Context(), key.UserID)
			if err != nil {
				writeError(w, http.StatusUnauthorized, CodeInvalidToken, "invalid API key")
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

			// Update last used
			s.apiKeyStore.UpdateAPIKeyLastUsed(r.Context(), key.ID)

			// Add to context
			scope := strings.Join(key.Scopes, " ")
			claims := &crypto.Claims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject: user.ID,
				},
				EmailVerified: user.EmailVerified,
				Scope:         scope,
				TokenType:     crypto.TokenTypeAccess,
			}

			ctx := context.WithValue(r.Context(), UserContextKey, user)
			ctx = context.WithValue(ctx, contextKeyClientType, ClientTypeAPI)
			ctx = context.WithValue(ctx, ClaimsContextKey, claims)
			ctx = context.WithValue(ctx, "api_key_scopes", key.Scopes)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ==================== SDK TOKENS ====================

// SDKToken is a long-lived token for SDK/mobile use.
type SDKToken struct {
	UserID    string
	DeviceID  string
	Scopes    []string
	ExpiresAt time.Time
}

// handleSDKTokenCreate creates a long-lived SDK token for mobile apps.
func (s *AuthService) handleSDKTokenCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	var req struct {
		DeviceName string `json:"device_name"`
		DeviceType string `json:"device_type"`
		Password   string `json:"password"` // Require password for security
		TOTPCode   string `json:"totp_code,omitempty"`
		BackupCode string `json:"backup_code,omitempty"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request")
		return
	}

	// Verify password
	if !crypto.VerifyPassword(req.Password, user.PasswordHash, user.PasswordSalt) {
		writeError(w, http.StatusUnauthorized, CodeInvalidCredentials, "invalid password")
		return
	}

	if s.config.EmailVerificationRequired && !user.EmailVerified {
		writeError(w, http.StatusForbidden, CodeAccountNotVerified, ErrAccountNotVerified.Error())
		return
	}

	twoFAVerified := false
	if s.config.Require2FAForSDK && user.TOTPEnabled {
		valid, _, err := s.verifyTOTPOrBackup(ctx, user, req.TOTPCode, req.BackupCode)
		if err != nil {
			s.logger.Error("totp verify error", zap.Error(err))
			writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
			return
		}
		if !valid {
			writeError(w, http.StatusUnauthorized, CodeInvalid2FACode, ErrInvalid2FACode.Error())
			return
		}
		twoFAVerified = true
	}

	// Create device if device management is enabled
	var deviceID string
	if s.deviceStore != nil {
		device := Device{
			UserID:     user.ID,
			Name:       req.DeviceName,
			DeviceType: req.DeviceType,
			TrustLevel: "trusted",
		}
		if err := s.deviceStore.CreateDevice(ctx, device); err != nil {
			s.logger.Error("create device error", zap.Error(err))
		} else {
			deviceID = device.ID
		}
	}

	// Issue long-lived tokens
	clientConfig := s.config.MobileClientConfig
	if req.DeviceType == "desktop" {
		// Desktop can have even longer tokens
		clientConfig.RefreshTokenTTL = 90 * 24 * time.Hour
	}

	accessToken, err := crypto.NewAccessTokenWithOptions(
		s.jwtSecret,
		user.ID,
		user.EmailVerified,
		twoFAVerified,
		clientConfig.AccessTokenTTL,
		crypto.AccessTokenOptions{
			DeviceID: deviceID,
		},
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	jti := generateJTI()
	refreshToken, err := crypto.NewRefreshTokenWithOptions(
		s.jwtSecret,
		user.ID,
		clientConfig.RefreshTokenTTL,
		crypto.RefreshTokenOptions{
			JTI:           jti,
			EmailVerified: user.EmailVerified,
			TwoFAVerified: twoFAVerified,
			DeviceID:      deviceID,
		},
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	// Store refresh token
	ipEnc, ipNonce, _ := s.encryptIP(s.clientIP(r))
	s.store.Tokens().StoreRefreshToken(ctx, user.ID, jti, time.Now().Add(clientConfig.RefreshTokenTTL), ipEnc, ipNonce)

	s.logAudit(ctx, user.ID, "sdk_token_created", r, map[string]any{
		"device_name": req.DeviceName,
		"device_type": req.DeviceType,
	})

	writeJSON(w, http.StatusCreated, map[string]any{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"device_id":     deviceID,
		"expires_in":    int(clientConfig.AccessTokenTTL.Seconds()),
	})
}

// ==================== BIOMETRIC AUTH ====================

// BiometricChallenge for mobile biometric authentication.
type BiometricChallenge struct {
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}

// handleBiometricChallenge creates a challenge for biometric auth.
func (s *AuthService) handleBiometricChallenge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	// Generate challenge
	challenge, _ := generateSecureToken(32)

	// Store challenge (short-lived)
	// This would typically be stored in Redis with a 1-minute TTL
	// For now, we'll use a simple in-memory approach
	
	s.logAudit(ctx, user.ID, "biometric_challenge", r, nil)

	writeJSON(w, http.StatusOK, BiometricChallenge{
		Challenge: challenge,
		ExpiresAt: time.Now().Add(1 * time.Minute),
	})
}

// ==================== HELPERS ====================

func generateJTI() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}



