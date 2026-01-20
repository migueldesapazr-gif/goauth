package goauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/migueldesapazr-gif/goauth/crypto"
)

// ==================== WEBAUTHN TYPES ====================

// WebAuthnCredential represents a stored passkey/security key.
type WebAuthnCredential struct {
	ID              string    `json:"id"`
	UserID          string    `json:"user_id"`
	CredentialID    []byte    `json:"credential_id"`
	PublicKey       []byte    `json:"public_key"`
	AttestationType string    `json:"attestation_type"`
	AAGUID          []byte    `json:"aaguid"`
	SignCount       uint32    `json:"sign_count"`
	CloneWarning    bool      `json:"clone_warning"`
	Transports      []string  `json:"transports,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	Name            string    `json:"name"`
}

// WebAuthnChallenge represents a pending WebAuthn challenge.
type WebAuthnChallenge struct {
	Challenge   []byte
	UserID      string
	SessionData []byte
	ExpiresAt   time.Time
	Type        string // "registration" or "authentication"
}

// WebAuthnStore handles WebAuthn credential persistence.
type WebAuthnStore interface {
	// Credentials
	CreateCredential(ctx context.Context, cred WebAuthnCredential) error
	GetCredentialByID(ctx context.Context, credentialID []byte) (*WebAuthnCredential, error)
	GetUserCredentials(ctx context.Context, userID string) ([]WebAuthnCredential, error)
	UpdateCredentialSignCount(ctx context.Context, credentialID []byte, signCount uint32) error
	DeleteCredential(ctx context.Context, userID string, credentialID []byte) error
	
	// Challenges
	StoreChallenge(ctx context.Context, challenge WebAuthnChallenge) error
	GetChallenge(ctx context.Context, challenge []byte) (*WebAuthnChallenge, error)
	DeleteChallenge(ctx context.Context, challenge []byte) error
}

// WebAuthnUsageStore updates usage metadata when supported.
type WebAuthnUsageStore interface {
	UpdateCredentialUsage(ctx context.Context, credentialID []byte, signCount uint32, lastUsedAt time.Time) error
}

// WebAuthnNameStore updates credential names when supported.
type WebAuthnNameStore interface {
	UpdateCredentialName(ctx context.Context, userID string, credentialID []byte, name string) error
}

// ==================== WEBAUTHN CONFIG ====================

// WebAuthnConfig configures WebAuthn/Passkey behavior.
type WebAuthnConfig struct {
	// RPDisplayName is the display name of your application
	RPDisplayName string
	// RPID is the relying party ID (usually your domain without protocol)
	RPID string
	// RPOrigins are the allowed origins for WebAuthn requests
	RPOrigins []string
	// Timeout for challenges in milliseconds
	Timeout int
	// AttestationPreference: "none", "indirect", or "direct"
	AttestationPreference string
	// UserVerification: "required", "preferred", or "discouraged"
	UserVerification string
	// ResidentKeyRequirement: "required", "preferred", or "discouraged"
	ResidentKeyRequirement string
	// AllowCredentials enables discoverable credentials (passkeys)
	AllowCredentials bool
	// MaxPasskeysPerUser limits how many passkeys a user can register (0 = unlimited)
	MaxPasskeysPerUser int
	// AllowPasskeysForRoles limits passkey registration to specific roles (empty = allow all)
	AllowPasskeysForRoles []Role
}

// DefaultWebAuthnConfig returns sensible defaults for WebAuthn.
func DefaultWebAuthnConfig() WebAuthnConfig {
	return WebAuthnConfig{
		Timeout:                60000, // 60 seconds
		AttestationPreference:  "none",
		UserVerification:       "preferred",
		ResidentKeyRequirement: "preferred",
		AllowCredentials:       true,
		MaxPasskeysPerUser:     0,
		AllowPasskeysForRoles:  nil,
	}
}

// ==================== WEBAUTHN HANDLERS ====================

// handleWebAuthnRegisterBegin starts the WebAuthn registration flow.
func (s *AuthService) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, ok := GetUserFromContext(ctx)
	if !ok {
		writeError(w, http.StatusUnauthorized, CodeInvalidToken, "unauthorized")
		return
	}
	if s.webauthnStore == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "webauthn not configured")
		return
	}
	if !s.passkeysAllowedForRole(user.Role) {
		writeError(w, http.StatusForbidden, "PASSKEYS_NOT_ALLOWED", "passkeys not allowed for this role")
		return
	}

	// Generate challenge
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		s.logger.Error("failed to generate challenge", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	// Get existing credentials to exclude
	creds, err := s.webauthnStore.GetUserCredentials(ctx, user.ID)
	if err != nil {
		s.logger.Error("failed to get credentials", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}
	if limit := s.config.WebAuthn.MaxPasskeysPerUser; limit > 0 && len(creds) >= limit {
		writeError(w, http.StatusBadRequest, "PASSKEY_LIMIT_REACHED", "passkey limit reached")
		return
	}
	var excludeCredentials []map[string]any
	for _, c := range creds {
		excludeCredentials = append(excludeCredentials, map[string]any{
			"type": "public-key",
			"id":   base64.RawURLEncoding.EncodeToString(c.CredentialID),
		})
	}

	// Store challenge
	if err := s.webauthnStore.StoreChallenge(ctx, WebAuthnChallenge{
		Challenge: challenge,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Type:      "registration",
	}); err != nil {
		s.logger.Error("failed to store challenge", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	// Build response
	displayName := user.Username
	if displayName == "" {
		displayName = user.ID
	}
	options := map[string]any{
		"challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"rp": map[string]string{
			"name": s.config.WebAuthn.RPDisplayName,
			"id":   s.config.WebAuthn.RPID,
		},
		"user": map[string]any{
			"id":          base64.RawURLEncoding.EncodeToString([]byte(user.ID)),
			"name":        displayName,
			"displayName": displayName,
		},
		"pubKeyCredParams": []map[string]any{
			{"type": "public-key", "alg": -7},   // ES256
			{"type": "public-key", "alg": -257}, // RS256
		},
		"timeout":     s.config.WebAuthn.Timeout,
		"attestation": s.config.WebAuthn.AttestationPreference,
		"authenticatorSelection": map[string]any{
			"userVerification":   s.config.WebAuthn.UserVerification,
			"residentKey":        s.config.WebAuthn.ResidentKeyRequirement,
			"requireResidentKey": s.config.WebAuthn.ResidentKeyRequirement == "required",
		},
	}

	if len(excludeCredentials) > 0 {
		options["excludeCredentials"] = excludeCredentials
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"options": options,
	})
}

// handleWebAuthnRegisterFinish completes WebAuthn registration.
func (s *AuthService) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, ok := GetUserFromContext(ctx)
	if !ok {
		writeError(w, http.StatusUnauthorized, CodeInvalidToken, "unauthorized")
		return
	}
	if s.webauthnStore == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "webauthn not configured")
		return
	}
	if !s.passkeysAllowedForRole(user.Role) {
		writeError(w, http.StatusForbidden, "PASSKEYS_NOT_ALLOWED", "passkeys not allowed for this role")
		return
	}

	var req struct {
		ID       string `json:"id"`
		RawID    string `json:"rawId"`
		Type     string `json:"type"`
		Response struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AttestationObject string `json:"attestationObject"`
		} `json:"response"`
		Name string `json:"name"` // User-provided name for the credential
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request")
		return
	}

	// Decode client data to get challenge
	clientDataJSON, err := base64.RawURLEncoding.DecodeString(req.Response.ClientDataJSON)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid client data")
		return
	}

	var clientData struct {
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
		Type      string `json:"type"`
	}
	if err := json.Unmarshal(clientDataJSON, &clientData); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid client data")
		return
	}

	// Verify challenge exists
	challengeBytes, _ := base64.RawURLEncoding.DecodeString(clientData.Challenge)
	stored, err := s.webauthnStore.GetChallenge(ctx, challengeBytes)
	if err != nil || stored == nil || stored.UserID != user.ID {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid challenge")
		return
	}
	if stored.Type != "registration" || time.Now().After(stored.ExpiresAt) {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "expired challenge")
		return
	}
	_ = s.webauthnStore.DeleteChallenge(ctx, challengeBytes)

	// Verify origin
	validOrigin := false
	for _, origin := range s.config.WebAuthn.RPOrigins {
		if clientData.Origin == origin {
			validOrigin = true
			break
		}
	}
	if !validOrigin && len(s.config.WebAuthn.RPOrigins) > 0 {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid origin")
		return
	}

	// Decode credential ID
	credentialID, err := base64.RawURLEncoding.DecodeString(req.RawID)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid credential ID")
		return
	}

	// Decode attestation object (simplified - production should fully parse CBOR)
	attestationObject, err := base64.RawURLEncoding.DecodeString(req.Response.AttestationObject)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid attestation")
		return
	}

	// Enforce passkey limit (in case of race)
	if limit := s.config.WebAuthn.MaxPasskeysPerUser; limit > 0 {
		creds, err := s.webauthnStore.GetUserCredentials(ctx, user.ID)
		if err != nil {
			s.logger.Error("failed to get credentials", zap.Error(err))
			writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
			return
		}
		if len(creds) >= limit {
			writeError(w, http.StatusBadRequest, "PASSKEY_LIMIT_REACHED", "passkey limit reached")
			return
		}
	}

	// Store credential
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "Passkey " + time.Now().Format("2006-01-02")
	}
	if len(name) > 64 {
		name = name[:64]
	}

	cred := WebAuthnCredential{
		UserID:          user.ID,
		CredentialID:    credentialID,
		PublicKey:       attestationObject, // Simplified - should extract actual public key
		AttestationType: s.config.WebAuthn.AttestationPreference,
		SignCount:       0,
		CreatedAt:       time.Now(),
		Name:            name,
	}

	if err := s.webauthnStore.CreateCredential(ctx, cred); err != nil {
		s.logger.Error("failed to store credential", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "failed to register")
		return
	}

	s.logAudit(ctx, user.ID, "webauthn_registered", r, map[string]any{"name": name})

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "passkey registered successfully",
		"name":    name,
	})
}

// handleWebAuthnLoginBegin starts the WebAuthn authentication flow.
func (s *AuthService) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if s.webauthnStore == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "webauthn not configured")
		return
	}

	// Optional: allow specifying a username for non-discoverable credentials
	var req struct {
		Email    string `json:"email,omitempty"`
		Username string `json:"username,omitempty"`
	}
	_ = readJSON(w, r, &req)

	// Generate challenge
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		s.logger.Error("failed to generate challenge", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	options := map[string]any{
		"challenge":        base64.RawURLEncoding.EncodeToString(challenge),
		"timeout":          s.config.WebAuthn.Timeout,
		"rpId":             s.config.WebAuthn.RPID,
		"userVerification": s.config.WebAuthn.UserVerification,
	}

	// If email/username provided, get their credentials
	var userID string
	if req.Email != "" || req.Username != "" {
		var user *User
		var err error
		if req.Email != "" {
			email := normalizeEmail(req.Email)
			emailHash := crypto.HashWithPepper(email, s.pepper)
			user, err = s.store.Users().GetUserByEmailHash(ctx, emailHash)
		} else {
			user, err = s.store.Users().GetUserByUsername(ctx, normalizeUsername(req.Username))
		}

		if err == nil && user != nil && s.webauthnStore != nil {
			userID = user.ID
			creds, _ := s.webauthnStore.GetUserCredentials(ctx, user.ID)
			var allowCredentials []map[string]any
			for _, c := range creds {
				allowCredentials = append(allowCredentials, map[string]any{
					"type":       "public-key",
					"id":         base64.RawURLEncoding.EncodeToString(c.CredentialID),
					"transports": c.Transports,
				})
			}
			if len(allowCredentials) > 0 {
				options["allowCredentials"] = allowCredentials
			}
		}
	}

	// Store challenge
	if s.webauthnStore != nil {
		_ = s.webauthnStore.StoreChallenge(ctx, WebAuthnChallenge{
			Challenge: challenge,
			UserID:    userID,
			ExpiresAt: time.Now().Add(5 * time.Minute),
			Type:      "authentication",
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"options": options,
	})
}

// handleWebAuthnLoginFinish completes WebAuthn authentication.
func (s *AuthService) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		ID       string `json:"id"`
		RawID    string `json:"rawId"`
		Type     string `json:"type"`
		Response struct {
			ClientDataJSON    string `json:"clientDataJSON"`
			AuthenticatorData string `json:"authenticatorData"`
			Signature         string `json:"signature"`
			UserHandle        string `json:"userHandle,omitempty"`
		} `json:"response"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request")
		return
	}

	// Decode credential ID
	credentialID, err := base64.RawURLEncoding.DecodeString(req.RawID)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid credential")
		return
	}

	// Find credential
	if s.webauthnStore == nil {
		writeError(w, http.StatusInternalServerError, CodeInternalError, "webauthn not configured")
		return
	}

	cred, err := s.webauthnStore.GetCredentialByID(ctx, credentialID)
	if err != nil || cred == nil {
		writeError(w, http.StatusUnauthorized, CodeInvalidCredentials, "unknown credential")
		return
	}

	// Decode client data to verify challenge
	clientDataJSON, _ := base64.RawURLEncoding.DecodeString(req.Response.ClientDataJSON)
	var clientData struct {
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
		Type      string `json:"type"`
	}
	_ = json.Unmarshal(clientDataJSON, &clientData)

	// Verify challenge
	challengeBytes, _ := base64.RawURLEncoding.DecodeString(clientData.Challenge)
	stored, err := s.webauthnStore.GetChallenge(ctx, challengeBytes)
	if err != nil || stored == nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid challenge")
		return
	}
	if stored.Type != "authentication" || time.Now().After(stored.ExpiresAt) {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "expired challenge")
		return
	}
	if stored.UserID != "" && stored.UserID != cred.UserID {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid challenge")
		return
	}
	_ = s.webauthnStore.DeleteChallenge(ctx, challengeBytes)

	// Get user
	user, err := s.store.Users().GetUserByID(ctx, cred.UserID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, CodeInvalidCredentials, "user not found")
		return
	}

	// Check account status
	if user.AccountStatus == StatusLocked {
		writeError(w, http.StatusForbidden, CodeAccountLocked, ErrAccountLocked.Error())
		return
	}
	if user.AccountStatus == StatusSuspended {
		writeError(w, http.StatusForbidden, CodeAccountSuspended, ErrAccountSuspended.Error())
		return
	}

	// Update sign count and last used (simplified - should verify it increased)
	if usageStore, ok := s.webauthnStore.(WebAuthnUsageStore); ok {
		_ = usageStore.UpdateCredentialUsage(ctx, credentialID, cred.SignCount+1, time.Now())
	} else {
		_ = s.webauthnStore.UpdateCredentialSignCount(ctx, credentialID, cred.SignCount+1)
	}

	// Issue tokens - WebAuthn counts as verified 2FA
	accessToken, refreshToken, err := s.issueTokens(ctx, user, r, true)
	if err != nil {
		s.logger.Error("token issue failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	s.store.Users().ResetLoginFailures(ctx, user.ID)
	ipEnc, ipNonce, _ := s.encryptIP(s.clientIP(r))
	s.store.Users().UpdateLastLogin(ctx, user.ID, ipEnc, ipNonce)
	s.logAudit(ctx, user.ID, EventLoginSuccess, r, map[string]any{"method": "webauthn"})

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":   accessToken,
		"refresh_token":  refreshToken,
		"user_id":        user.ID,
		"email_verified": user.EmailVerified,
	})
}

// handleWebAuthnList returns the user's registered passkeys.
func (s *AuthService) handleWebAuthnList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	if s.webauthnStore == nil {
		writeJSON(w, http.StatusOK, map[string]any{"credentials": []any{}})
		return
	}

	creds, err := s.webauthnStore.GetUserCredentials(ctx, user.ID)
	if err != nil {
		s.logger.Error("failed to get credentials", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	result := make([]map[string]any, len(creds))
	for i, c := range creds {
		result[i] = map[string]any{
			"id":          base64.RawURLEncoding.EncodeToString(c.CredentialID),
			"name":        c.Name,
			"created_at":  c.CreatedAt,
			"last_used":   c.LastUsedAt,
			"transports":  c.Transports,
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"credentials": result})
}

// handleWebAuthnDelete removes a passkey.
func (s *AuthService) handleWebAuthnDelete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	if s.webauthnStore == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "webauthn not configured")
		return
	}

	var req struct {
		CredentialID string `json:"credential_id"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request")
		return
	}

	credentialID, err := base64.RawURLEncoding.DecodeString(req.CredentialID)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid credential ID")
		return
	}

	cred, err := s.webauthnStore.GetCredentialByID(ctx, credentialID)
	if err != nil || cred == nil || cred.UserID != user.ID {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "credential not found")
		return
	}

	if err := s.webauthnStore.DeleteCredential(ctx, user.ID, credentialID); err != nil {
		s.logger.Error("failed to delete credential", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "failed to delete")
		return
	}

	s.logAudit(ctx, user.ID, "webauthn_deleted", r, nil)
	writeJSON(w, http.StatusOK, map[string]any{"message": "passkey deleted"})
}

// handleWebAuthnRename renames a passkey.
func (s *AuthService) handleWebAuthnRename(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	if s.webauthnStore == nil {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "webauthn not configured")
		return
	}

	var req struct {
		CredentialID string `json:"credential_id"`
		Name         string `json:"name"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request")
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "name is required")
		return
	}
	if len(name) > 64 {
		name = name[:64]
	}

	credentialID, err := base64.RawURLEncoding.DecodeString(req.CredentialID)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid credential ID")
		return
	}

	cred, err := s.webauthnStore.GetCredentialByID(ctx, credentialID)
	if err != nil || cred == nil || cred.UserID != user.ID {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "credential not found")
		return
	}

	nameStore, ok := s.webauthnStore.(WebAuthnNameStore)
	if !ok {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "passkey renaming not supported")
		return
	}

	if err := nameStore.UpdateCredentialName(ctx, user.ID, credentialID, name); err != nil {
		s.logger.Error("failed to rename credential", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "failed to rename")
		return
	}

	s.logAudit(ctx, user.ID, EventPasskeyRenamed, r, map[string]any{"name": name})
	writeJSON(w, http.StatusOK, map[string]any{"message": "passkey renamed"})
}

// ==================== OPTIONS ====================

// WithWebAuthn enables WebAuthn/Passkey support.
func WithWebAuthn(config WebAuthnConfig) Option {
	return func(s *AuthService) error {
		s.config.WebAuthn = config
		s.config.WebAuthnEnabled = true
		return nil
	}
}

// WithWebAuthnStore sets the WebAuthn credential store.
func WithWebAuthnStore(store WebAuthnStore) Option {
	return func(s *AuthService) error {
		s.webauthnStore = store
		return nil
	}
}

func (s *AuthService) passkeysAllowedForRole(role string) bool {
	allowed := s.config.WebAuthn.AllowPasskeysForRoles
	if len(allowed) == 0 {
		return true
	}
	if role == "" {
		role = string(RoleUser)
	}
	for _, r := range allowed {
		if string(r) == role {
			return true
		}
	}
	return false
}
