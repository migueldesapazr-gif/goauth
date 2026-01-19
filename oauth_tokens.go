package goauth

import (
	"context"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/migueldesapazr-gif/goauth/crypto"
)

// ==================== OAUTH TOKEN MANAGEMENT ====================

// OAuthTokenManager handles OAuth token storage, refresh, and revocation.
type OAuthTokenManager struct {
	svc    *AuthService
	tokens sync.Map // userID+provider -> *storedOAuthToken
}

type storedOAuthToken struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	Provider     string
}

// NewOAuthTokenManager creates a new OAuth token manager.
func (s *AuthService) NewOAuthTokenManager() *OAuthTokenManager {
	return &OAuthTokenManager{svc: s}
}

// StoreTokens stores OAuth tokens for a user.
func (m *OAuthTokenManager) StoreTokens(ctx context.Context, userID, provider string, tokens *OAuthTokens) error {
	key := userID + ":" + provider
	
	var expiresAt time.Time
	if tokens.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)
	}

	// Store in memory
	m.tokens.Store(key, &storedOAuthToken{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresAt:    expiresAt,
		Provider:     provider,
	})

	// Store encrypted in database if store supports it
	if store, ok := m.svc.store.(OAuthTokenStore); ok {
		accessEnc, accessNonce, _ := crypto.Encrypt([]byte(tokens.AccessToken), m.svc.keys.TOTPKey)
		var refreshEnc, refreshNonce []byte
		if tokens.RefreshToken != "" {
			refreshEnc, refreshNonce, _ = crypto.Encrypt([]byte(tokens.RefreshToken), m.svc.keys.TOTPKey)
		}
		return store.StoreOAuthTokens(ctx, userID, provider, accessEnc, accessNonce, refreshEnc, refreshNonce, expiresAt)
	}

	return nil
}

// GetValidToken returns a valid access token, refreshing if needed.
func (m *OAuthTokenManager) GetValidToken(ctx context.Context, userID, provider string) (string, error) {
	key := userID + ":" + provider
	
	// Check memory cache first
	if val, ok := m.tokens.Load(key); ok {
		stored := val.(*storedOAuthToken)
		if time.Now().Before(stored.ExpiresAt.Add(-5 * time.Minute)) {
			return stored.AccessToken, nil
		}
		// Token expiring soon, try refresh
		if stored.RefreshToken != "" {
			return m.refreshToken(ctx, userID, provider, stored)
		}
	}

	// Try database
	if store, ok := m.svc.store.(OAuthTokenStore); ok {
		accessEnc, accessNonce, refreshEnc, refreshNonce, expiresAt, err := store.GetOAuthTokens(ctx, userID, provider)
		if err == nil {
			access, _ := crypto.Decrypt(accessEnc, accessNonce, m.svc.keys.TOTPKey)
			refresh, _ := crypto.Decrypt(refreshEnc, refreshNonce, m.svc.keys.TOTPKey)
			
			stored := &storedOAuthToken{
				AccessToken:  string(access),
				RefreshToken: string(refresh),
				ExpiresAt:    expiresAt,
				Provider:     provider,
			}
			m.tokens.Store(key, stored)
			
			if time.Now().Before(expiresAt.Add(-5 * time.Minute)) {
				return string(access), nil
			}
			if len(refresh) > 0 {
				return m.refreshToken(ctx, userID, provider, stored)
			}
		}
	}

	return "", ErrOAuthTokenExpired
}

func (m *OAuthTokenManager) refreshToken(ctx context.Context, userID, provider string, stored *storedOAuthToken) (string, error) {
	p, ok := m.svc.oauth[provider]
	if !ok {
		return "", ErrOAuthProviderNotFound
	}

	refresher, ok := p.(OAuthRefresher)
	if !ok {
		return "", ErrOAuthRefreshNotSupported
	}

	newTokens, err := refresher.RefreshToken(ctx, stored.RefreshToken)
	if err != nil {
		m.svc.logger.Warn("oauth refresh failed", zap.String("provider", provider), zap.Error(err))
		return "", err
	}

	if err := m.StoreTokens(ctx, userID, provider, newTokens); err != nil {
		m.svc.logger.Error("failed to store refreshed tokens", zap.Error(err))
	}

	return newTokens.AccessToken, nil
}

// RevokeTokens revokes OAuth tokens for a user (logout from provider).
func (m *OAuthTokenManager) RevokeTokens(ctx context.Context, userID, provider string) error {
	key := userID + ":" + provider

	// Get current token
	var accessToken string
	if val, ok := m.tokens.Load(key); ok {
		accessToken = val.(*storedOAuthToken).AccessToken
	} else if store, ok := m.svc.store.(OAuthTokenStore); ok {
		accessEnc, accessNonce, _, _, _, err := store.GetOAuthTokens(ctx, userID, provider)
		if err == nil {
			decrypted, _ := crypto.Decrypt(accessEnc, accessNonce, m.svc.keys.TOTPKey)
			accessToken = string(decrypted)
		}
	}

	// Revoke at provider
	if accessToken != "" {
		if p, ok := m.svc.oauth[provider]; ok {
			if revoker, ok := p.(OAuthRevoker); ok {
				if err := revoker.RevokeToken(ctx, accessToken); err != nil {
					m.svc.logger.Warn("oauth revoke failed", zap.String("provider", provider), zap.Error(err))
				}
			}
		}
	}

	// Remove from memory
	m.tokens.Delete(key)

	// Remove from database
	if store, ok := m.svc.store.(OAuthTokenStore); ok {
		return store.DeleteOAuthTokens(ctx, userID, provider)
	}

	return nil
}

// ==================== INTERFACES ====================

// OAuthRefresher is implemented by providers that support token refresh.
type OAuthRefresher interface {
	RefreshToken(ctx context.Context, refreshToken string) (*OAuthTokens, error)
}

// OAuthRevoker is implemented by providers that support token revocation.
type OAuthRevoker interface {
	RevokeToken(ctx context.Context, accessToken string) error
}

// OAuthTokenStore handles OAuth token persistence.
type OAuthTokenStore interface {
	StoreOAuthTokens(ctx context.Context, userID, provider string, accessEnc, accessNonce, refreshEnc, refreshNonce []byte, expiresAt time.Time) error
	GetOAuthTokens(ctx context.Context, userID, provider string) (accessEnc, accessNonce, refreshEnc, refreshNonce []byte, expiresAt time.Time, err error)
	DeleteOAuthTokens(ctx context.Context, userID, provider string) error
}

// ==================== HANDLERS ====================

// handleOAuthRevoke revokes tokens for a specific provider.
func (s *AuthService) handleOAuthRevoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	var req struct {
		Provider string `json:"provider"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request")
		return
	}

	if s.oauthTokenManager != nil {
		if err := s.oauthTokenManager.RevokeTokens(ctx, user.ID, req.Provider); err != nil {
			s.logger.Warn("oauth revoke tokens failed", zap.Error(err))
		}
	}

	// Unlink OAuth connection if store supports it
	if store, ok := s.store.(OAuthConnectionStore); ok {
		if err := store.UnlinkOAuthConnection(ctx, user.ID, req.Provider); err != nil {
			s.logger.Error("unlink oauth failed", zap.Error(err))
		}
	}

	s.logAudit(ctx, user.ID, "oauth_unlinked", r, map[string]any{"provider": req.Provider})
	writeJSON(w, http.StatusOK, map[string]any{"message": "provider unlinked"})
}

// handleOAuthConnections lists connected OAuth providers.
func (s *AuthService) handleOAuthConnections(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	store, ok := s.store.(OAuthConnectionStore)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"connections": []any{}})
		return
	}

	connections, err := store.GetUserOAuthConnections(ctx, user.ID)
	if err != nil {
		s.logger.Error("get oauth connections failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	result := make([]map[string]any, len(connections))
	for i, c := range connections {
		result[i] = map[string]any{
			"provider":   c.Provider,
			"connected":  true,
			"linked_at":  c.CreatedAt,
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"connections": result})
}

// ==================== ERRORS ====================

var (
	ErrOAuthTokenExpired        = newAuthError("OAUTH_TOKEN_EXPIRED", "oauth token expired", nil)
	ErrOAuthProviderNotFound    = newAuthError("OAUTH_PROVIDER_NOT_FOUND", "oauth provider not found", nil)
	ErrOAuthRefreshNotSupported = newAuthError("OAUTH_REFRESH_NOT_SUPPORTED", "oauth refresh not supported", nil)
)
