package goauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/migueldesapazr-gif/goauth/crypto"
)

// handleOAuthRedirect redirects the user to the OAuth provider.
func (s *AuthService) handleOAuthRedirect(name string, provider OAuthProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Generate state token
		state, err := generateState()
		if err != nil {
			s.logger.Error("failed to generate state", zap.Error(err))
			writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
			return
		}

		// Store state in cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "oauth_state",
			Value:    state,
			Path:     "/",
			MaxAge:   600, // 10 minutes
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
		})

		// Build callback URL
		callbackURL := s.config.AppBaseURL + "/auth/" + name + "/callback"
		if s.config.CallbackPath != "" {
			callbackURL = s.config.AppBaseURL + s.config.CallbackPath + "/" + name
		}
		if s.config.CallbackPath != "" {
			callbackURL = s.config.AppBaseURL + s.config.CallbackPath + "/" + name
		}

		// Redirect to provider
		authURL := provider.AuthURL(state, callbackURL)
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

// handleOAuthCallback handles the OAuth callback from the provider.
func (s *AuthService) handleOAuthCallback(name string, provider OAuthProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Verify state
		stateCookie, err := r.Cookie("oauth_state")
		if err != nil {
			writeError(w, http.StatusBadRequest, CodeBadRequest, "missing state cookie")
			return
		}

		state := r.URL.Query().Get("state")
		if state == "" || state != stateCookie.Value {
			writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid state")
			return
		}

		// Clear state cookie
		http.SetCookie(w, &http.Cookie{
			Name:   "oauth_state",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})

		// Check for error from provider
		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			errDesc := r.URL.Query().Get("error_description")
			writeError(w, http.StatusBadRequest, "OAUTH_ERROR", errMsg+": "+errDesc)
			return
		}

		// Get authorization code
		code := r.URL.Query().Get("code")
		if code == "" {
			writeError(w, http.StatusBadRequest, CodeBadRequest, "missing code")
			return
		}

		// Build callback URL
		callbackURL := s.config.AppBaseURL + "/auth/" + name + "/callback"

		// Exchange code for tokens
		tokens, err := provider.ExchangeCode(ctx, code, callbackURL)
		if err != nil {
			s.logger.Error("oauth token exchange failed", zap.Error(err), zap.String("provider", name))
			writeError(w, http.StatusInternalServerError, CodeInternalError, "authentication failed")
			return
		}

		// Get user info
		oauthUser, err := provider.GetUser(ctx, tokens.AccessToken)
		if err != nil {
			s.logger.Error("oauth get user failed", zap.Error(err), zap.String("provider", name))
			writeError(w, http.StatusInternalServerError, CodeInternalError, "failed to get user info")
			return
		}

		// Find or create user
		user, isNew, err := s.findOrCreateOAuthUser(ctx, name, oauthUser, r)
		if err != nil {
			switch err {
			case ErrEmailAlreadyExists:
				writeError(w, http.StatusConflict, CodeEmailExists, ErrEmailAlreadyExists.Error())
			case ErrAccountNotVerified:
				writeError(w, http.StatusForbidden, CodeAccountNotVerified, ErrAccountNotVerified.Error())
			case ErrDisposableEmail:
				writeError(w, http.StatusBadRequest, CodeDisposableEmail, ErrDisposableEmail.Error())
			default:
				s.logger.Error("oauth user create failed", zap.Error(err))
				writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
			}
			return
		}

		// Store OAuth tokens when supported
		if s.oauthTokenManager != nil {
			if _, ok := s.store.(OAuthTokenStore); ok {
				if err := s.oauthTokenManager.StoreTokens(ctx, user.ID, name, tokens); err != nil {
					s.logger.Warn("oauth token store failed", zap.Error(err), zap.String("provider", name))
				}
			}
		}

		if s.config.Require2FAForOAuth && user.TOTPEnabled {
			tempToken, err := crypto.NewTemp2FAToken(s.jwtSecret, user.ID, 5*time.Minute)
			if err != nil {
				s.logger.Error("temp token error", zap.Error(err))
				writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"requires_2fa":  true,
				"temp_token":    tempToken,
				"user_id":       user.ID,
				"email_verified": user.EmailVerified,
				"provider":      name,
			})
			return
		}

		// Issue tokens
		accessToken, refreshToken, err := s.issueTokens(ctx, user, r, false)
		if err != nil {
			s.logger.Error("token issue failed", zap.Error(err))
			writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
			return
		}

		ipEnc, ipNonce, _ := s.encryptIP(s.clientIP(r))
		s.store.Users().ResetLoginFailures(ctx, user.ID)
		s.store.Users().UpdateLastLogin(ctx, user.ID, ipEnc, ipNonce)

		// Log audit event
		if isNew {
			s.logAudit(ctx, user.ID, "oauth_register", r, map[string]any{"provider": name})
		} else {
			s.logAudit(ctx, user.ID, EventLoginSuccess, r, map[string]any{"provider": name})
		}
		s.CheckSuspiciousLogin(ctx, user, r)

		// Return tokens
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":   accessToken,
			"refresh_token":  refreshToken,
			"user_id":        user.ID,
			"email_verified": user.EmailVerified,
			"is_new_user":    isNew,
			"provider":       name,
		})
	}
}

// handleMe returns the current user's profile.
func (s *AuthService) handleMe(w http.ResponseWriter, r *http.Request) {
	user, ok := GetUserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, CodeInvalidToken, "unauthorized")
		return
	}

	// Decrypt email if we have it
	email := ""
	if user.EmailEncrypted != nil && s.keys != nil {
		decrypted, err := crypto.Decrypt(user.EmailEncrypted, user.EmailNonce, s.keys.EmailKey)
		if err == nil {
			email = string(decrypted)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":        user.ID,
		"email":          crypto.MaskEmail(email),
		"username":       user.Username,
		"email_verified": user.EmailVerified,
		"totp_enabled":   user.TOTPEnabled,
	})
}

// findOrCreateOAuthUser finds an existing user or creates a new one for OAuth.
func (s *AuthService) findOrCreateOAuthUser(ctx context.Context, provider string, oauthUser *OAuthUser, r *http.Request) (*User, bool, error) {
	if oauthUser == nil || oauthUser.ID == "" {
		return nil, false, errors.New("missing oauth user id")
	}

	var oauthStore OAuthConnectionStore
	if store, ok := s.store.(OAuthConnectionStore); ok {
		oauthStore = store
		if existing, err := store.GetUserByOAuthProvider(ctx, provider, oauthUser.ID); err == nil {
			return existing, false, nil
		}
	}

	// Try to find by email
	if oauthUser.Email != "" {
		email := strings.ToLower(strings.TrimSpace(oauthUser.Email))
		emailHash := crypto.HashWithPepper(email, s.pepper)
		existingUser, err := s.store.Users().GetUserByEmailHash(ctx, emailHash)
		if err == nil {
			if !s.config.AllowOAuthEmailLinking {
				return nil, false, ErrEmailAlreadyExists
			}
			if !oauthUser.EmailVerified && !s.config.AllowUnverifiedOAuthEmailLinking {
				return nil, false, ErrAccountNotVerified
			}
			if oauthStore != nil {
				_ = oauthStore.LinkOAuthConnection(ctx, existingUser.ID, provider, oauthUser.ID)
			}
			return existingUser, false, nil
		}
		if s.config.BlockDisposableEmails && s.isDisposableEmail(email) {
			return nil, false, ErrDisposableEmail
		}
	}

	if s.config.EmailVerificationRequired && !oauthUser.EmailVerified {
		return nil, false, ErrAccountNotVerified
	}

	username := ""
	usernameNormalized := ""
	if s.config.UsernameEnabled {
		generated, normalized, err := s.generateAvailableUsername(ctx, oauthUser.Email)
		if err != nil && s.config.UsernameRequired {
			return nil, false, ErrInvalidUsername
		}
		if err == nil {
			username = generated
			usernameNormalized = normalized
		}
	}

	// Create new user
	email := strings.ToLower(strings.TrimSpace(oauthUser.Email))
	emailHash := crypto.HashWithPepper(email, s.pepper)
	emailEnc, emailNonce, _ := crypto.Encrypt([]byte(email), s.keys.EmailKey)

	accountStatus := StatusActive
	if s.config.EmailVerificationRequired && !oauthUser.EmailVerified {
		accountStatus = StatusPendingVerification
	}

	newUser := User{
		EmailHash:      emailHash,
		EmailEncrypted: emailEnc,
		EmailNonce:     emailNonce,
		Username:       username,
		UsernameNormalized: usernameNormalized,
		EmailVerified:  oauthUser.EmailVerified,
		AccountStatus:  accountStatus,
	}

	var deadline time.Time
	if accountStatus == StatusPendingVerification && s.config.UnverifiedAccountTTL > 0 {
		deadline = time.Now().Add(s.config.UnverifiedAccountTTL)
	}

	userID, err := s.store.Users().CreateUser(ctx, newUser, deadline)
	if err != nil {
		return nil, false, err
	}

	newUser.ID = userID
	if oauthStore != nil {
		_ = oauthStore.LinkOAuthConnection(ctx, userID, provider, oauthUser.ID)
	}
	return &newUser, true, nil
}

// generateState generates a random state token for OAuth.
func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

