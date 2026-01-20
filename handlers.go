package goauth

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"image/png"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"

	"github.com/migueldesapazr-gif/goauth/crypto"
)

// handleRegister handles user registration.
func (s *AuthService) handleRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientIP := s.clientIP(r)

	if s.isIPBlocked(ctx, clientIP) {
		writeError(w, http.StatusTooManyRequests, CodeIPBlocked, ErrIPBlocked.Error())
		return
	}

	// Rate limiting
	allowed, err := s.allowRateLimit(ctx, "register:"+s.hashIP(clientIP), s.config.RateLimits.RegisterLimit, s.config.RateLimits.RegisterWindow)
	if err != nil {
		s.logger.Error("rate limit error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}
	if !allowed {
		writeError(w, http.StatusTooManyRequests, CodeRateLimited, ErrRateLimited.Error())
		return
	}

	var req registerRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}

	captchaToken := req.CaptchaToken
	if captchaToken == "" {
		captchaToken = req.TurnstileToken
	}
	ok, err := s.verifyCaptcha(ctx, captchaToken, clientIP, "register")
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

	// Validate email
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !isValidEmail(email) {
		writeError(w, http.StatusBadRequest, CodeInvalidEmail, ErrInvalidEmail.Error())
		return
	}

	// Check email domain if enabled
	if s.config.EmailDomainCheck {
		if !hasValidMX(email) {
			writeError(w, http.StatusBadRequest, CodeInvalidEmail, "email domain does not accept mail")
			return
		}
	}
	if s.config.BlockDisposableEmails && s.isDisposableEmail(email) {
		writeError(w, http.StatusBadRequest, CodeDisposableEmail, ErrDisposableEmail.Error())
		return
	}

	username := strings.TrimSpace(req.Username)
	if err := s.validateUsername(username); err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidUsername, err.Error())
		return
	}
	if !s.config.UsernameEnabled {
		username = ""
	}
	usernameNormalized := normalizeUsername(username)
	if s.config.UsernameEnabled && usernameNormalized != "" {
		exists, err := s.store.Users().UsernameExists(ctx, usernameNormalized)
		if err != nil {
			s.logger.Error("db error", zap.Error(err))
			writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
			return
		}
		if exists {
			writeError(w, http.StatusConflict, CodeUsernameExists, ErrUsernameAlreadyExists.Error())
			return
		}
	}

	// Validate password strength
	if err := s.validatePassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, CodeWeakPassword, err.Error())
		return
	}

	// Check HIBP if enabled
	if s.config.HIBPEnabled {
		pwned, err := s.isPasswordPwned(ctx, req.Password)
		if err != nil {
			s.logger.Warn("hibp check failed", zap.Error(err))
		} else if pwned {
			writeError(w, http.StatusBadRequest, CodePasswordBreached, ErrPasswordBreached.Error())
			return
		}
	}

	// Hash email for lookup
	emailHash := crypto.HashWithPepper(email, s.pepper)

	// Check if email exists
	exists, err := s.store.Users().EmailExists(ctx, emailHash)
	if err != nil {
		s.logger.Error("db error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}
	if exists {
		writeError(w, http.StatusConflict, CodeEmailExists, ErrEmailAlreadyExists.Error())
		return
	}

	// Encrypt email for storage
	emailEnc, emailNonce, err := crypto.Encrypt([]byte(email), s.keys.EmailKey)
	if err != nil {
		s.logger.Error("encrypt error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	// Hash password
	salt, err := crypto.GenerateSalt(crypto.DefaultSaltSize)
	if err != nil {
		s.logger.Error("salt error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}
	passwordHash := crypto.HashPassword(req.Password, salt)

	accountStatus := StatusActive
	if s.config.EmailVerificationRequired {
		accountStatus = StatusPendingVerification
	}

	// Create user
	user := User{
		EmailHash:      emailHash,
		EmailEncrypted: emailEnc,
		EmailNonce:     emailNonce,
		Username:       username,
		UsernameNormalized: usernameNormalized,
		PasswordHash:   passwordHash,
		PasswordSalt:   salt,
		AccountStatus:  accountStatus,
		EmailVerified:  false,
	}

	var deadline time.Time
	if s.config.EmailVerificationRequired && s.config.UnverifiedAccountTTL > 0 {
		deadline = time.Now().Add(s.config.UnverifiedAccountTTL)
	}
	userID, err := s.store.Users().CreateUser(ctx, user, deadline)
	if err != nil {
		s.logger.Error("create user error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	// Generate access token (limited until verified)
	accessToken, err := crypto.NewAccessToken(s.jwtSecret, userID, false, false, s.config.AccessTokenTTL)
	if err != nil {
		s.logger.Error("token error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	message := "Account created"
	if s.config.EmailVerificationRequired {
		message = "Please verify your email to activate your account"
	}

	s.logAudit(ctx, userID, EventRegister, r, nil)

	writeJSON(w, http.StatusCreated, map[string]any{
		"user_id":        userID,
		"access_token":   accessToken,
		"email_masked":   crypto.MaskEmail(email),
		"email_verified": false,
		"message":        message,
	})
}

// handleLogin handles user login.
func (s *AuthService) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientIP := s.clientIP(r)

	if s.isIPBlocked(ctx, clientIP) {
		writeError(w, http.StatusTooManyRequests, CodeIPBlocked, ErrIPBlocked.Error())
		return
	}

	// Rate limiting by IP
	allowed, err := s.allowRateLimit(ctx, "login:"+s.hashIP(clientIP), s.config.RateLimits.LoginLimit, s.config.RateLimits.LoginWindow)
	if err != nil {
		s.logger.Error("rate limit error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}
	if !allowed {
		writeError(w, http.StatusTooManyRequests, CodeRateLimited, ErrRateLimited.Error())
		return
	}

	var req loginRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}

	captchaToken := req.CaptchaToken
	if captchaToken == "" {
		captchaToken = req.TurnstileToken
	}
	ok, err := s.verifyCaptcha(ctx, captchaToken, clientIP, "login")
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

	identifier := strings.TrimSpace(req.Username)
	if identifier == "" {
		identifier = strings.TrimSpace(req.Email)
	}
	if identifier == "" {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "missing email or username")
		return
	}

	var user *User

	if strings.Contains(identifier, "@") {
		email := strings.ToLower(identifier)
		emailHash := crypto.HashWithPepper(email, s.pepper)
		user, err = s.store.Users().GetUserByEmailHash(ctx, emailHash)
	} else {
		if !s.config.UsernameEnabled {
			// Use dummy hash to prevent timing attacks
			dummySalt, _ := crypto.GenerateSalt(crypto.DefaultSaltSize)
			crypto.HashPassword(req.Password, dummySalt)
			writeError(w, http.StatusUnauthorized, CodeInvalidCredentials, ErrInvalidCredentials.Error())
			return
		}
		username := normalizeUsername(identifier)
		user, err = s.store.Users().GetUserByUsername(ctx, username)
	}
	if err != nil {
		// Use dummy hash to prevent timing attacks
		dummySalt, _ := crypto.GenerateSalt(crypto.DefaultSaltSize)
		crypto.HashPassword(req.Password, dummySalt)
		s.recordIPFailure(ctx, clientIP, "login")
		writeError(w, http.StatusUnauthorized, CodeInvalidCredentials, ErrInvalidCredentials.Error())
		return
	}

	// Check account status
	switch user.AccountStatus {
	case StatusLocked:
		if s.config.LockoutDuration > 0 && user.LockedAt != nil {
			if time.Since(*user.LockedAt) >= s.config.LockoutDuration {
				_ = s.store.Users().UnlockUser(ctx, user.ID)
				_ = s.store.Users().ResetLoginFailures(ctx, user.ID)
				user.AccountStatus = StatusActive
			} else {
				writeError(w, http.StatusForbidden, CodeAccountLocked, ErrAccountLocked.Error())
				return
			}
		} else {
			writeError(w, http.StatusForbidden, CodeAccountLocked, ErrAccountLocked.Error())
			return
		}
	case StatusSuspended:
		writeError(w, http.StatusForbidden, CodeAccountSuspended, ErrAccountSuspended.Error())
		return
	case StatusDeleted:
		writeError(w, http.StatusForbidden, CodeAccountSuspended, "account deleted")
		return
	}

	// Verify password
	if !crypto.VerifyPassword(req.Password, user.PasswordHash, user.PasswordSalt) {
		// Increment failed attempts when lockout is enabled
		if s.config.MaxLoginAttempts > 0 {
			attempts, _ := s.store.Users().IncrementLoginFailures(ctx, user.ID)
			if attempts >= s.config.MaxLoginAttempts {
				s.store.Users().LockUser(ctx, user.ID)
				s.logAudit(ctx, user.ID, EventLoginFailed, r, nil)
				writeError(w, http.StatusForbidden, CodeAccountLocked, ErrAccountLocked.Error())
				return
			}
		}
		s.logAudit(ctx, user.ID, EventLoginFailed, r, nil)
		s.recordIPFailure(ctx, clientIP, "login")
		writeError(w, http.StatusUnauthorized, CodeInvalidCredentials, ErrInvalidCredentials.Error())
		return
	}

	if s.config.EmailVerificationRequired && !user.EmailVerified {
		writeError(w, http.StatusForbidden, CodeAccountNotVerified, ErrAccountNotVerified.Error())
		return
	}

	// Check if 2FA is required
	if user.TOTPEnabled {
		tempToken, err := crypto.NewTemp2FAToken(s.jwtSecret, user.ID, 5*time.Minute)
		if err != nil {
			s.logger.Error("temp token error", zap.Error(err))
			writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"requires_2fa": true,
			"temp_token":   tempToken,
		})
		return
	}

	// Issue tokens
	accessToken, refreshToken, err := s.issueTokens(ctx, user, r, false)
	if err != nil {
		s.logger.Error("issue tokens error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	// Reset failed attempts and update last login
	s.store.Users().ResetLoginFailures(ctx, user.ID)
	ipEnc, ipNonce, _ := s.encryptIP(clientIP)
	s.store.Users().UpdateLastLogin(ctx, user.ID, ipEnc, ipNonce)
	s.logAudit(ctx, user.ID, EventLoginSuccess, r, nil)
	s.CheckSuspiciousLogin(ctx, user, r)

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":   accessToken,
		"refresh_token":  refreshToken,
		"user_id":        user.ID,
		"email_verified": user.EmailVerified,
		"totp_enabled":   user.TOTPEnabled,
	})
}

// handleLogin2FA handles the second factor authentication.
func (s *AuthService) handleLogin2FA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientIP := s.clientIP(r)

	if s.isIPBlocked(ctx, clientIP) {
		writeError(w, http.StatusTooManyRequests, CodeIPBlocked, ErrIPBlocked.Error())
		return
	}

	// Rate limiting
	allowed, err := s.allowRateLimit(ctx, "2fa:"+s.hashIP(clientIP), s.config.RateLimits.TwoFALimit, s.config.RateLimits.TwoFAWindow)
	if err != nil {
		s.logger.Error("rate limit error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}
	if !allowed {
		writeError(w, http.StatusTooManyRequests, CodeRateLimited, ErrRateLimited.Error())
		return
	}

	var req login2FARequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}

	// Parse temp token
	claims, err := crypto.ParseToken(s.jwtSecret, req.TempToken)
	if err != nil || claims.TokenType != crypto.TokenType2FA {
		writeError(w, http.StatusUnauthorized, CodeInvalidToken, ErrInvalidToken.Error())
		return
	}

	// Get user
	user, err := s.store.Users().GetUserByID(ctx, claims.Subject)
	if err != nil {
		writeError(w, http.StatusUnauthorized, CodeInvalidToken, ErrInvalidToken.Error())
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
		writeError(w, http.StatusForbidden, CodeAccountNotVerified, ErrAccountNotVerified.Error())
		return
	}

	// Verify TOTP or backup code
	valid, usedBackup, err := s.verifyTOTPOrBackup(ctx, user, req.TOTPCode, req.BackupCode)
	if err != nil {
		s.logger.Error("totp verify error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}
	if !valid {
		s.recordIPFailure(ctx, clientIP, "2fa")
		writeError(w, http.StatusUnauthorized, CodeInvalid2FACode, ErrInvalid2FACode.Error())
		return
	}

	// Issue tokens
	accessToken, refreshToken, err := s.issueTokens(ctx, user, r, true)
	if err != nil {
		s.logger.Error("issue tokens error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	// Reset failed attempts and update last login
	s.store.Users().ResetLoginFailures(ctx, user.ID)
	ipEnc, ipNonce, _ := s.encryptIP(clientIP)
	s.store.Users().UpdateLastLogin(ctx, user.ID, ipEnc, ipNonce)
	s.logAudit(ctx, user.ID, EventLoginSuccess, r, nil)
	s.CheckSuspiciousLogin(ctx, user, r)

	resp := map[string]any{
		"access_token":   accessToken,
		"refresh_token":  refreshToken,
		"user_id":        user.ID,
		"email_verified": user.EmailVerified,
		"totp_enabled":   user.TOTPEnabled,
	}

	if usedBackup {
		resp["warning"] = "You used a backup code. Please generate new backup codes."
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleRefresh handles token refresh.
func (s *AuthService) handleRefresh(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req refreshRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}

	// Parse refresh token
	claims, err := crypto.ParseToken(s.jwtSecret, req.RefreshToken)
	if err != nil || claims.TokenType != crypto.TokenTypeRefresh {
		writeError(w, http.StatusUnauthorized, CodeInvalidToken, ErrInvalidToken.Error())
		return
	}
	if claims.ID == "" {
		writeError(w, http.StatusUnauthorized, CodeInvalidToken, ErrInvalidToken.Error())
		return
	}

	// Check if refresh token is valid in database
	valid, err := s.store.Tokens().RefreshTokenValid(ctx, claims.ID)
	if err != nil {
		s.logger.Error("refresh token check error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}
	if !valid {
		writeError(w, http.StatusUnauthorized, CodeInvalidToken, ErrInvalidToken.Error())
		return
	}

	// Get user
	user, err := s.store.Users().GetUserByID(ctx, claims.Subject)
	if err != nil {
		writeError(w, http.StatusUnauthorized, CodeInvalidToken, ErrInvalidToken.Error())
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

	twoFAVerified := claims.TwoFAVerified && user.TOTPEnabled
	accessToken, err := crypto.NewAccessTokenWithOptions(
		s.jwtSecret,
		user.ID,
		user.EmailVerified,
		twoFAVerified,
		s.config.AccessTokenTTL,
		crypto.AccessTokenOptions{
			DeviceID: claims.DeviceID,
			Scope:    claims.Scope,
		},
	)
	if err != nil {
		s.logger.Error("access token error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	if s.config.RotateRefreshTokens {
		_ = s.store.Tokens().RevokeRefreshToken(ctx, claims.ID)
		jti := uuid.New().String()
		refreshToken, err := crypto.NewRefreshTokenWithOptions(
			s.jwtSecret,
			user.ID,
			s.config.RefreshTokenTTL,
			crypto.RefreshTokenOptions{
				JTI:           jti,
				EmailVerified: user.EmailVerified,
				TwoFAVerified: twoFAVerified,
				DeviceID:      claims.DeviceID,
				Scope:         claims.Scope,
			},
		)
		if err != nil {
			s.logger.Error("refresh token error", zap.Error(err))
			writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
			return
		}
		ipEnc, ipNonce, _ := s.encryptIP(s.clientIP(r))
		expiresAt := time.Now().Add(s.config.RefreshTokenTTL)
		if err := s.store.Tokens().StoreRefreshToken(ctx, user.ID, jti, expiresAt, ipEnc, ipNonce); err != nil {
			s.logger.Error("refresh token store error", zap.Error(err))
			writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": accessToken,
	})
}

// handleLogout handles user logout.
func (s *AuthService) handleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	var req logoutRequest
	if err := readJSON(w, r, &req); err != nil {
		// Even without a body, revoke all tokens
		s.store.Tokens().RevokeAllRefreshTokens(ctx, user.ID)
		s.blacklistAccessToken(ctx, r)
		s.logAudit(ctx, user.ID, EventLogout, r, nil)
		writeJSON(w, http.StatusOK, map[string]any{"message": "logged out"})
		return
	}

	// Revoke specific refresh token if provided
	if req.RefreshToken != "" {
		claims, err := crypto.ParseToken(s.jwtSecret, req.RefreshToken)
		if err == nil && claims.TokenType == crypto.TokenTypeRefresh {
			s.store.Tokens().RevokeRefreshToken(ctx, claims.ID)
		}
	}

	s.blacklistAccessToken(ctx, r)
	s.logAudit(ctx, user.ID, EventLogout, r, nil)
	writeJSON(w, http.StatusOK, map[string]any{"message": "logged out"})
}

func (s *AuthService) blacklistAccessToken(ctx context.Context, r *http.Request) {
	if s.tokenBlacklist == nil {
		return
	}
	tokenStr := bearerTokenFromHeader(r.Header.Get("Authorization"))
	if tokenStr == "" {
		return
	}
	claims, err := crypto.ParseToken(s.jwtSecret, tokenStr)
	if err != nil || claims.TokenType != crypto.TokenTypeAccess || claims.ID == "" || claims.ExpiresAt == nil {
		return
	}
	_ = s.tokenBlacklist.Add(ctx, claims.ID, claims.ExpiresAt.Time)
}

// issueTokens creates access and refresh tokens for a user.
func (s *AuthService) issueTokens(ctx context.Context, user *User, r *http.Request, twoFAVerified bool) (string, string, error) {
	accessToken, err := crypto.NewAccessTokenWithOptions(
		s.jwtSecret,
		user.ID,
		user.EmailVerified,
		twoFAVerified,
		s.config.AccessTokenTTL,
		crypto.AccessTokenOptions{},
	)
	if err != nil {
		return "", "", err
	}

	jti := uuid.New().String()
	refreshToken, err := crypto.NewRefreshTokenWithOptions(
		s.jwtSecret,
		user.ID,
		s.config.RefreshTokenTTL,
		crypto.RefreshTokenOptions{
			JTI:           jti,
			EmailVerified: user.EmailVerified,
			TwoFAVerified: twoFAVerified,
		},
	)
	if err != nil {
		return "", "", err
	}

	// Store refresh token
	ipEnc, ipNonce, _ := s.encryptIP(s.clientIP(r))
	expiresAt := time.Now().Add(s.config.RefreshTokenTTL)
	if err := s.store.Tokens().StoreRefreshToken(ctx, user.ID, jti, expiresAt, ipEnc, ipNonce); err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// verifyTOTPOrBackup verifies a TOTP code or backup code.
func (s *AuthService) verifyTOTPOrBackup(ctx context.Context, user *User, totpCode, backupCode string) (bool, bool, error) {
	// Try backup code first if provided
	if backupCode != "" {
		codeHash := s.hashBackupCode(backupCode)
		used, err := s.store.Users().UseBackupCode(ctx, user.ID, codeHash)
		if err != nil {
			return false, false, err
		}
		if used {
			return true, true, nil
		}
		legacyHash := crypto.HashToken(backupCode)
		used, err = s.store.Users().UseBackupCode(ctx, user.ID, legacyHash)
		if err != nil {
			return false, false, err
		}
		return used, true, nil
	}

	// Verify TOTP
	if totpCode == "" {
		return false, false, nil
	}

	// Decrypt TOTP secret
	secret, err := crypto.Decrypt(user.TOTPSecretEncrypted, user.TOTPNonce, s.keys.TOTPKey)
	if err != nil {
		return false, false, err
	}

	// Use ValidateCustom with time skew tolerance for clock drift (+/-1 step = 30 seconds)
	valid, err := totp.ValidateCustom(totpCode, string(secret), time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1, // Allow +/-30 seconds for clock drift
		Digits:    s.totpDigits(),
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return false, false, err
	}
	return valid, false, nil
}

// logAudit logs an audit event.
func (s *AuthService) logAudit(ctx context.Context, userID, eventType string, r *http.Request, metadata map[string]any) {
	clientIP := s.clientIP(r)
	ipEnc, ipNonce, _ := s.auditIP(clientIP)

	userAgent := r.Header.Get("User-Agent")
	var uaHash []byte
	if s.config.StoreUserAgentHash && userAgent != "" {
		sum := sha256.Sum256([]byte(userAgent))
		uaHash = sum[:]
	}

	var expiresAt *time.Time
	if s.config.AuditLogRetention > 0 {
		t := time.Now().Add(s.config.AuditLogRetention)
		expiresAt = &t
	}

	log := AuditLog{
		UserID:        userID,
		EventType:     eventType,
		IPEncrypted:   ipEnc,
		IPNonce:       ipNonce,
		UserAgentHash: uaHash,
	}
	if expiresAt != nil {
		log.ExpiresAt = *expiresAt
	}

	if err := s.store.Audit().InsertAuditLog(ctx, log); err != nil {
		s.logger.Error("audit log error", zap.Error(err))
	}
}

// Placeholder for handlers not yet implemented
func (s *AuthService) handleVerifySend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, ok := GetUserFromContext(ctx)
	if !ok {
		writeError(w, http.StatusUnauthorized, CodeInvalidToken, "unauthorized")
		return
	}

	if user.EmailVerified {
		writeJSON(w, http.StatusOK, map[string]any{
			"message": "email already verified",
		})
		return
	}

	// Generate verification code
	code, err := crypto.RandomCode(6)
	if err != nil {
		s.logger.Error("code generation error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	// Generate link token
	linkToken, err := crypto.RandomToken(32)
	if err != nil {
		s.logger.Error("link token error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	// Get user email
	email, err := crypto.Decrypt(user.EmailEncrypted, user.EmailNonce, s.keys.EmailKey)
	if err != nil {
		s.logger.Error("decrypt email error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	// Create verification token
	token := VerificationToken{
		UserID:      user.ID,
		CodeHash:    crypto.HashToken(code),
		LinkHash:    crypto.HashToken(linkToken),
		EmailHash:   user.EmailHash,
		ExpiresAt:   time.Now().Add(s.config.VerificationCodeTTL),
		MaxAttempts: s.config.MaxVerificationAttempts,
	}

	ipEnc, ipNonce, _ := s.encryptIP(s.clientIP(r))
	_, err = s.store.Tokens().CreateVerificationToken(ctx, token, ipEnc, ipNonce)
	if err != nil {
		s.logger.Error("create verification token error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	// Send verification email
	verifyLink := fmt.Sprintf("%s/verify?token=%s", s.config.AppBaseURL, linkToken)
	if err := s.mailer.SendVerification(ctx, string(email), code, verifyLink); err != nil {
		s.logger.Error("send email error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "failed to send email")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message":      "verification email sent",
		"email_masked": crypto.MaskEmail(string(email)),
	})
}

func (s *AuthService) handleVerifyCode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req verifyCodeRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}

	// Get active verification token
	token, err := s.store.Tokens().GetActiveVerificationToken(ctx, req.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidToken, ErrInvalidToken.Error())
		return
	}

	if token.Used || time.Now().After(token.ExpiresAt) {
		writeError(w, http.StatusBadRequest, CodeTokenExpired, ErrTokenExpired.Error())
		return
	}

	// Increment attempts
	attempts, err := s.store.Tokens().IncrementVerificationAttempts(ctx, token.ID)
	if err != nil {
		s.logger.Error("increment attempts error", zap.Error(err))
	}

	if attempts > token.MaxAttempts {
		writeError(w, http.StatusBadRequest, CodeTooManyAttempts, ErrTooManyAttempts.Error())
		return
	}

	// Verify code
	codeHash := crypto.HashToken(req.Code)
	if !crypto.ConstantTimeEquals(codeHash, token.CodeHash) {
		writeError(w, http.StatusBadRequest, CodeInvalidToken, "invalid code")
		return
	}

	// Mark token as used
	ipEnc, ipNonce, _ := s.encryptIP(s.clientIP(r))
	if err := s.store.Tokens().MarkVerificationTokenUsed(ctx, token.ID, ipEnc, ipNonce); err != nil {
		s.logger.Error("mark token used error", zap.Error(err))
	}

	// Set user as verified
	if err := s.store.Users().SetUserVerified(ctx, req.UserID); err != nil {
		s.logger.Error("set verified error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	s.logAudit(ctx, req.UserID, EventEmailVerified, r, nil)

	writeJSON(w, http.StatusOK, map[string]any{
		"message":        "email verified successfully",
		"email_verified": true,
	})
}

func (s *AuthService) handleVerifyLink(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	linkToken := r.URL.Query().Get("token")

	if linkToken == "" {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "missing token")
		return
	}

	// Get token by link hash
	linkHash := crypto.HashToken(linkToken)
	token, err := s.store.Tokens().GetVerificationTokenByLinkHash(ctx, linkHash)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidToken, ErrInvalidToken.Error())
		return
	}

	if token.Used || time.Now().After(token.ExpiresAt) {
		writeError(w, http.StatusBadRequest, CodeTokenExpired, ErrTokenExpired.Error())
		return
	}

	// Mark token as used
	ipEnc, ipNonce, _ := s.encryptIP(s.clientIP(r))
	if err := s.store.Tokens().MarkVerificationTokenUsed(ctx, token.ID, ipEnc, ipNonce); err != nil {
		s.logger.Error("mark token used error", zap.Error(err))
	}

	// Set user as verified
	if err := s.store.Users().SetUserVerified(ctx, token.UserID); err != nil {
		s.logger.Error("set verified error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	s.logAudit(ctx, token.UserID, EventEmailVerified, r, nil)

	// Redirect to success page
	http.Redirect(w, r, s.config.AppBaseURL+"/verified", http.StatusFound)
}

func (s *AuthService) handlePasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientIP := s.clientIP(r)

	if s.isIPBlocked(ctx, clientIP) {
		writeJSON(w, http.StatusOK, map[string]any{
			"message": "if the email exists, a reset link has been sent",
		})
		return
	}

	// Rate limiting
	allowed, err := s.allowRateLimit(ctx, "reset:"+s.hashIP(clientIP), s.config.RateLimits.PasswordResetLimit, s.config.RateLimits.PasswordResetWindow)
	if err != nil {
		s.logger.Error("rate limit error", zap.Error(err))
	}
	if !allowed {
		// Don't reveal rate limiting - just return success
		writeJSON(w, http.StatusOK, map[string]any{
			"message": "if the email exists, a reset link has been sent",
		})
		return
	}

	var req passwordResetRequestBody
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}

	captchaToken := req.CaptchaToken
	if captchaToken == "" {
		captchaToken = req.TurnstileToken
	}
	ok, err := s.verifyCaptcha(ctx, captchaToken, clientIP, "password_reset")
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

	email := strings.ToLower(strings.TrimSpace(req.Email))
	emailHash := crypto.HashWithPepper(email, s.pepper)

	// Always return success to prevent email enumeration
	defer func() {
		writeJSON(w, http.StatusOK, map[string]any{
			"message": "if the email exists, a reset link has been sent",
		})
	}()

	// Get user
	user, err := s.store.Users().GetUserByEmailHash(ctx, emailHash)
	if err != nil {
		return // Email doesn't exist, but don't reveal that
	}

	// Generate reset token
	resetToken, err := crypto.RandomToken(32)
	if err != nil {
		s.logger.Error("reset token error", zap.Error(err))
		return
	}

	// Create password reset token
	token := PasswordResetToken{
		UserID:    user.ID,
		TokenHash: crypto.HashToken(resetToken),
		ExpiresAt: time.Now().Add(s.config.PasswordResetTTL),
	}

	ipEnc, ipNonce, _ := s.encryptIP(clientIP)
	_, err = s.store.Tokens().CreatePasswordResetToken(ctx, token, ipEnc, ipNonce)
	if err != nil {
		s.logger.Error("create reset token error", zap.Error(err))
		return
	}

	// Send reset email
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", s.config.AppBaseURL, resetToken)
	decryptedEmail, _ := crypto.Decrypt(user.EmailEncrypted, user.EmailNonce, s.keys.EmailKey)
	if err := s.mailer.SendPasswordReset(ctx, string(decryptedEmail), resetLink); err != nil {
		s.logger.Error("send reset email error", zap.Error(err))
	}

	s.logAudit(ctx, user.ID, EventPasswordResetRequest, r, nil)
}

func (s *AuthService) handlePasswordResetConfirm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req passwordResetConfirmRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}

	// Validate password
	if err := s.validatePassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, CodeWeakPassword, err.Error())
		return
	}

	// Check HIBP if enabled
	if s.config.HIBPEnabled {
		pwned, err := s.isPasswordPwned(ctx, req.Password)
		if err != nil {
			s.logger.Warn("hibp check failed", zap.Error(err))
		} else if pwned {
			writeError(w, http.StatusBadRequest, CodePasswordBreached, ErrPasswordBreached.Error())
			return
		}
	}

	// Get token
	tokenHash := crypto.HashToken(req.Token)
	token, err := s.store.Tokens().GetPasswordResetTokenByHash(ctx, tokenHash)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidToken, ErrInvalidToken.Error())
		return
	}

	if token.Used || time.Now().After(token.ExpiresAt) {
		writeError(w, http.StatusBadRequest, CodeTokenExpired, ErrTokenExpired.Error())
		return
	}

	// Check password history
	if s.config.PasswordHistorySize > 0 {
		history, err := s.store.Users().RecentPasswordHistory(ctx, token.UserID, s.config.PasswordHistorySize)
		if err != nil {
			s.logger.Error("password history error", zap.Error(err))
		}
		for _, h := range history {
			if crypto.VerifyPassword(req.Password, h.Hash, h.Salt) {
				writeError(w, http.StatusBadRequest, CodePasswordReused, ErrPasswordReused.Error())
				return
			}
		}
	}

	// Update password
	salt, err := crypto.GenerateSalt(crypto.DefaultSaltSize)
	if err != nil {
		s.logger.Error("salt error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}
	passwordHash := crypto.HashPassword(req.Password, salt)

	if err := s.store.Users().UpdatePassword(ctx, token.UserID, passwordHash, salt); err != nil {
		s.logger.Error("update password error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	// Mark token as used
	ipEnc, ipNonce, _ := s.encryptIP(s.clientIP(r))
	s.store.Tokens().MarkPasswordResetUsed(ctx, token.ID, ipEnc, ipNonce)

	// Revoke all refresh tokens for security
	s.store.Tokens().RevokeAllRefreshTokens(ctx, token.UserID)

	s.logAudit(ctx, token.UserID, EventPasswordChanged, r, nil)
	s.logAudit(ctx, token.UserID, EventPasswordResetComplete, r, nil)

	if s.config.NotifyOnPasswordChange {
		user, err := s.store.Users().GetUserByID(ctx, token.UserID)
		if err == nil {
			if pcm, ok := s.mailer.(PasswordChangeMailer); ok {
				if email, err := crypto.Decrypt(user.EmailEncrypted, user.EmailNonce, s.keys.EmailKey); err == nil {
					_ = pcm.SendPasswordChanged(ctx, string(email))
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "password reset successfully",
	})
}

func (s *AuthService) handleTwoFASetup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	if user.TOTPEnabled {
		writeError(w, http.StatusConflict, Code2FAAlreadyEnabled, Err2FAAlreadyEnabled.Error())
		return
	}

	// Get user email for TOTP issuer
	email, err := crypto.Decrypt(user.EmailEncrypted, user.EmailNonce, s.keys.EmailKey)
	if err != nil {
		s.logger.Error("decrypt email error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	accountName := string(email)
	if s.config.TOTPAccountName != "" {
		accountName = s.config.TOTPAccountName
	} else if s.config.TOTPUseUsername && user.Username != "" {
		accountName = user.Username
	}

	// Generate TOTP secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.config.AppName,
		AccountName: accountName,
		SecretSize:  32,
		Algorithm:   otp.AlgorithmSHA1,
		Digits:      s.totpDigits(),
	})
	if err != nil {
		s.logger.Error("totp generate error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	// Encrypt TOTP secret
	secretEnc, secretNonce, err := crypto.Encrypt([]byte(key.Secret()), s.keys.TOTPKey)
	if err != nil {
		s.logger.Error("encrypt secret error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	// Save encrypted secret (not enabled yet)
	if err := s.store.Users().UpdateTOTPSecret(ctx, user.ID, secretEnc, secretNonce); err != nil {
		s.logger.Error("update totp secret error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	resp := map[string]any{
		"secret":       key.Secret(),
		"url":          key.URL(),
		"issuer":       s.config.AppName,
		"account_name": accountName,
		"digits":       s.totpDigitsInt(),
		"message":      "scan the QR code and then verify with a code",
	}
	if s.config.TOTPQRCodeEnabled {
		pngB64, dataURL, err := s.buildTOTPQRCode(key.URL())
		if err != nil {
			s.logger.Warn("qr code generation failed", zap.Error(err))
		} else {
			resp["qr_code_png"] = pngB64
			resp["qr_code_data_url"] = dataURL
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *AuthService) handleTwoFAVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	var req twoFAVerifyRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}

	if user.TOTPEnabled {
		writeError(w, http.StatusConflict, Code2FAAlreadyEnabled, Err2FAAlreadyEnabled.Error())
		return
	}

	// Get current user (with secret)
	currentUser, err := s.store.Users().GetUserByID(ctx, user.ID)
	if err != nil || currentUser.TOTPSecretEncrypted == nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "2FA not set up")
		return
	}

	// Decrypt and verify
	secret, err := crypto.Decrypt(currentUser.TOTPSecretEncrypted, currentUser.TOTPNonce, s.keys.TOTPKey)
	if err != nil {
		s.logger.Error("decrypt secret error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	valid, err := totp.ValidateCustom(req.Code, string(secret), time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    s.totpDigits(),
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		s.logger.Error("totp verify error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}
	if !valid {
		writeError(w, http.StatusBadRequest, CodeInvalid2FACode, ErrInvalid2FACode.Error())
		return
	}

	// Enable TOTP
	if err := s.store.Users().EnableTOTP(ctx, user.ID); err != nil {
		s.logger.Error("enable totp error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	backupCodes, backupHashes, err := s.generateBackupCodes()
	if err != nil {
		s.logger.Error("backup code generation error", zap.Error(err))
		_ = s.store.Users().DisableTOTP(ctx, user.ID)
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	if err := s.store.Users().ReplaceBackupCodes(ctx, user.ID, backupHashes); err != nil {
		s.logger.Error("save backup codes error", zap.Error(err))
		_ = s.store.Users().DisableTOTP(ctx, user.ID)
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	s.logAudit(ctx, user.ID, Event2FAEnabled, r, nil)

	writeJSON(w, http.StatusOK, map[string]any{
		"message":      "2FA enabled successfully",
		"backup_codes": backupCodes,
		"backup_codes_count": len(backupCodes),
		"warning":      "save these backup codes in a safe place",
	})
}

func (s *AuthService) handleTwoFADisable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	var req twoFADisableRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}

	if !user.TOTPEnabled {
		writeError(w, http.StatusBadRequest, Code2FANotEnabled, Err2FANotEnabled.Error())
		return
	}

	// Verify password or a current factor
	passwordOk := false
	if req.Password != "" && crypto.VerifyPassword(req.Password, user.PasswordHash, user.PasswordSalt) {
		passwordOk = true
	}
	if !passwordOk {
		if req.TOTPCode == "" && req.BackupCode == "" {
			writeError(w, http.StatusBadRequest, CodeBadRequest, "password or 2FA code required")
			return
		}
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
	}

	// Disable TOTP
	if err := s.store.Users().DisableTOTP(ctx, user.ID); err != nil {
		s.logger.Error("disable totp error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	s.logAudit(ctx, user.ID, Event2FADisabled, r, nil)

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "2FA disabled successfully",
	})
}

func (s *AuthService) handleBackupCodesRegenerate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	if !user.TOTPEnabled {
		writeError(w, http.StatusBadRequest, Code2FANotEnabled, Err2FANotEnabled.Error())
		return
	}

	codes, err := s.regenerateBackupCodes(ctx, user.ID)
	if err != nil {
		s.logger.Error("regenerate backup codes error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	s.logAudit(ctx, user.ID, EventBackupCodesRegenerated, r, nil)
	writeJSON(w, http.StatusOK, map[string]any{
		"backup_codes":       codes,
		"backup_codes_count": len(codes),
		"warning":            "save these backup codes in a safe place",
	})
}

func (s *AuthService) handleBackupCodesDownload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	if !user.TOTPEnabled {
		writeError(w, http.StatusBadRequest, Code2FANotEnabled, Err2FANotEnabled.Error())
		return
	}

	codes, err := s.regenerateBackupCodes(ctx, user.ID)
	if err != nil {
		s.logger.Error("regenerate backup codes error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	s.logAudit(ctx, user.ID, EventBackupCodesRegenerated, r, nil)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"backup-codes.txt\"")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(strings.Join(codes, "\n") + "\n"))
}

// Helper for HIBP check (k-anonymity with SHA-1).
func (s *AuthService) isPasswordPwned(ctx context.Context, password string) (bool, error) {
	if s.config.HIBPAPIURL == "" {
		return false, fmt.Errorf("hibp api url not configured")
	}

	sum := sha1.Sum([]byte(password))
	hashStr := strings.ToUpper(hex.EncodeToString(sum[:]))
	prefix := hashStr[:5]
	suffix := hashStr[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.config.HIBPAPIURL+prefix, nil)
	if err != nil {
		return false, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("hibp returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	lines := strings.Split(string(body), "\n")

	for _, line := range lines {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) >= 1 && strings.EqualFold(parts[0], suffix) {
			return true, nil
		}
	}

	return false, nil
}

// Email validation helpers (simplified)
func isValidEmail(email string) bool {
	if len(email) < 5 || len(email) > 254 {
		return false
	}
	at := strings.LastIndex(email, "@")
	if at < 1 || at > len(email)-3 {
		return false
	}
	local := email[:at]
	domain := email[at+1:]
	if len(local) > 64 || len(domain) < 2 {
		return false
	}
	if strings.Contains(domain, "..") || !strings.Contains(domain, ".") {
		return false
	}
	return true
}

func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

func hasValidMX(email string) bool {
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	domain := email[at+1:]
	if domain == "" {
		return false
	}
	records, err := net.LookupMX(domain)
	return err == nil && len(records) > 0
}

func (s *AuthService) validateUsername(username string) error {
	if !s.config.UsernameEnabled {
		return nil
	}
	if username == "" {
		if s.config.UsernameRequired {
			return fmt.Errorf("username is required")
		}
		return nil
	}
	normalized := normalizeUsername(username)
	if strings.HasPrefix(normalized, ".") || strings.HasPrefix(normalized, "-") ||
		strings.HasSuffix(normalized, ".") || strings.HasSuffix(normalized, "-") {
		return fmt.Errorf("username cannot start or end with '.' or '-'")
	}
	minLen := s.config.MinUsernameLength
	if minLen <= 0 {
		minLen = 3
	}
	maxLen := s.config.MaxUsernameLength
	if maxLen <= 0 {
		maxLen = 32
	}
	if len(normalized) < minLen {
		return fmt.Errorf("username must be at least %d characters", minLen)
	}
	if len(normalized) > maxLen {
		return fmt.Errorf("username must be at most %d characters", maxLen)
	}
	if strings.Contains(normalized, "@") {
		return fmt.Errorf("username cannot contain @")
	}
	if !s.config.UsernameAllowNumericOnly {
		allDigits := true
		for _, c := range normalized {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return fmt.Errorf("username cannot be only numbers")
		}
	}
	for _, reserved := range s.config.UsernameReserved {
		if normalizeUsername(reserved) == normalized {
			return fmt.Errorf("username is reserved")
		}
	}
	if s.config.UsernamePattern != "" {
		re, err := regexp.Compile(s.config.UsernamePattern)
		if err != nil {
			return fmt.Errorf("username policy is invalid")
		}
		if !re.MatchString(normalized) {
			return fmt.Errorf("username does not match policy")
		}
	}
	for _, c := range normalized {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			continue
		}
		return fmt.Errorf("username contains invalid characters")
	}
	return nil
}

func (s *AuthService) generateAvailableUsername(ctx context.Context, base string) (string, string, error) {
	if !s.config.UsernameEnabled {
		return "", "", nil
	}
	candidate := normalizeUsername(base)
	if at := strings.Index(candidate, "@"); at > 0 {
		candidate = candidate[:at]
	}
	candidate = sanitizeUsername(candidate)
	candidate = strings.Trim(candidate, ".-")
	if candidate == "" {
		candidate = "user"
	}
	if err := s.validateUsername(candidate); err != nil {
		candidate = "user"
	}
	normalized := normalizeUsername(candidate)
	exists, err := s.store.Users().UsernameExists(ctx, normalized)
	if err == nil && !exists {
		return candidate, normalized, nil
	}
	maxLen := s.config.MaxUsernameLength
	if maxLen <= 0 {
		maxLen = 32
	}
	for i := 0; i < 5; i++ {
		suffix, err := crypto.RandomToken(3)
		if err != nil {
			return "", "", err
		}
		trimLen := maxLen - len(suffix) - 1
		name := candidate
		if trimLen > 0 && len(name) > trimLen {
			name = name[:trimLen]
		}
		name = name + "-" + suffix
		normalized = normalizeUsername(name)
		exists, err = s.store.Users().UsernameExists(ctx, normalized)
		if err == nil && !exists {
			return name, normalized, nil
		}
	}
	return "", "", errors.New("unable to generate username")
}

func sanitizeUsername(username string) string {
	var b strings.Builder
	for _, c := range username {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func (s *AuthService) validatePassword(password string) error {
	minLen := s.config.MinPasswordLength
	if minLen <= 0 {
		minLen = 8
	}
	if len(password) < minLen {
		return fmt.Errorf("password must be at least %d characters", minLen)
	}
	if len(password) > 128 {
		return fmt.Errorf("password must be at most 128 characters")
	}
	if s.config.RequirePasswordComplexity {
		hasUpper := false
		hasLower := false
		hasDigit := false
		for _, c := range password {
			if c >= 'A' && c <= 'Z' {
				hasUpper = true
			}
			if c >= 'a' && c <= 'z' {
				hasLower = true
			}
			if c >= '0' && c <= '9' {
				hasDigit = true
			}
		}
		if !hasUpper || !hasLower || !hasDigit {
			return fmt.Errorf("password must contain uppercase, lowercase, and digits")
		}
	}
	// Check for common passwords
	common := []string{"password", "12345678", "qwerty", "letmein"}
	lower := strings.ToLower(password)
	for _, c := range common {
		if strings.Contains(lower, c) {
			return fmt.Errorf("password is too common")
		}
	}
	return nil
}

func (s *AuthService) totpDigits() otp.Digits {
	if s.config.TOTPDigits == 8 {
		return otp.DigitsEight
	}
	return otp.DigitsSix
}

func (s *AuthService) totpDigitsInt() int {
	if s.config.TOTPDigits == 8 {
		return 8
	}
	return 6
}

func (s *AuthService) buildTOTPQRCode(url string) (string, string, error) {
	size := s.config.TOTPQRCodeSize
	if size <= 0 {
		size = 256
	}
	code, err := qr.Encode(url, qr.M, qr.Auto)
	if err != nil {
		return "", "", err
	}
	code, err = barcode.Scale(code, size, size)
	if err != nil {
		return "", "", err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, code); err != nil {
		return "", "", err
	}
	pngB64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	dataURL := "data:image/png;base64," + pngB64
	return pngB64, dataURL, nil
}

func (s *AuthService) hashBackupCode(code string) []byte {
	return crypto.HashTokenWithPepper(code, s.pepper)
}

func (s *AuthService) generateBackupCodes() ([]string, [][]byte, error) {
	count := s.config.BackupCodeCount
	if count <= 0 {
		count = 10
	}
	length := s.config.BackupCodeLength
	if length <= 0 {
		length = 8
	}
	alphabet := "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	digitsOnly := s.config.BackupCodeDigitsOnly

	codes := make([]string, 0, count)
	hashes := make([][]byte, 0, count)
	seen := make(map[string]struct{}, count)
	for len(codes) < count {
		var code string
		var err error
		if digitsOnly {
			code, err = crypto.RandomCode(length)
		} else {
			code, err = crypto.RandomString(length, alphabet)
		}
		if err != nil {
			return nil, nil, err
		}
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		codes = append(codes, code)
		hashes = append(hashes, s.hashBackupCode(code))
	}

	return codes, hashes, nil
}

func (s *AuthService) regenerateBackupCodes(ctx context.Context, userID string) ([]string, error) {
	codes, hashes, err := s.generateBackupCodes()
	if err != nil {
		return nil, err
	}
	if err := s.store.Users().ReplaceBackupCodes(ctx, userID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

// Base64 helpers
func b64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func b64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

