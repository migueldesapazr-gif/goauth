package goauth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/migueldesapazr-gif/goauth/crypto"
)

func (s *AuthService) handleEmailChangeRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, ok := GetUserFromContext(ctx)
	if !ok {
		writeError(w, http.StatusUnauthorized, CodeInvalidToken, "unauthorized")
		return
	}

	var req emailChangeRequest
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request body")
		return
	}

	if !crypto.VerifyPassword(req.Password, user.PasswordHash, user.PasswordSalt) {
		writeError(w, http.StatusUnauthorized, CodeInvalidCredentials, ErrInvalidCredentials.Error())
		return
	}

	if s.config.Require2FAForEmailChange && user.TOTPEnabled {
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

	newEmail := strings.ToLower(strings.TrimSpace(req.NewEmail))
	if !isValidEmail(newEmail) {
		writeError(w, http.StatusBadRequest, CodeInvalidEmail, ErrInvalidEmail.Error())
		return
	}
	if s.config.EmailDomainCheck && !hasValidMX(newEmail) {
		writeError(w, http.StatusBadRequest, CodeInvalidEmail, "email domain does not accept mail")
		return
	}
	if s.config.BlockDisposableEmails && s.isDisposableEmail(newEmail) {
		writeError(w, http.StatusBadRequest, CodeDisposableEmail, ErrDisposableEmail.Error())
		return
	}

	newEmailHash := crypto.HashWithPepper(newEmail, s.pepper)
	if crypto.ConstantTimeEquals(newEmailHash, user.EmailHash) {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "email already set")
		return
	}

	exists, err := s.store.Users().EmailExists(ctx, newEmailHash)
	if err != nil {
		s.logger.Error("db error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}
	if exists {
		writeError(w, http.StatusConflict, CodeEmailExists, ErrEmailAlreadyExists.Error())
		return
	}

	emailEnc, emailNonce, err := crypto.Encrypt([]byte(newEmail), s.keys.EmailKey)
	if err != nil {
		s.logger.Error("encrypt error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	tokenStr, err := crypto.RandomToken(32)
	if err != nil {
		s.logger.Error("token generation error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	token := EmailChangeToken{
		UserID:            user.ID,
		TokenHash:         crypto.HashToken(tokenStr),
		NewEmailHash:      newEmailHash,
		NewEmailEncrypted: emailEnc,
		NewEmailNonce:     emailNonce,
		ExpiresAt:         time.Now().Add(s.config.EmailChangeTTL),
	}

	ipEnc, ipNonce, _ := s.encryptIP(s.clientIP(r))
	if _, err := s.store.Tokens().CreateEmailChangeToken(ctx, token, ipEnc, ipNonce); err != nil {
		s.logger.Error("create email change token error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	if ecm, ok := s.mailer.(EmailChangeMailer); ok {
		link := fmt.Sprintf("%s/email/change/confirm?token=%s", s.config.AppBaseURL, tokenStr)
		if err := ecm.SendEmailChange(ctx, newEmail, link); err != nil {
			s.logger.Error("send email change error", zap.Error(err))
			writeError(w, http.StatusInternalServerError, CodeInternalError, "failed to send email")
			return
		}
	} else {
		writeError(w, http.StatusInternalServerError, CodeInternalError, "email change not supported")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "email change confirmation sent",
	})
}

func (s *AuthService) handleEmailChangeConfirm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tokenStr := r.URL.Query().Get("token")
	if tokenStr == "" {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "missing token")
		return
	}

	tokenHash := crypto.HashToken(tokenStr)
	token, err := s.store.Tokens().GetEmailChangeTokenByHash(ctx, tokenHash)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidToken, ErrInvalidToken.Error())
		return
	}
	if token.Used || time.Now().After(token.ExpiresAt) {
		writeError(w, http.StatusBadRequest, CodeTokenExpired, ErrTokenExpired.Error())
		return
	}

	user, err := s.store.Users().GetUserByID(ctx, token.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidToken, ErrInvalidToken.Error())
		return
	}
	oldEmail := ""
	if user.EmailEncrypted != nil {
		if decrypted, err := crypto.Decrypt(user.EmailEncrypted, user.EmailNonce, s.keys.EmailKey); err == nil {
			oldEmail = string(decrypted)
		}
	}

	if err := s.store.Users().UpdateEmail(ctx, token.UserID, token.NewEmailHash, token.NewEmailEncrypted, token.NewEmailNonce, true); err != nil {
		s.logger.Error("update email error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	ipEnc, ipNonce, _ := s.encryptIP(s.clientIP(r))
	_ = s.store.Tokens().MarkEmailChangeUsed(ctx, token.ID, ipEnc, ipNonce)

	if s.config.NotifyOnEmailChange && oldEmail != "" {
		if ecm, ok := s.mailer.(EmailChangedMailer); ok {
			newEmail, _ := crypto.Decrypt(token.NewEmailEncrypted, token.NewEmailNonce, s.keys.EmailKey)
			_ = ecm.SendEmailChanged(ctx, oldEmail, string(newEmail))
		}
	}

	s.logAudit(ctx, token.UserID, EventEmailChanged, r, nil)

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "email updated",
	})
}
