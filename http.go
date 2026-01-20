package goauth

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// maxBodySize is the maximum request body size (1MB).
const maxBodySize = 1 << 20

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// readJSON reads and unmarshals a JSON request body.
func readJSON(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("invalid JSON body")
	}
	return nil
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": message,
		"code":  code,
	})
}

// Request types for authentication endpoints.

type registerRequest struct {
	Email          string `json:"email"`
	Username       string `json:"username,omitempty"`
	Password       string `json:"password"`
	CaptchaToken   string `json:"captcha_token,omitempty"`
	TurnstileToken string `json:"cf_turnstile_token,omitempty"`
}

type loginRequest struct {
	Email          string `json:"email"`
	Username       string `json:"username,omitempty"`
	Password       string `json:"password"`
	CaptchaToken   string `json:"captcha_token,omitempty"`
	TurnstileToken string `json:"cf_turnstile_token,omitempty"`
}

type login2FARequest struct {
	TempToken  string `json:"temp_token"`
	TOTPCode   string `json:"totp_code,omitempty"`
	BackupCode string `json:"backup_code,omitempty"`
}

type verifySendRequest struct {
	UserID    string `json:"user_id"`
	Confirmed bool   `json:"confirmed"`
}

type verifyCodeRequest struct {
	UserID string `json:"user_id"`
	Code   string `json:"code"`
}

type passwordResetRequestBody struct {
	Email          string `json:"email"`
	CaptchaToken   string `json:"captcha_token,omitempty"`
	TurnstileToken string `json:"cf_turnstile_token,omitempty"`
}

type passwordResetConfirmRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type twoFAVerifyRequest struct {
	Code string `json:"code"`
}

type twoFADisableRequest struct {
	Password   string `json:"password,omitempty"`
	TOTPCode   string `json:"totp_code,omitempty"`
	BackupCode string `json:"backup_code,omitempty"`
}

type emailChangeRequest struct {
	NewEmail   string `json:"new_email"`
	Password   string `json:"password"`
	TOTPCode   string `json:"totp_code,omitempty"`
	BackupCode string `json:"backup_code,omitempty"`
}

// Turnstile verification.

