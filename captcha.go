package goauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ==================== CAPTCHA INTERFACE ====================

// CaptchaProvider defines the interface for CAPTCHA verification.
type CaptchaProvider interface {
	// Name returns the provider name
	Name() string
	// Verify checks if the CAPTCHA token is valid
	Verify(ctx context.Context, token, ip string) (bool, error)
}

// ==================== CLOUDFLARE TURNSTILE ====================

// TurnstileProvider implements CaptchaProvider for Cloudflare Turnstile.
type TurnstileProvider struct {
	secret    string
	verifyURL string
	client    *http.Client
}

// NewTurnstile creates a Cloudflare Turnstile CAPTCHA provider.
// Get your site key and secret from: https://dash.cloudflare.com/turnstile
func NewTurnstile(secret string) *TurnstileProvider {
	return &TurnstileProvider{
		secret:    secret,
		verifyURL: "https://challenges.cloudflare.com/turnstile/v0/siteverify",
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

func (t *TurnstileProvider) Name() string {
	return "turnstile"
}

func (t *TurnstileProvider) Verify(ctx context.Context, token, ip string) (bool, error) {
	if token == "" {
		return false, nil
	}

	data := url.Values{}
	data.Set("secret", t.secret)
	data.Set("response", token)
	if ip != "" {
		data.Set("remoteip", ip)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", t.verifyURL, strings.NewReader(data.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := t.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var result struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, err
	}

	return result.Success, nil
}

// ==================== GOOGLE RECAPTCHA ====================

// ReCaptchaProvider implements CaptchaProvider for Google reCAPTCHA.
type ReCaptchaProvider struct {
	secret    string
	verifyURL string
	minScore  float64 // For reCAPTCHA v3 (0.0 to 1.0)
	client    *http.Client
}

// ReCaptchaConfig holds reCAPTCHA configuration.
type ReCaptchaConfig struct {
	// Secret is your reCAPTCHA secret key
	Secret string
	// MinScore is the minimum score for v3 (0.0 to 1.0, default 0.5)
	MinScore float64
	// IsV3 indicates whether this is reCAPTCHA v3 (score-based)
	IsV3 bool
}

// NewReCaptcha creates a Google reCAPTCHA provider.
// Get your keys from: https://www.google.com/recaptcha/admin
func NewReCaptcha(secret string) *ReCaptchaProvider {
	return &ReCaptchaProvider{
		secret:    secret,
		verifyURL: "https://www.google.com/recaptcha/api/siteverify",
		minScore:  0.5,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// NewReCaptchaV3 creates a Google reCAPTCHA v3 provider with score threshold.
func NewReCaptchaV3(secret string, minScore float64) *ReCaptchaProvider {
	if minScore <= 0 || minScore > 1 {
		minScore = 0.5
	}
	return &ReCaptchaProvider{
		secret:    secret,
		verifyURL: "https://www.google.com/recaptcha/api/siteverify",
		minScore:  minScore,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

func (r *ReCaptchaProvider) Name() string {
	return "recaptcha"
}

func (r *ReCaptchaProvider) Verify(ctx context.Context, token, ip string) (bool, error) {
	if token == "" {
		return false, nil
	}

	data := url.Values{}
	data.Set("secret", r.secret)
	data.Set("response", token)
	if ip != "" {
		data.Set("remoteip", ip)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", r.verifyURL, strings.NewReader(data.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := r.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var result struct {
		Success bool    `json:"success"`
		Score   float64 `json:"score"` // Only for v3
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, err
	}

	if !result.Success {
		return false, nil
	}

	// For v3, also check score
	if r.minScore > 0 && result.Score > 0 {
		return result.Score >= r.minScore, nil
	}

	return true, nil
}

// ==================== HCAPTCHA ====================

// HCaptchaProvider implements CaptchaProvider for hCaptcha.
type HCaptchaProvider struct {
	secret    string
	verifyURL string
	client    *http.Client
}

// NewHCaptcha creates an hCaptcha provider.
// Get your keys from: https://dashboard.hcaptcha.com
func NewHCaptcha(secret string) *HCaptchaProvider {
	return &HCaptchaProvider{
		secret:    secret,
		verifyURL: "https://api.hcaptcha.com/siteverify",
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

func (h *HCaptchaProvider) Name() string {
	return "hcaptcha"
}

func (h *HCaptchaProvider) Verify(ctx context.Context, token, ip string) (bool, error) {
	if token == "" {
		return false, nil
	}

	data := url.Values{}
	data.Set("secret", h.secret)
	data.Set("response", token)
	if ip != "" {
		data.Set("remoteip", ip)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", h.verifyURL, strings.NewReader(data.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := h.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}

	var result struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, err
	}

	return result.Success, nil
}

// ==================== CAPTCHA OPTIONS ====================

// WithCaptcha sets the CAPTCHA provider.
func WithCaptcha(provider CaptchaProvider) Option {
	return func(s *AuthService) error {
		s.captcha = provider
		s.config.CaptchaRequired = true
		return nil
	}
}

// WithTurnstile adds Cloudflare Turnstile CAPTCHA.
func WithTurnstile(secret string) Option {
	return func(s *AuthService) error {
		s.captcha = NewTurnstile(secret)
		s.config.TurnstileEnabled = true
		s.config.TurnstileSecret = secret
		s.config.CaptchaRequired = true
		return nil
	}
}

// WithReCaptcha adds Google reCAPTCHA v2.
func WithReCaptcha(secret string) Option {
	return func(s *AuthService) error {
		s.captcha = NewReCaptcha(secret)
		s.config.CaptchaRequired = true
		return nil
	}
}

// WithReCaptchaV3 adds Google reCAPTCHA v3 with score threshold.
func WithReCaptchaV3(secret string, minScore float64) Option {
	return func(s *AuthService) error {
		s.captcha = NewReCaptchaV3(secret, minScore)
		s.config.CaptchaRequired = true
		return nil
	}
}

// WithHCaptcha adds hCaptcha.
func WithHCaptcha(secret string) Option {
	return func(s *AuthService) error {
		s.captcha = NewHCaptcha(secret)
		s.config.CaptchaRequired = true
		return nil
	}
}

// WithCaptchaRequired enables or disables CAPTCHA enforcement.
func WithCaptchaRequired(required bool) Option {
	return func(s *AuthService) error {
		s.config.CaptchaRequired = required
		return nil
	}
}

// WithCaptchaFailOpen controls whether captcha errors allow the request.
func WithCaptchaFailOpen(enabled bool) Option {
	return func(s *AuthService) error {
		s.config.CaptchaFailOpen = enabled
		return nil
	}
}

func (s *AuthService) shouldRequireCaptcha(kind string) bool {
	if !s.config.CaptchaRequired {
		return false
	}
	switch kind {
	case "register":
		return s.config.CaptchaOnRegister
	case "login":
		return s.config.CaptchaOnLogin
	case "password_reset":
		return s.config.CaptchaOnPasswordReset
	case "magic_link":
		return s.config.CaptchaOnMagicLink
	default:
		return true
	}
}

func (s *AuthService) verifyCaptcha(ctx context.Context, token, ip, kind string) (bool, error) {
	if !s.shouldRequireCaptcha(kind) {
		return true, nil
	}
	if s.captcha == nil {
		return false, errors.New("captcha provider not configured")
	}
	return s.captcha.Verify(ctx, token, ip)
}
