package goauth

import (
	"context"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/migueldesapazr-gif/goauth/crypto"
)

// ==================== MULTI-TENANT SUPPORT ====================

// Tenant represents an organization/workspace in multi-tenant mode.
type Tenant struct {
	ID          string
	Name        string
	Slug        string // URL-friendly identifier
	Plan        string // "free", "pro", "enterprise"
	Settings    TenantSettings
	CreatedAt   time.Time
	SuspendedAt *time.Time
}

// TenantSettings holds per-tenant configuration.
type TenantSettings struct {
	MaxUsers          int
	AllowedDomains    []string // Email domains allowed to register
	EnforceMFA        bool     // Require 2FA for all users
	SessionTimeout    time.Duration
	AllowedOAuthProviders []string
	CustomBranding    map[string]string // logo_url, primary_color, etc.
}

// TenantStore handles tenant operations.
type TenantStore interface {
	GetTenant(ctx context.Context, tenantID string) (*Tenant, error)
	GetTenantBySlug(ctx context.Context, slug string) (*Tenant, error)
	CreateTenant(ctx context.Context, tenant Tenant) (string, error)
	UpdateTenantSettings(ctx context.Context, tenantID string, settings TenantSettings) error
	GetUserTenants(ctx context.Context, userID string) ([]Tenant, error)
}

// contextKeyTenant is the context key for tenant.
const contextKeyTenant contextKey = "goauth_tenant"

// GetTenantFromContext retrieves the current tenant from context.
func GetTenantFromContext(ctx context.Context) (*Tenant, bool) {
	tenant, ok := ctx.Value(contextKeyTenant).(*Tenant)
	return tenant, ok
}

// TenantMiddleware extracts tenant from request and adds to context.
func (s *AuthService) TenantMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.tenantStore == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Try to get tenant from various sources
			var tenantID string

			// 1. From header
			tenantID = r.Header.Get("X-Tenant-ID")

			// 2. From subdomain
			if tenantID == "" {
				host := r.Host
				if idx := strings.Index(host, "."); idx > 0 {
					subdomain := host[:idx]
					if subdomain != "www" && subdomain != "api" {
						// Look up by slug
						tenant, err := s.tenantStore.GetTenantBySlug(r.Context(), subdomain)
						if err == nil {
							tenantID = tenant.ID
						}
					}
				}
			}

			// 3. From URL path (e.g., /tenant/acme/...)
			if tenantID == "" {
				parts := strings.Split(r.URL.Path, "/")
				for i, part := range parts {
					if part == "tenant" && i+1 < len(parts) {
						tenant, err := s.tenantStore.GetTenantBySlug(r.Context(), parts[i+1])
						if err == nil {
							tenantID = tenant.ID
						}
						break
					}
				}
			}

			if tenantID != "" {
				tenant, err := s.tenantStore.GetTenant(r.Context(), tenantID)
				if err == nil && tenant.SuspendedAt == nil {
					ctx := context.WithValue(r.Context(), contextKeyTenant, tenant)
					r = r.WithContext(ctx)
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ==================== SESSION MANAGEMENT ====================

// Session represents an active user session.
type Session struct {
	ID          string
	UserID      string
	TenantID    string // For multi-tenant
	DeviceID    string
	ExpiresAt   time.Time
	CreatedAt   time.Time
	LastActive  time.Time
	IPAddress   []byte // Encrypted
	IPNonce     []byte
	UserAgent   string
	Data        map[string]any // Custom session data
}

// SessionStore handles session persistence.
type SessionStore interface {
	CreateSession(ctx context.Context, session Session) error
	GetSession(ctx context.Context, sessionID string) (*Session, error)
	UpdateSession(ctx context.Context, sessionID string, data map[string]any) error
	ExtendSession(ctx context.Context, sessionID string, expiresAt time.Time) error
	DeleteSession(ctx context.Context, sessionID string) error
	DeleteUserSessions(ctx context.Context, userID string) error
}

// ==================== WEBHOOKS ====================

// WebhookEvent represents an event that can trigger webhooks.
type WebhookEvent string

const (
	WebhookEventUserCreated       WebhookEvent = "user.created"
	WebhookEventUserVerified      WebhookEvent = "user.verified"
	WebhookEventUserLogin         WebhookEvent = "user.login"
	WebhookEventUserLogout        WebhookEvent = "user.logout"
	WebhookEventUserPasswordReset WebhookEvent = "user.password_reset"
	WebhookEvent2FAEnabled        WebhookEvent = "user.2fa_enabled"
	WebhookEvent2FADisabled       WebhookEvent = "user.2fa_disabled"
	WebhookEventAccountLocked     WebhookEvent = "user.account_locked"
	WebhookEventAccountDeleted    WebhookEvent = "user.account_deleted"
	WebhookEventSuspiciousLogin   WebhookEvent = "security.suspicious_login"
)

// Webhook represents a configured webhook.
type Webhook struct {
	ID        string
	URL       string
	Secret    string // For signature verification
	Events    []WebhookEvent
	TenantID  string // Optional, for multi-tenant
	Active    bool
	CreatedAt time.Time
}

// WebhookPayload is sent to webhook endpoints.
type WebhookPayload struct {
	Event     WebhookEvent   `json:"event"`
	Timestamp time.Time      `json:"timestamp"`
	Data      map[string]any `json:"data"`
}

// WebhookStore handles webhook configuration.
type WebhookStore interface {
	GetActiveWebhooks(ctx context.Context, event WebhookEvent, tenantID string) ([]Webhook, error)
	CreateWebhook(ctx context.Context, webhook Webhook) (string, error)
	DeleteWebhook(ctx context.Context, webhookID string) error
}

// TriggerWebhook sends an event to configured webhooks.
func (s *AuthService) TriggerWebhook(ctx context.Context, event WebhookEvent, data map[string]any) {
	if s.webhookStore == nil {
		return
	}

	tenantID := ""
	if tenant, ok := GetTenantFromContext(ctx); ok {
		tenantID = tenant.ID
	}

	webhooks, err := s.webhookStore.GetActiveWebhooks(ctx, event, tenantID)
	if err != nil || len(webhooks) == 0 {
		return
	}

	payload := WebhookPayload{
		Event:     event,
		Timestamp: time.Now(),
		Data:      data,
	}

	// Send async
	for _, wh := range webhooks {
		go s.sendWebhook(wh, payload)
	}
}

func (s *AuthService) sendWebhook(wh Webhook, payload WebhookPayload) {
	// Implementation with retry, signature, etc.
	// This would use the http client to POST to wh.URL
	s.logger.Debug("webhook sent", zap.String("event", string(payload.Event)), zap.String("url", wh.URL))
}

// ==================== AUDIT EXPORT ====================

// AuditExporter allows exporting audit logs for compliance.
type AuditExporter interface {
	ExportUserAuditLogs(ctx context.Context, userID string, format string) ([]byte, error)
	ExportTenantAuditLogs(ctx context.Context, tenantID string, from, to time.Time, format string) ([]byte, error)
}

// handleExportAuditLogs exports audit logs for the current user (GDPR compliance).
func (s *AuthService) handleExportAuditLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	exporter, ok := s.store.(AuditExporter)
	if !ok {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "audit export not available")
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	data, err := exporter.ExportUserAuditLogs(ctx, user.ID, format)
	if err != nil {
		s.logger.Error("export audit logs error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	contentType := "application/json"
	if format == "csv" {
		contentType = "text/csv"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename=audit_logs."+format)
	w.Write(data)
}

// ==================== GDPR COMPLIANCE ====================

// handleDeleteAccount handles GDPR "right to deletion" requests.
func (s *AuthService) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	var req struct {
		Password string `json:"password"`
		Confirm  bool   `json:"confirm"`
	}
	if err := readJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "invalid request")
		return
	}

	if !req.Confirm {
		writeError(w, http.StatusBadRequest, CodeBadRequest, "confirmation required")
		return
	}

	// Verify password
	if !crypto.VerifyPassword(req.Password, user.PasswordHash, user.PasswordSalt) {
		writeError(w, http.StatusUnauthorized, CodeInvalidCredentials, "invalid password")
		return
	}

	// Delete user data
	if deleter, ok := s.store.(UserDeleter); ok {
		if err := deleter.DeleteUser(ctx, user.ID); err != nil {
			s.logger.Error("delete user error", zap.Error(err))
			writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
			return
		}
	}

	// Trigger webhook
	s.TriggerWebhook(ctx, WebhookEventAccountDeleted, map[string]any{
		"user_id": user.ID,
	})

	s.logAudit(ctx, user.ID, "account_deleted", r, nil)
	writeJSON(w, http.StatusOK, map[string]any{"message": "account deleted"})
}

// handleExportData exports all user data (GDPR right to data portability).
func (s *AuthService) handleExportData(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	exporter, ok := s.store.(DataExporter)
	if !ok {
		writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "data export not available")
		return
	}

	data, err := exporter.ExportUserData(ctx, user.ID)
	if err != nil {
		s.logger.Error("export data error", zap.Error(err))
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=user_data.json")
	w.Write(data)
}

// UserDeleter handles user deletion.
type UserDeleter interface {
	DeleteUser(ctx context.Context, userID string) error
}

// DataExporter handles data export.
type DataExporter interface {
	ExportUserData(ctx context.Context, userID string) ([]byte, error)
}

// ==================== OPTIONS ====================

// WithMultiTenant enables multi-tenant support.
func WithMultiTenant(store TenantStore) Option {
	return func(s *AuthService) error {
		s.tenantStore = store
		return nil
	}
}

// WithDeviceManagement enables device/session management.
func WithDeviceManagement(store DeviceStore) Option {
	return func(s *AuthService) error {
		s.deviceStore = store
		return nil
	}
}

// WithWebhooks enables webhook support.
func WithWebhooks(store WebhookStore) Option {
	return func(s *AuthService) error {
		s.webhookStore = store
		return nil
	}
}

// WithAPIKeys enables API key support.
func WithAPIKeys(store APIKeyStore) Option {
	return func(s *AuthService) error {
		s.apiKeyStore = store
		return nil
	}
}

// WithMagicLinks enables passwordless magic link login.
func WithMagicLinks() Option {
	return func(s *AuthService) error {
		s.config.MagicLinksEnabled = true
		return nil
	}
}


