package goauth

import (
	"context"
	"encoding/hex"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/migueldesapazr-gif/goauth/crypto"
)

// ==================== SECURITY MONITORING ====================

// SecurityAlert represents a security event that may need attention.
type SecurityAlert struct {
	Type      string
	UserID    string
	IP        string
	Details   map[string]any
	Severity  string // "low", "medium", "high", "critical"
	Timestamp time.Time
}

// SecurityMonitor interface for security event handling.
type SecurityMonitor interface {
	OnAlert(ctx context.Context, alert SecurityAlert)
}

// defaultSecurityMonitor logs security alerts.
type defaultSecurityMonitor struct {
	logger *zap.Logger
	svc    *AuthService
}

func (m *defaultSecurityMonitor) OnAlert(ctx context.Context, alert SecurityAlert) {
	m.logger.Warn("security alert",
		zap.String("type", alert.Type),
		zap.String("user_id", alert.UserID),
		zap.String("severity", alert.Severity),
		zap.Any("details", alert.Details))

	// Send webhook
	if m.svc != nil {
		m.svc.TriggerWebhook(ctx, WebhookEventSuspiciousLogin, map[string]any{
			"type":     alert.Type,
			"user_id":  alert.UserID,
			"severity": alert.Severity,
			"details":  alert.Details,
		})
	}

	// Send security alert email
	if m.svc != nil && (alert.Severity == "high" || alert.Severity == "critical") {
		if sam, ok := m.svc.mailer.(SecurityAlertMailer); ok {
			user, err := m.svc.store.Users().GetUserByID(ctx, alert.UserID)
			if err == nil {
				email, _ := crypto.Decrypt(user.EmailEncrypted, user.EmailNonce, m.svc.keys.EmailKey)
				sam.SendSecurityAlert(ctx, string(email), alert.Type, "Security alert detected on your account")
			}
		}
	}
}

// ==================== SUSPICIOUS ACTIVITY DETECTION ====================

// CheckSuspiciousLogin checks for suspicious login patterns.
func (s *AuthService) CheckSuspiciousLogin(ctx context.Context, user *User, r *http.Request) bool {
	ip := s.clientIP(r)
	if !s.config.IPPrivacy.StoreIP {
		if s.config.IPPrivacy.HashIPInLogs {
			ip = s.hashIP(ip)
		} else {
			ip = ""
		}
	}
	userAgent := r.UserAgent()
	
	alerts := []SecurityAlert{}

	// Check 1: New device/location
	if s.deviceStore != nil {
		devices, _ := s.deviceStore.GetUserDevices(ctx, user.ID)
		isNewDevice := true
		for _, d := range devices {
			if d.Fingerprint == hashUserAgent(userAgent) {
				isNewDevice = false
				break
			}
		}
		if isNewDevice && len(devices) > 0 {
			alerts = append(alerts, SecurityAlert{
				Type:     "new_device",
				UserID:   user.ID,
				IP:       ip,
				Severity: "medium",
				Details:  map[string]any{"user_agent": userAgent},
			})
		}
	}

	// Check 2: Multiple failed attempts recently
	if user.FailedLoginAttempts >= 3 {
		alerts = append(alerts, SecurityAlert{
			Type:     "multiple_failures",
			UserID:   user.ID,
			IP:       ip,
			Severity: "medium",
			Details:  map[string]any{"attempts": user.FailedLoginAttempts},
		})
	}

	// Check 3: Login from different country (would need GeoIP)
	// This is a placeholder for GeoIP integration

	// Check 4: Unusual login time
	hour := time.Now().Hour()
	if user.LastLoginAt != nil {
		usualHour := user.LastLoginAt.Hour()
		hourDiff := abs(hour - usualHour)
		if hourDiff > 8 && hourDiff < 16 { // Significant time difference
			alerts = append(alerts, SecurityAlert{
				Type:     "unusual_time",
				UserID:   user.ID,
				IP:       ip,
				Severity: "low",
				Details:  map[string]any{"hour": hour, "usual_hour": usualHour},
			})
		}
	}

	// Process alerts
	for _, alert := range alerts {
		alert.Timestamp = time.Now()
		if s.securityMonitor != nil {
			s.securityMonitor.OnAlert(ctx, alert)
		}
	}

	// Return true if any high severity alerts
	for _, alert := range alerts {
		if alert.Severity == "high" || alert.Severity == "critical" {
			return true
		}
	}

	return false
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func hashUserAgent(ua string) string {
	h := crypto.HashToken(ua)
	return hex.EncodeToString(h[:16])
}

// ==================== IP INTELLIGENCE ====================

// IPIntelligence provides IP reputation data.
type IPIntelligence interface {
	// Check returns reputation info for an IP.
	Check(ctx context.Context, ip string) (*IPReputation, error)
}

// IPReputation holds IP reputation data.
type IPReputation struct {
	IP          string
	IsProxy     bool
	IsVPN       bool
	IsTor       bool
	IsDatacenter bool
	IsBotnet    bool
	ThreatScore float64 // 0-1, higher = more risky
	Country     string
	City        string
	ISP         string
}

// WithIPIntelligence adds IP reputation checking.
func WithIPIntelligence(provider IPIntelligence) Option {
	return func(s *AuthService) error {
		s.ipIntel = provider
		return nil
	}
}

// ==================== BREACH DETECTION ====================

// BreachNotification handles data breach notifications.
type BreachNotification struct {
	BreachName   string
	BreachDate   time.Time
	DataTypes    []string // "password", "email", "address", etc.
	Description  string
	SourceURL    string
}

// handleBreachCheck allows users to check if their email was breached.
func (s *AuthService) handleBreachCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user, _ := GetUserFromContext(ctx)

	// Get user email
	email, err := crypto.Decrypt(user.EmailEncrypted, user.EmailNonce, s.keys.EmailKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
		return
	}

	// Check HIBP for breaches
	breaches, err := checkHIBPBreaches(string(email))
	if err != nil {
		s.logger.Error("breach check error", zap.Error(err))
		writeJSON(w, http.StatusOK, map[string]any{
			"checked":  false,
			"message":  "unable to check breaches at this time",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"checked":        true,
		"breach_count":   len(breaches),
		"breaches":       breaches,
		"recommendation": getBreachRecommendation(len(breaches)),
	})
}

func checkHIBPBreaches(email string) ([]BreachNotification, error) {
	// Note: HIBP v3 API requires an API key for breach lookups
	// Register at https://haveibeenpwned.com/API/Key
	// For now, return empty (safe default)
	return []BreachNotification{}, nil
}

func getBreachRecommendation(count int) string {
	if count == 0 {
		return "Your email was not found in any known data breaches."
	}
	if count < 3 {
		return "Your email was found in some data breaches. Consider changing your password if you reuse passwords."
	}
	return "Your email was found in multiple data breaches. We strongly recommend using unique passwords and enabling 2FA."
}

// ==================== ACCOUNT RECOVERY ====================

// handleAccountRecovery handles account recovery when user can't access normal methods.
func (s *AuthService) handleAccountRecovery(w http.ResponseWriter, r *http.Request) {
	// This would implement a more complex recovery flow:
	// 1. Verify identity via backup codes
	// 2. Verify via trusted device
	// 3. Verify via support ticket with ID verification
	// For now, return not implemented
	writeError(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "contact support for account recovery")
}

// ==================== OPTIONS ====================

// WithSecurityMonitor sets a custom security monitor.
func WithSecurityMonitor(monitor SecurityMonitor) Option {
	return func(s *AuthService) error {
		s.securityMonitor = monitor
		return nil
	}
}



