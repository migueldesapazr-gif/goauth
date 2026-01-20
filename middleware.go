package goauth

import (
	"context"
	"encoding/hex"
	"net"
	"net/http"
	"strings"

	"github.com/migueldesapazr-gif/goauth/crypto"
)

// contextKey is a type for context keys to avoid collisions.
type contextKey string

const (
	// UserContextKey is the context key for the authenticated user.
	UserContextKey contextKey = "goauth_user"
	// ClaimsContextKey is the context key for JWT claims.
	ClaimsContextKey contextKey = "goauth_claims"
)

// GetUserFromContext retrieves the authenticated user from the request context.
func GetUserFromContext(ctx context.Context) (*User, bool) {
	user, ok := ctx.Value(UserContextKey).(*User)
	return user, ok
}

// GetClaimsFromContext retrieves the JWT claims from the request context.
func GetClaimsFromContext(ctx context.Context) (*crypto.Claims, bool) {
	claims, ok := ctx.Value(ClaimsContextKey).(*crypto.Claims)
	return claims, ok
}

// requireAuth is middleware that requires a valid JWT access token.
func (s *AuthService) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenStr := bearerTokenFromHeader(r.Header.Get("Authorization"))
		if tokenStr == "" {
			writeError(w, http.StatusUnauthorized, CodeInvalidToken, "missing or invalid authorization header")
			return
		}

		claims, err := crypto.ParseToken(s.jwtSecret, tokenStr)
		if err != nil {
			writeError(w, http.StatusUnauthorized, CodeInvalidToken, "invalid or expired token")
			return
		}

		if claims.TokenType != crypto.TokenTypeAccess {
			writeError(w, http.StatusUnauthorized, CodeInvalidToken, "invalid token type")
			return
		}

		if s.tokenBlacklist != nil {
			if claims.ID == "" {
				writeError(w, http.StatusUnauthorized, CodeInvalidToken, "invalid token")
				return
			}
			blacklisted, err := s.tokenBlacklist.IsBlacklisted(r.Context(), claims.ID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, CodeInternalError, "internal error")
				return
			}
			if blacklisted {
				writeError(w, http.StatusUnauthorized, CodeInvalidToken, "token revoked")
				return
			}
		}

		// Get user from database
		user, err := s.store.Users().GetUserByID(r.Context(), claims.Subject)
		if err != nil {
			writeError(w, http.StatusUnauthorized, CodeInvalidToken, "user not found")
			return
		}

		if user.AccountStatus == StatusLocked {
			writeError(w, http.StatusForbidden, CodeAccountLocked, ErrAccountLocked.Error())
			return
		}
		if user.AccountStatus == StatusSuspended {
			writeError(w, http.StatusForbidden, CodeAccountSuspended, ErrAccountSuspended.Error())
			return
		}
		if user.AccountStatus == StatusDeleted {
			writeError(w, http.StatusForbidden, CodeAccountSuspended, "account deleted")
			return
		}

		if s.config.RequireVerifiedEmailForAuth && !user.EmailVerified {
			writeError(w, http.StatusForbidden, CodeAccountNotVerified, ErrAccountNotVerified.Error())
			return
		}
		if s.config.Require2FAForAuth && !claims.TwoFAVerified {
			writeError(w, http.StatusForbidden, Code2FARequired, Err2FARequired.Error())
			return
		}

		// Add user and claims to context
		ctx := context.WithValue(r.Context(), UserContextKey, user)
		ctx = context.WithValue(ctx, ClaimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAuthMiddleware returns middleware that validates JWT tokens.
// Use this to protect your own routes with GoAuth authentication.
func (s *AuthService) RequireAuthMiddleware() func(http.Handler) http.Handler {
	return s.requireAuth
}

// RequireVerifiedEmail enforces email verification for protected routes.
func (s *AuthService) RequireVerifiedEmail() func(http.Handler) http.Handler {
	return s.requireCondition(func(user *User, claims *crypto.Claims) (bool, string, string) {
		if user.EmailVerified || (claims != nil && claims.EmailVerified) {
			return true, "", ""
		}
		return false, CodeAccountNotVerified, ErrAccountNotVerified.Error()
	})
}

// Require2FA enforces a completed second factor on protected routes.
func (s *AuthService) Require2FA() func(http.Handler) http.Handler {
	return s.requireCondition(func(user *User, claims *crypto.Claims) (bool, string, string) {
		if claims != nil && claims.TwoFAVerified {
			return true, "", ""
		}
		return false, Code2FARequired, Err2FARequired.Error()
	})
}

type conditionFunc func(user *User, claims *crypto.Claims) (bool, string, string)

func (s *AuthService) requireCondition(check conditionFunc) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := GetUserFromContext(r.Context())
			if !ok {
				writeError(w, http.StatusUnauthorized, CodeInvalidToken, "unauthorized")
				return
			}
			claims, _ := GetClaimsFromContext(r.Context())
			allowed, code, message := check(user, claims)
			if !allowed {
				writeError(w, http.StatusForbidden, code, message)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// GetClientIP extracts the client IP from the request without trust rules.
func GetClientIP(r *http.Request) string {
	return parseIPFromAddr(r.RemoteAddr)
}

func bearerTokenFromHeader(authHeader string) string {
	if authHeader == "" {
		return ""
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return parts[1]
}

func (s *AuthService) clientIP(r *http.Request) string {
	remoteIP := parseIPFromAddr(r.RemoteAddr)
	if !s.config.TrustProxyHeaders || remoteIP == "" {
		return remoteIP
	}
	if !s.isTrustedProxy(remoteIP) {
		return remoteIP
	}

	cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP"))
	if cf != "" && net.ParseIP(cf) != nil {
		return cf
	}
	tci := strings.TrimSpace(r.Header.Get("True-Client-IP"))
	if tci != "" && net.ParseIP(tci) != nil {
		return tci
	}
	if forwarded := r.Header.Get("Forwarded"); forwarded != "" {
		if ip := parseForwardedFor(forwarded, s.isTrustedProxy); ip != "" {
			return ip
		}
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if ip == "" {
				continue
			}
			parsed := net.ParseIP(ip)
			if parsed == nil {
				continue
			}
			if !s.isTrustedProxy(parsed.String()) {
				return parsed.String()
			}
		}
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	xri := r.Header.Get("X-Real-IP")
	if xri != "" && net.ParseIP(strings.TrimSpace(xri)) != nil {
		return strings.TrimSpace(xri)
	}

	return remoteIP
}

func (s *AuthService) isRequestSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if !s.config.TrustProxyHeaders {
		return false
	}
	remoteIP := parseIPFromAddr(r.RemoteAddr)
	if remoteIP == "" || !s.isTrustedProxy(remoteIP) {
		return false
	}
	if proto := firstForwardedProto(r.Header.Get("X-Forwarded-Proto")); strings.EqualFold(proto, "https") {
		return true
	}
	if proto := firstForwardedProto(r.Header.Get("X-Forwarded-Scheme")); strings.EqualFold(proto, "https") {
		return true
	}
	if proto := parseForwardedProto(r.Header.Get("Forwarded")); strings.EqualFold(proto, "https") {
		return true
	}
	cfVisitor := strings.ToLower(strings.TrimSpace(r.Header.Get("CF-Visitor")))
	if strings.Contains(cfVisitor, "\"scheme\":\"https\"") {
		return true
	}
	return false
}

func (s *AuthService) isTrustedProxy(ip string) bool {
	if len(s.trustedProxyNets) == 0 {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, network := range s.trustedProxyNets {
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

func parseIPFromAddr(addr string) string {
	if addr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}
	if strings.HasPrefix(addr, "[") && strings.Contains(addr, "]") {
		return strings.TrimPrefix(strings.SplitN(addr, "]", 2)[0], "[")
	}
	return addr
}

func parseForwardedFor(header string, isTrusted func(string) bool) string {
	if header == "" {
		return ""
	}
	var ips []string
	parts := strings.Split(header, ",")
	for _, part := range parts {
		params := strings.Split(part, ";")
		for _, param := range params {
			param = strings.TrimSpace(param)
			if len(param) < 4 || strings.ToLower(param[:4]) != "for=" {
				continue
			}
			val := strings.TrimSpace(param[4:])
			val = strings.Trim(val, "\"")
			if strings.EqualFold(val, "unknown") || val == "" {
				continue
			}
			if strings.HasPrefix(val, "[") && strings.Contains(val, "]") {
				val = strings.TrimPrefix(val, "[")
				val = strings.SplitN(val, "]", 2)[0]
			}
			if host, _, err := net.SplitHostPort(val); err == nil {
				val = host
			}
			if net.ParseIP(val) == nil {
				continue
			}
			ips = append(ips, val)
		}
	}
	if len(ips) == 0 {
		return ""
	}
	for i := len(ips) - 1; i >= 0; i-- {
		if !isTrusted(ips[i]) {
			return ips[i]
		}
	}
	return ips[0]
}

func parseForwardedProto(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.Split(header, ",")
	for _, part := range parts {
		params := strings.Split(part, ";")
		for _, param := range params {
			param = strings.TrimSpace(param)
			if len(param) < 6 || strings.ToLower(param[:6]) != "proto=" {
				continue
			}
			value := strings.Trim(strings.TrimSpace(param[6:]), "\"")
			if value != "" {
				return value
			}
		}
	}
	return ""
}

func firstForwardedProto(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.Split(header, ",")
	return strings.TrimSpace(parts[0])
}

// hashIP hashes an IP address for privacy-preserving logging.
func (s *AuthService) hashIP(ip string) string {
	sum := crypto.HashWithPepper(ip, s.keys.MetaKey)
	return hex.EncodeToString(sum)
}

// encryptIP encrypts an IP address for storage.
func (s *AuthService) encryptIP(ip string) ([]byte, []byte, error) {
	if ip == "" || !s.config.IPPrivacy.StoreIP {
		return nil, nil, nil
	}
	if !s.config.IPPrivacy.EncryptIP {
		return []byte(ip), nil, nil
	}
	return crypto.Encrypt([]byte(ip), s.keys.IPKey)
}

func (s *AuthService) auditIP(ip string) ([]byte, []byte, error) {
	if ip == "" {
		return nil, nil, nil
	}
	if !s.config.IPPrivacy.StoreIP {
		if s.config.IPPrivacy.HashIPInLogs {
			sum := crypto.HashWithPepper(ip, s.keys.MetaKey)
			return sum, nil, nil
		}
		return nil, nil, nil
	}
	return s.encryptIP(ip)
}

