package goauth

import (
	"context"
	"net/http"
	"strings"
)

// ==================== ROLES & PERMISSIONS ====================

// Role represents a user role.
type Role string

const (
	RoleUser      Role = "user"
	RoleAdmin     Role = "admin"
	RoleModerator Role = "moderator"
	RoleService   Role = "service" // For service-to-service auth
)

// Permission represents a specific permission.
type Permission string

// Common permissions
const (
	PermissionRead   Permission = "read"
	PermissionWrite  Permission = "write"
	PermissionDelete Permission = "delete"
	PermissionAdmin  Permission = "admin"
)

// RolePermissions maps roles to their permissions.
var DefaultRolePermissions = map[Role][]Permission{
	RoleUser:      {PermissionRead},
	RoleModerator: {PermissionRead, PermissionWrite},
	RoleAdmin:     {PermissionRead, PermissionWrite, PermissionDelete, PermissionAdmin},
	RoleService:   {PermissionRead, PermissionWrite},
}

// ==================== AUTHORIZATION MIDDLEWARE ====================

// RequireRole creates middleware that requires the user to have a specific role.
func (s *AuthService) RequireRole(roles ...Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := GetUserFromContext(r.Context())
			if !ok {
				writeError(w, http.StatusUnauthorized, CodeInvalidToken, "unauthorized")
				return
			}

			userRole := Role(user.Role)
			for _, role := range roles {
				if userRole == role {
					next.ServeHTTP(w, r)
					return
				}
			}

			writeError(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		})
	}
}

// RequirePermission creates middleware that requires a specific permission.
func (s *AuthService) RequirePermission(perm Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := GetUserFromContext(r.Context())
			if !ok {
				writeError(w, http.StatusUnauthorized, CodeInvalidToken, "unauthorized")
				return
			}

			if !s.HasPermission(user, perm) {
				writeError(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// HasPermission checks if a user has a specific permission.
func (s *AuthService) HasPermission(user *User, perm Permission) bool {
	role := Role(user.Role)
	if role == "" {
		role = RoleUser
	}

	// Check custom permissions first
	if s.rolePermissions != nil {
		if perms, ok := s.rolePermissions[role]; ok {
			for _, p := range perms {
				if p == perm {
					return true
				}
			}
			return false
		}
	}

	// Fall back to defaults
	if perms, ok := DefaultRolePermissions[role]; ok {
		for _, p := range perms {
			if p == perm {
				return true
			}
		}
	}

	return false
}

// HasRole checks if a user has a specific role.
func (s *AuthService) HasRole(user *User, role Role) bool {
	return Role(user.Role) == role
}

// ==================== RESOURCE-BASED ACCESS CONTROL ====================

// ResourceChecker is called to verify access to a specific resource.
type ResourceChecker func(ctx context.Context, user *User, resourceID string) bool

// RequireResource creates middleware that checks access to a specific resource.
func (s *AuthService) RequireResource(resourceType string, checker ResourceChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := GetUserFromContext(r.Context())
			if !ok {
				writeError(w, http.StatusUnauthorized, CodeInvalidToken, "unauthorized")
				return
			}

			// Extract resource ID from URL (assumes :id or {id} pattern)
			resourceID := extractResourceID(r)
			if resourceID == "" {
				writeError(w, http.StatusBadRequest, CodeBadRequest, "missing resource id")
				return
			}

			if !checker(r.Context(), user, resourceID) {
				writeError(w, http.StatusForbidden, "FORBIDDEN", "access denied")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func extractResourceID(r *http.Request) string {
	// Try common patterns
	path := r.URL.Path
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "id" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	// Last non-empty segment
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "" {
			return parts[i]
		}
	}
	return ""
}

// ==================== RBAC OPTIONS ====================

// WithRolePermissions sets custom role-permission mappings.
func WithRolePermissions(rp map[Role][]Permission) Option {
	return func(s *AuthService) error {
		s.rolePermissions = rp
		return nil
	}
}

// ==================== SCOPES (API/OAuth) ====================

// Scope represents an OAuth/API scope.
type Scope string

// Common scopes
const (
	ScopeRead     Scope = "read"
	ScopeWrite    Scope = "write"
	ScopeProfile  Scope = "profile"
	ScopeEmail    Scope = "email"
	ScopeOffline  Scope = "offline_access" // For refresh tokens
	ScopeOpenID   Scope = "openid"
)

// RequireScope creates middleware that requires specific OAuth scopes.
func (s *AuthService) RequireScope(scopes ...Scope) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetClaimsFromContext(r.Context())
			if !ok {
				writeError(w, http.StatusUnauthorized, CodeInvalidToken, "unauthorized")
				return
			}

			// Check if token has required scopes
			tokenScopes := strings.Split(claims.Scope, " ")
			for _, required := range scopes {
				found := false
				for _, have := range tokenScopes {
					if have == string(required) {
						found = true
						break
					}
				}
				if !found {
					writeError(w, http.StatusForbidden, "INSUFFICIENT_SCOPE",
						"missing scope: "+string(required))
					return
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
