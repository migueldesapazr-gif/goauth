package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// CleanupExpiredTokens removes all expired tokens.
func (s *Store) CleanupExpiredTokens(ctx context.Context) (int64, error) {
	var total int64

	// Verification tokens
	tag, err := s.users.Exec(ctx, `DELETE FROM email_verification_tokens WHERE expires_at < NOW()`)
	if err == nil {
		total += tag.RowsAffected()
	}

	// Password reset tokens
	tag, err = s.users.Exec(ctx, `DELETE FROM password_reset_tokens WHERE expires_at < NOW()`)
	if err == nil {
		total += tag.RowsAffected()
	}

	// Email change tokens
	tag, err = s.users.Exec(ctx, `DELETE FROM email_change_tokens WHERE expires_at < NOW()`)
	if err == nil {
		total += tag.RowsAffected()
	}

	// Refresh tokens
	tag, err = s.users.Exec(ctx, `DELETE FROM refresh_tokens WHERE expires_at < NOW()`)
	if err == nil {
		total += tag.RowsAffected()
	}

	// Magic link tokens
	tag, _ = s.users.Exec(ctx, `DELETE FROM magic_link_tokens WHERE expires_at < NOW()`)
	if err == nil {
		total += tag.RowsAffected()
	}

	return total, nil
}

// CleanupOldAuditLogs removes audit logs older than retention period.
func (s *Store) CleanupOldAuditLogs(ctx context.Context, retention time.Duration) (int64, error) {
	cutoff := time.Now().Add(-retention)
	tag, err := s.audit.Exec(ctx, `DELETE FROM audit_logs WHERE created_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// CleanupUnverifiedAccounts removes unverified accounts past deadline.
func (s *Store) CleanupUnverifiedAccounts(ctx context.Context) (int64, error) {
	tag, err := s.users.Exec(ctx, `
		DELETE FROM users 
		WHERE email_verified = false 
		AND verification_deadline IS NOT NULL 
		AND verification_deadline < NOW()
	`)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeleteUser removes all user data (GDPR compliance).
func (s *Store) DeleteUser(ctx context.Context, userID string) error {
	tx, err := s.users.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Delete in order of dependencies
	tables := []string{
		"totp_backup_codes",
		"refresh_tokens",
		"email_verification_tokens",
		"password_reset_tokens",
		"email_change_tokens",
		"password_history",
		"magic_link_tokens",
		"api_keys",
		"devices",
		"profiles",
		"oauth_connections",
	}

	for _, table := range tables {
		tx.Exec(ctx, `DELETE FROM `+table+` WHERE user_id = $1`, userID)
	}

	// Delete audit logs (or anonymize)
	tx.Exec(ctx, `DELETE FROM audit_logs WHERE user_id = $1`, userID)

	// Finally delete user
	_, err = tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// ExportUserData exports all user data as JSON (GDPR compliance).
func (s *Store) ExportUserData(ctx context.Context, userID string) ([]byte, error) {
	data := make(map[string]any)

	// User info
	var user struct {
		ID            string    `json:"id"`
		EmailVerified bool      `json:"email_verified"`
		TOTPEnabled   bool      `json:"totp_enabled"`
		AccountStatus string    `json:"account_status"`
		Role          string    `json:"role"`
		CreatedAt     time.Time `json:"created_at"`
		LastLoginAt   *time.Time `json:"last_login_at"`
	}
	err := s.users.QueryRow(ctx, `
		SELECT id, email_verified, totp_enabled, account_status, role, created_at, last_login_at
		FROM users WHERE id = $1
	`, userID).Scan(&user.ID, &user.EmailVerified, &user.TOTPEnabled, &user.AccountStatus, &user.Role, &user.CreatedAt, &user.LastLoginAt)
	if err != nil {
		return nil, err
	}
	data["user"] = user

	// Profile
	var profile struct {
		DisplayName     string
		DisplayPhotoURL string
		Bio             string
		Locale          string
		Timezone        string
		CreatedAt       time.Time
		UpdatedAt       time.Time
	}
	var metadata []byte
	err = s.users.QueryRow(ctx, `
		SELECT display_name, display_photo_url, bio, locale, timezone, metadata, created_at, updated_at
		FROM profiles WHERE user_id = $1
	`, userID).Scan(
		&profile.DisplayName,
		&profile.DisplayPhotoURL,
		&profile.Bio,
		&profile.Locale,
		&profile.Timezone,
		&metadata,
		&profile.CreatedAt,
		&profile.UpdatedAt,
	)
	if err == nil {
		entry := map[string]any{
			"display_name":      profile.DisplayName,
			"display_photo_url": profile.DisplayPhotoURL,
			"bio":               profile.Bio,
			"locale":            profile.Locale,
			"timezone":          profile.Timezone,
			"created_at":        profile.CreatedAt,
			"updated_at":        profile.UpdatedAt,
		}
		if len(metadata) > 0 {
			var meta map[string]any
			if json.Unmarshal(metadata, &meta) == nil {
				entry["metadata"] = meta
			}
		}
		data["profile"] = entry
	}

	// Audit logs
	rows, _ := s.audit.Query(ctx, `
		SELECT event_type, created_at FROM audit_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100
	`, userID)
	var logs []map[string]any
	for rows.Next() {
		var eventType string
		var createdAt time.Time
		rows.Scan(&eventType, &createdAt)
		logs = append(logs, map[string]any{"event": eventType, "timestamp": createdAt})
	}
	rows.Close()
	data["audit_logs"] = logs

	// Devices
	rows, _ = s.users.Query(ctx, `
		SELECT id, name, device_type, created_at, last_active FROM devices WHERE user_id = $1
	`, userID)
	var devices []map[string]any
	for rows.Next() {
		var id, name, deviceType string
		var createdAt, lastActive time.Time
		rows.Scan(&id, &name, &deviceType, &createdAt, &lastActive)
		devices = append(devices, map[string]any{
			"id": id, "name": name, "type": deviceType, "created_at": createdAt, "last_active": lastActive,
		})
	}
	rows.Close()
	data["devices"] = devices

	// OAuth connections
	rows, _ = s.users.Query(ctx, `
		SELECT provider, created_at FROM oauth_connections WHERE user_id = $1
	`, userID)
	var oauthConns []map[string]any
	for rows.Next() {
		var provider string
		var createdAt time.Time
		rows.Scan(&provider, &createdAt)
		oauthConns = append(oauthConns, map[string]any{"provider": provider, "connected_at": createdAt})
	}
	rows.Close()
	data["oauth_connections"] = oauthConns

	return json.Marshal(data)
}

// ExportUserAuditLogs exports user audit logs.
func (s *Store) ExportUserAuditLogs(ctx context.Context, userID, format string) ([]byte, error) {
	rows, err := s.audit.Query(ctx, `
		SELECT id, event_type, created_at FROM audit_logs WHERE user_id = $1 ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []map[string]any
	for rows.Next() {
		var id, eventType string
		var createdAt time.Time
		rows.Scan(&id, &eventType, &createdAt)
		logs = append(logs, map[string]any{"id": id, "event": eventType, "timestamp": createdAt})
	}

	if format == "csv" {
		var buf bytes.Buffer
		buf.WriteString("id,event,timestamp\n")
		for _, log := range logs {
			buf.WriteString(fmt.Sprintf("%s,%s,%s\n", log["id"], log["event"], log["timestamp"]))
		}
		return buf.Bytes(), nil
	}

	return json.Marshal(logs)
}
