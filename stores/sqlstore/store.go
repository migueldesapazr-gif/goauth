// Package sqlstore provides a SQL store implementation for goauth using database/sql.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/migueldesapazr-gif/goauth"
)

// Store implements goauth.Store for SQL databases (MySQL/SQLite).
type Store struct {
	users      *sql.DB
	audit      *sql.DB
	userStore  *UserStore
	tokenStore *TokenStore
	auditStore *AuditStore
	profileStore *ProfileStore
}

// New creates a new SQL store.
// usersDB is the connection for user data, auditDB is for audit logs (can be the same).
func New(usersDB, auditDB *sql.DB) *Store {
	if auditDB == nil {
		auditDB = usersDB
	}
	s := &Store{
		users: usersDB,
		audit: auditDB,
	}
	s.userStore = &UserStore{db: usersDB}
	s.tokenStore = &TokenStore{db: usersDB}
	s.auditStore = &AuditStore{db: auditDB}
	s.profileStore = &ProfileStore{db: usersDB}
	return s
}

// Users returns the user store.
func (s *Store) Users() goauth.UserStore {
	return s.userStore
}

// Tokens returns the token store.
func (s *Store) Tokens() goauth.TokenStore {
	return s.tokenStore
}

// Audit returns the audit store.
func (s *Store) Audit() goauth.AuditStore {
	return s.auditStore
}

// Profiles returns the profile store.
func (s *Store) Profiles() goauth.ProfileStore {
	return s.profileStore
}

// GetUserByOAuthProvider returns a user linked to an OAuth provider.
func (s *Store) GetUserByOAuthProvider(ctx context.Context, provider, providerUserID string) (*goauth.User, error) {
	var userID string
	err := s.users.QueryRowContext(ctx, `
		SELECT user_id FROM oauth_connections WHERE provider = ? AND provider_user_id = ?
	`, provider, providerUserID).Scan(&userID)
	if err != nil {
		return nil, err
	}
	return s.userStore.GetUserByID(ctx, userID)
}

// LinkOAuthConnection links a user to an OAuth provider.
func (s *Store) LinkOAuthConnection(ctx context.Context, userID, provider, providerUserID string) error {
	_, err := s.users.ExecContext(ctx, `
		INSERT INTO oauth_connections (id, user_id, provider, provider_user_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`, uuid.NewString(), userID, provider, providerUserID)
	return err
}

// UnlinkOAuthConnection removes a provider link for a user.
func (s *Store) UnlinkOAuthConnection(ctx context.Context, userID, provider string) error {
	_, err := s.users.ExecContext(ctx, `
		DELETE FROM oauth_connections WHERE user_id = ? AND provider = ?
	`, userID, provider)
	return err
}

// GetUserOAuthConnections lists OAuth connections for a user.
func (s *Store) GetUserOAuthConnections(ctx context.Context, userID string) ([]goauth.OAuthConnection, error) {
	rows, err := s.users.QueryContext(ctx, `
		SELECT id, provider, provider_user_id, created_at
		FROM oauth_connections
		WHERE user_id = ?
		ORDER BY created_at DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []goauth.OAuthConnection
	for rows.Next() {
		var c goauth.OAuthConnection
		if err := rows.Scan(&c.ID, &c.Provider, &c.ProviderID, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.UserID = userID
		out = append(out, c)
	}
	return out, nil
}

// StoreOAuthTokens stores encrypted OAuth tokens for a user/provider.
func (s *Store) StoreOAuthTokens(ctx context.Context, userID, provider string, accessEnc, accessNonce, refreshEnc, refreshNonce []byte, expiresAt time.Time) error {
	_, err := s.users.ExecContext(ctx, `
		UPDATE oauth_connections
		SET access_token_encrypted = ?,
			access_token_nonce = ?,
			refresh_token_encrypted = ?,
			refresh_token_nonce = ?,
			token_expires_at = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE user_id = ? AND provider = ?
	`, accessEnc, accessNonce, refreshEnc, refreshNonce, expiresAt, userID, provider)
	return err
}

// GetOAuthTokens retrieves encrypted OAuth tokens for a user/provider.
func (s *Store) GetOAuthTokens(ctx context.Context, userID, provider string) (accessEnc, accessNonce, refreshEnc, refreshNonce []byte, expiresAt time.Time, err error) {
	var expires sql.NullTime
	err = s.users.QueryRowContext(ctx, `
		SELECT access_token_encrypted, access_token_nonce, refresh_token_encrypted, refresh_token_nonce, token_expires_at
		FROM oauth_connections WHERE user_id = ? AND provider = ?
	`, userID, provider).Scan(&accessEnc, &accessNonce, &refreshEnc, &refreshNonce, &expires)
	if expires.Valid {
		expiresAt = expires.Time
	}
	return accessEnc, accessNonce, refreshEnc, refreshNonce, expiresAt, err
}

// DeleteOAuthTokens clears stored OAuth tokens for a user/provider.
func (s *Store) DeleteOAuthTokens(ctx context.Context, userID, provider string) error {
	_, err := s.users.ExecContext(ctx, `
		UPDATE oauth_connections
		SET access_token_encrypted = NULL,
			access_token_nonce = NULL,
			refresh_token_encrypted = NULL,
			refresh_token_nonce = NULL,
			token_expires_at = NULL,
			updated_at = CURRENT_TIMESTAMP
		WHERE user_id = ? AND provider = ?
	`, userID, provider)
	return err
}

// UserStore handles user operations.
type UserStore struct {
	db *sql.DB
}

func (s *UserStore) EmailExists(ctx context.Context, emailHash []byte) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE email_hash=?)", emailHash).Scan(&exists)
	return exists, err
}

func (s *UserStore) UsernameExists(ctx context.Context, usernameNormalized string) (bool, error) {
	if usernameNormalized == "" {
		return false, nil
	}
	var exists bool
	err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE username_normalized=?)", usernameNormalized).Scan(&exists)
	return exists, err
}

func (s *UserStore) CreateUser(ctx context.Context, user goauth.User, verificationDeadline time.Time) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	userID := user.ID
	if userID == "" {
		userID = uuid.NewString()
	}

	var deadline any
	if !verificationDeadline.IsZero() {
		deadline = verificationDeadline
	}

	username := nullString(user.Username)
	usernameNormalized := nullString(user.UsernameNormalized)

	_, err = tx.ExecContext(ctx, `
		INSERT INTO users (
			id, email_hash, email_encrypted, email_nonce, username, username_normalized, password_hash, password_salt,
			account_status, email_verified, verification_deadline
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		userID, user.EmailHash, user.EmailEncrypted, user.EmailNonce,
		username, usernameNormalized,
		user.PasswordHash, user.PasswordSalt,
		user.AccountStatus, user.EmailVerified, deadline,
	)
	if err != nil {
		return "", err
	}

	if user.PasswordHash != nil && user.PasswordSalt != nil {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO password_history (id, user_id, password_hash, password_salt, created_at)
			VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
		`, uuid.NewString(), userID, user.PasswordHash, user.PasswordSalt)
		if err != nil {
			return "", err
		}
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}

	return userID, nil
}

func (s *UserStore) GetUserByEmailHash(ctx context.Context, emailHash []byte) (*goauth.User, error) {
	user := &goauth.User{}
	var lockedAt sql.NullTime
	var lastLogin sql.NullTime
	var role sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT id, email_hash, email_encrypted, email_nonce, username, username_normalized, password_hash, password_salt,
			totp_secret_encrypted, totp_nonce, totp_enabled, email_verified,
			account_status, failed_login_attempts, locked_at, last_login_at, last_login_ip_encrypted, last_login_ip_nonce, role
		FROM users WHERE email_hash = ?
	`, emailHash).Scan(
		&user.ID, &user.EmailHash, &user.EmailEncrypted, &user.EmailNonce,
		&user.Username, &user.UsernameNormalized,
		&user.PasswordHash, &user.PasswordSalt,
		&user.TOTPSecretEncrypted, &user.TOTPNonce, &user.TOTPEnabled,
		&user.EmailVerified, &user.AccountStatus, &user.FailedLoginAttempts,
		&lockedAt, &lastLogin, &user.LastLoginIPEncrypted, &user.LastLoginIPNonce, &role,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("user not found")
	}
	user.LockedAt = nullTimePtr(lockedAt)
	user.LastLoginAt = nullTimePtr(lastLogin)
	user.Role = role.String
	return user, err
}

func (s *UserStore) GetUserByID(ctx context.Context, userID string) (*goauth.User, error) {
	user := &goauth.User{}
	var lockedAt sql.NullTime
	var lastLogin sql.NullTime
	var role sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT id, email_hash, email_encrypted, email_nonce, username, username_normalized, password_hash, password_salt,
			totp_secret_encrypted, totp_nonce, totp_enabled, email_verified,
			account_status, failed_login_attempts, locked_at, last_login_at, last_login_ip_encrypted, last_login_ip_nonce, role
		FROM users WHERE id = ?
	`, userID).Scan(
		&user.ID, &user.EmailHash, &user.EmailEncrypted, &user.EmailNonce,
		&user.Username, &user.UsernameNormalized,
		&user.PasswordHash, &user.PasswordSalt,
		&user.TOTPSecretEncrypted, &user.TOTPNonce, &user.TOTPEnabled,
		&user.EmailVerified, &user.AccountStatus, &user.FailedLoginAttempts,
		&lockedAt, &lastLogin, &user.LastLoginIPEncrypted, &user.LastLoginIPNonce, &role,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("user not found")
	}
	user.LockedAt = nullTimePtr(lockedAt)
	user.LastLoginAt = nullTimePtr(lastLogin)
	user.Role = role.String
	return user, err
}

func (s *UserStore) SetUserVerified(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET email_verified = 1, account_status = 'active',
			email_verified_at = CURRENT_TIMESTAMP, verification_deadline = NULL
		WHERE id = ?
	`, userID)
	return err
}

func (s *UserStore) IncrementLoginFailures(ctx context.Context, userID string) (int, error) {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?
	`, userID)
	if err != nil {
		return 0, err
	}
	var count int
	err = s.db.QueryRowContext(ctx, `SELECT failed_login_attempts FROM users WHERE id = ?`, userID).Scan(&count)
	return count, err
}

func (s *UserStore) LockUser(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET account_status = 'locked', locked_at = CURRENT_TIMESTAMP WHERE id = ?
	`, userID)
	return err
}

func (s *UserStore) UnlockUser(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET account_status = 'active', locked_at = NULL WHERE id = ?
	`, userID)
	return err
}

func (s *UserStore) ResetLoginFailures(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET failed_login_attempts = 0 WHERE id = ?
	`, userID)
	return err
}

func (s *UserStore) UpdateLastLogin(ctx context.Context, userID string, ipEnc, ipNonce []byte) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET last_login_at = CURRENT_TIMESTAMP, last_login_ip_encrypted = ?, last_login_ip_nonce = ? WHERE id = ?
	`, ipEnc, ipNonce, userID)
	return err
}

func (s *UserStore) GetUserByUsername(ctx context.Context, usernameNormalized string) (*goauth.User, error) {
	user := &goauth.User{}
	var lockedAt sql.NullTime
	var lastLogin sql.NullTime
	var role sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT id, email_hash, email_encrypted, email_nonce, username, username_normalized, password_hash, password_salt,
			totp_secret_encrypted, totp_nonce, totp_enabled, email_verified,
			account_status, failed_login_attempts, locked_at, last_login_at, last_login_ip_encrypted, last_login_ip_nonce, role
		FROM users WHERE username_normalized = ?
	`, usernameNormalized).Scan(
		&user.ID, &user.EmailHash, &user.EmailEncrypted, &user.EmailNonce,
		&user.Username, &user.UsernameNormalized,
		&user.PasswordHash, &user.PasswordSalt,
		&user.TOTPSecretEncrypted, &user.TOTPNonce, &user.TOTPEnabled,
		&user.EmailVerified, &user.AccountStatus, &user.FailedLoginAttempts,
		&lockedAt, &lastLogin, &user.LastLoginIPEncrypted, &user.LastLoginIPNonce, &role,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("user not found")
	}
	user.LockedAt = nullTimePtr(lockedAt)
	user.LastLoginAt = nullTimePtr(lastLogin)
	user.Role = role.String
	return user, err
}

func (s *UserStore) UpdateUsername(ctx context.Context, userID, username, usernameNormalized string) error {
	usernameValue := nullString(username)
	usernameNormalizedValue := nullString(usernameNormalized)
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET username = ?, username_normalized = ? WHERE id = ?
	`, usernameValue, usernameNormalizedValue, userID)
	return err
}

func (s *UserStore) UpdatePassword(ctx context.Context, userID string, hash, salt []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
		UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?
	`, hash, salt, userID)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `
		INSERT INTO password_history (id, user_id, password_hash, password_salt, created_at)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
	`, uuid.NewString(), userID, hash, salt)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *UserStore) UpdateEmail(ctx context.Context, userID string, emailHash, emailEnc, emailNonce []byte, verified bool) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users
		SET email_hash = ?, email_encrypted = ?, email_nonce = ?,
			email_verified = ?, email_verified_at = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE NULL END,
			account_status = CASE WHEN ? THEN 'active' ELSE account_status END,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, emailHash, emailEnc, emailNonce, verified, verified, verified, userID)
	return err
}

func (s *UserStore) RecentPasswordHistory(ctx context.Context, userID string, limit int) ([]goauth.PasswordHistory, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT password_hash, password_salt FROM password_history
		WHERE user_id = ? ORDER BY created_at DESC LIMIT ?
	`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []goauth.PasswordHistory
	for rows.Next() {
		var h goauth.PasswordHistory
		if err := rows.Scan(&h.Hash, &h.Salt); err != nil {
			return nil, err
		}
		history = append(history, h)
	}
	return history, nil
}

func (s *UserStore) UpdateTOTPSecret(ctx context.Context, userID string, secretEnc, secretNonce []byte) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET totp_secret_encrypted = ?, totp_nonce = ? WHERE id = ?
	`, secretEnc, secretNonce, userID)
	return err
}

func (s *UserStore) EnableTOTP(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET totp_enabled = 1, totp_verified_at = CURRENT_TIMESTAMP WHERE id = ?
	`, userID)
	return err
}

func (s *UserStore) DisableTOTP(ctx context.Context, userID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
		UPDATE users SET totp_enabled = 0, totp_secret_encrypted = NULL,
			totp_nonce = NULL, totp_verified_at = NULL
		WHERE id = ?
	`, userID)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, `DELETE FROM totp_backup_codes WHERE user_id = ?`, userID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (s *UserStore) ReplaceBackupCodes(ctx context.Context, userID string, hashes [][]byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `DELETE FROM totp_backup_codes WHERE user_id = ?`, userID)
	if err != nil {
		return err
	}

	for _, hash := range hashes {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO totp_backup_codes (id, user_id, code_hash, used, created_at)
			VALUES (?, ?, ?, 0, CURRENT_TIMESTAMP)
		`, uuid.NewString(), userID, hash)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *UserStore) UseBackupCode(ctx context.Context, userID string, codeHash []byte) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE totp_backup_codes SET used = 1, used_at = CURRENT_TIMESTAMP
		WHERE user_id = ? AND code_hash = ? AND used = 0
	`, userID, codeHash)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	return affected > 0, err
}

func (s *UserStore) UpdateUserRole(ctx context.Context, userID string, role string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET role = ? WHERE id = ?`, role, userID)
	return err
}

// TokenStore handles token operations.
type TokenStore struct {
	db *sql.DB
}

func (s *TokenStore) CreateVerificationToken(ctx context.Context, token goauth.VerificationToken, ipEnc, ipNonce []byte) (string, error) {
	_, _ = s.db.ExecContext(ctx, `
		UPDATE email_verification_tokens SET used = 1 WHERE user_id = ? AND used = 0
	`, token.UserID)

	id := uuid.NewString()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO email_verification_tokens
			(id, user_id, code_hash, link_token_hash, email_hash, expires_at, max_code_attempts,
			ip_created_encrypted, ip_created_nonce, used, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP)
	`, id, token.UserID, token.CodeHash, token.LinkHash, token.EmailHash, token.ExpiresAt, token.MaxAttempts, ipEnc, ipNonce)
	return id, err
}

func (s *TokenStore) GetActiveVerificationToken(ctx context.Context, userID string) (*goauth.VerificationToken, error) {
	token := &goauth.VerificationToken{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, code_hash, link_token_hash, email_hash, expires_at, code_attempts, max_code_attempts, used
		FROM email_verification_tokens
		WHERE user_id = ? AND used = 0 ORDER BY created_at DESC LIMIT 1
	`, userID).Scan(
		&token.ID, &token.UserID, &token.CodeHash, &token.LinkHash, &token.EmailHash,
		&token.ExpiresAt, &token.CodeAttempts, &token.MaxAttempts, &token.Used,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("token not found")
	}
	return token, err
}

func (s *TokenStore) GetVerificationTokenByLinkHash(ctx context.Context, linkHash []byte) (*goauth.VerificationToken, error) {
	token := &goauth.VerificationToken{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, code_hash, link_token_hash, email_hash, expires_at, code_attempts, max_code_attempts, used
		FROM email_verification_tokens
		WHERE link_token_hash = ?
	`, linkHash).Scan(
		&token.ID, &token.UserID, &token.CodeHash, &token.LinkHash, &token.EmailHash,
		&token.ExpiresAt, &token.CodeAttempts, &token.MaxAttempts, &token.Used,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("token not found")
	}
	return token, err
}

func (s *TokenStore) IncrementVerificationAttempts(ctx context.Context, tokenID string) (int, error) {
	_, err := s.db.ExecContext(ctx, `
		UPDATE email_verification_tokens SET code_attempts = code_attempts + 1 WHERE id = ?
	`, tokenID)
	if err != nil {
		return 0, err
	}
	var count int
	err = s.db.QueryRowContext(ctx, `
		SELECT code_attempts FROM email_verification_tokens WHERE id = ?
	`, tokenID).Scan(&count)
	return count, err
}

func (s *TokenStore) MarkVerificationTokenUsed(ctx context.Context, tokenID string, ipEnc, ipNonce []byte) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE email_verification_tokens SET used = 1, used_at = CURRENT_TIMESTAMP,
			ip_used_encrypted = ?, ip_used_nonce = ?
		WHERE id = ?
	`, ipEnc, ipNonce, tokenID)
	return err
}

func (s *TokenStore) CreatePasswordResetToken(ctx context.Context, token goauth.PasswordResetToken, ipEnc, ipNonce []byte) (string, error) {
	id := uuid.NewString()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at, used, ip_request_encrypted, ip_request_nonce, created_at)
		VALUES (?, ?, ?, ?, 0, ?, ?, CURRENT_TIMESTAMP)
	`, id, token.UserID, token.TokenHash, token.ExpiresAt, ipEnc, ipNonce)
	return id, err
}

func (s *TokenStore) GetPasswordResetTokenByHash(ctx context.Context, tokenHash []byte) (*goauth.PasswordResetToken, error) {
	token := &goauth.PasswordResetToken{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, token_hash, expires_at, used
		FROM password_reset_tokens WHERE token_hash = ?
	`, tokenHash).Scan(&token.ID, &token.UserID, &token.TokenHash, &token.ExpiresAt, &token.Used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("token not found")
	}
	return token, err
}

func (s *TokenStore) MarkPasswordResetUsed(ctx context.Context, tokenID string, ipEnc, ipNonce []byte) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE password_reset_tokens SET used = 1, used_at = CURRENT_TIMESTAMP,
			ip_used_encrypted = ?, ip_used_nonce = ?
		WHERE id = ?
	`, ipEnc, ipNonce, tokenID)
	return err
}

func (s *TokenStore) CreateEmailChangeToken(ctx context.Context, token goauth.EmailChangeToken, ipEnc, ipNonce []byte) (string, error) {
	id := uuid.NewString()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO email_change_tokens (id, user_id, token_hash, new_email_hash, new_email_encrypted, new_email_nonce, expires_at, used, ip_created_encrypted, ip_created_nonce, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, CURRENT_TIMESTAMP)
	`, id, token.UserID, token.TokenHash, token.NewEmailHash, token.NewEmailEncrypted, token.NewEmailNonce, token.ExpiresAt, ipEnc, ipNonce)
	return id, err
}

func (s *TokenStore) GetEmailChangeTokenByHash(ctx context.Context, tokenHash []byte) (*goauth.EmailChangeToken, error) {
	token := &goauth.EmailChangeToken{}
	err := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, token_hash, new_email_hash, new_email_encrypted, new_email_nonce, expires_at, used
		FROM email_change_tokens WHERE token_hash = ?
	`, tokenHash).Scan(
		&token.ID, &token.UserID, &token.TokenHash, &token.NewEmailHash, &token.NewEmailEncrypted, &token.NewEmailNonce, &token.ExpiresAt, &token.Used,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("token not found")
	}
	return token, err
}

func (s *TokenStore) MarkEmailChangeUsed(ctx context.Context, tokenID string, ipEnc, ipNonce []byte) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE email_change_tokens SET used = 1, used_at = CURRENT_TIMESTAMP,
			ip_used_encrypted = ?, ip_used_nonce = ?
		WHERE id = ?
	`, ipEnc, ipNonce, tokenID)
	return err
}

func (s *TokenStore) StoreRefreshToken(ctx context.Context, userID, jti string, expiresAt time.Time, ipEnc, ipNonce []byte) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO refresh_tokens (jti, user_id, expires_at, ip_encrypted, ip_nonce, created_at)
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	`, jti, userID, expiresAt, ipEnc, ipNonce)
	return err
}

func (s *TokenStore) RefreshTokenValid(ctx context.Context, jti string) (bool, error) {
	var valid bool
	err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM refresh_tokens
			WHERE jti = ? AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP
		)
	`, jti).Scan(&valid)
	return valid, err
}

func (s *TokenStore) RevokeRefreshToken(ctx context.Context, jti string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE jti = ?`, jti)
	return err
}

func (s *TokenStore) RevokeAllRefreshTokens(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE refresh_tokens SET revoked_at = CURRENT_TIMESTAMP
		WHERE user_id = ? AND revoked_at IS NULL
	`, userID)
	return err
}

// AuditStore handles audit logging.
type AuditStore struct {
	db *sql.DB
}

func (s *AuditStore) InsertAuditLog(ctx context.Context, log goauth.AuditLog) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_logs (id, user_id, event_type, ip_encrypted, ip_nonce, user_agent_hash, metadata_encrypted, metadata_nonce, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	`, uuid.NewString(), log.UserID, log.EventType, log.IPEncrypted, log.IPNonce, log.UserAgentHash, log.MetadataEnc, log.MetadataNonce, log.ExpiresAt)
	return err
}

func (s *AuditStore) GetUserAuditLogs(ctx context.Context, userID string, limit int) ([]goauth.AuditLog, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT event_type, created_at FROM audit_logs WHERE user_id = ?
		ORDER BY created_at DESC LIMIT ?
	`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var logs []goauth.AuditLog
	for rows.Next() {
		var log goauth.AuditLog
		if err := rows.Scan(&log.EventType, &log.CreatedAt); err != nil {
			return nil, err
		}
		logs = append(logs, log)
	}
	return logs, nil
}

func nullTimePtr(nt sql.NullTime) *time.Time {
	if nt.Valid {
		return &nt.Time
	}
	return nil
}

func nullString(val string) any {
	if val == "" {
		return nil
	}
	return val
}
