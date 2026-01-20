// Package postgres provides a PostgreSQL implementation of the goauth.Store interface.
package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/migueldesapazr-gif/goauth"
)

// Store implements goauth.Store for PostgreSQL.
type Store struct {
	users  *pgxpool.Pool
	audit  *pgxpool.Pool
	userStore  *UserStore
	tokenStore *TokenStore
	auditStore *AuditStore
	profileStore *ProfileStore
}

// New creates a new PostgreSQL store.
// usersPool is the connection pool for the users database.
// auditPool is the connection pool for the audit database (can be the same as usersPool).
func New(usersPool, auditPool *pgxpool.Pool) *Store {
	s := &Store{
		users: usersPool,
		audit: auditPool,
	}
	s.userStore = &UserStore{pool: usersPool}
	s.tokenStore = &TokenStore{pool: usersPool}
	s.auditStore = &AuditStore{pool: auditPool}
	s.profileStore = &ProfileStore{pool: usersPool}
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
	err := s.users.QueryRow(ctx, `
		SELECT user_id FROM oauth_connections WHERE provider = $1 AND provider_user_id = $2
	`, provider, providerUserID).Scan(&userID)
	if err != nil {
		return nil, err
	}
	return s.userStore.GetUserByID(ctx, userID)
}

// LinkOAuthConnection links a user to an OAuth provider.
func (s *Store) LinkOAuthConnection(ctx context.Context, userID, provider, providerUserID string) error {
	_, err := s.users.Exec(ctx, `
		INSERT INTO oauth_connections (user_id, provider, provider_user_id)
		VALUES ($1, $2, $3)
	`, userID, provider, providerUserID)
	return err
}

// UnlinkOAuthConnection removes a provider link for a user.
func (s *Store) UnlinkOAuthConnection(ctx context.Context, userID, provider string) error {
	_, err := s.users.Exec(ctx, `
		DELETE FROM oauth_connections WHERE user_id = $1 AND provider = $2
	`, userID, provider)
	return err
}

// GetUserOAuthConnections lists OAuth connections for a user.
func (s *Store) GetUserOAuthConnections(ctx context.Context, userID string) ([]goauth.OAuthConnection, error) {
	rows, err := s.users.Query(ctx, `
		SELECT id, provider, provider_user_id, created_at
		FROM oauth_connections
		WHERE user_id = $1
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
	_, err := s.users.Exec(ctx, `
		UPDATE oauth_connections
		SET access_token_encrypted = $1,
			access_token_nonce = $2,
			refresh_token_encrypted = $3,
			refresh_token_nonce = $4,
			token_expires_at = $5,
			updated_at = NOW()
		WHERE user_id = $6 AND provider = $7
	`, accessEnc, accessNonce, refreshEnc, refreshNonce, expiresAt, userID, provider)
	return err
}

// GetOAuthTokens retrieves encrypted OAuth tokens for a user/provider.
func (s *Store) GetOAuthTokens(ctx context.Context, userID, provider string) (accessEnc, accessNonce, refreshEnc, refreshNonce []byte, expiresAt time.Time, err error) {
	err = s.users.QueryRow(ctx, `
		SELECT access_token_encrypted, access_token_nonce, refresh_token_encrypted, refresh_token_nonce, token_expires_at
		FROM oauth_connections WHERE user_id = $1 AND provider = $2
	`, userID, provider).Scan(&accessEnc, &accessNonce, &refreshEnc, &refreshNonce, &expiresAt)
	return accessEnc, accessNonce, refreshEnc, refreshNonce, expiresAt, err
}

// DeleteOAuthTokens clears stored OAuth tokens for a user/provider.
func (s *Store) DeleteOAuthTokens(ctx context.Context, userID, provider string) error {
	_, err := s.users.Exec(ctx, `
		UPDATE oauth_connections
		SET access_token_encrypted = NULL,
			access_token_nonce = NULL,
			refresh_token_encrypted = NULL,
			refresh_token_nonce = NULL,
			token_expires_at = NULL,
			updated_at = NOW()
		WHERE user_id = $1 AND provider = $2
	`, userID, provider)
	return err
}

// UserStore handles user operations.
type UserStore struct {
	pool *pgxpool.Pool
}

func (s *UserStore) EmailExists(ctx context.Context, emailHash []byte) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE email_hash=$1)", emailHash).Scan(&exists)
	return exists, err
}

func (s *UserStore) UsernameExists(ctx context.Context, usernameNormalized string) (bool, error) {
	if usernameNormalized == "" {
		return false, nil
	}
	var exists bool
	err := s.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE username_normalized=$1)", usernameNormalized).Scan(&exists)
	return exists, err
}

func (s *UserStore) CreateUser(ctx context.Context, user goauth.User, verificationDeadline time.Time) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	var userID string
	var deadline any
	if !verificationDeadline.IsZero() {
		deadline = verificationDeadline
	}
	username := nullString(user.Username)
	usernameNormalized := nullString(user.UsernameNormalized)
	err = tx.QueryRow(ctx, `
		INSERT INTO users (email_hash, email_encrypted, email_nonce, username, username_normalized, password_hash, password_salt, 
			account_status, email_verified, verification_deadline)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id`,
		user.EmailHash, user.EmailEncrypted, user.EmailNonce,
		username, usernameNormalized,
		user.PasswordHash, user.PasswordSalt,
		user.AccountStatus, user.EmailVerified, deadline,
	).Scan(&userID)
	if err != nil {
		return "", err
	}

	// Store initial password in history
	_, err = tx.Exec(ctx, `
		INSERT INTO password_history (user_id, password_hash, password_salt)
		VALUES ($1,$2,$3)`,
		userID, user.PasswordHash, user.PasswordSalt,
	)
	if err != nil {
		return "", err
	}

	if err := tx.Commit(ctx); err != nil {
		return "", err
	}

	return userID, nil
}

func (s *UserStore) GetUserByEmailHash(ctx context.Context, emailHash []byte) (*goauth.User, error) {
	user := &goauth.User{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, email_hash, email_encrypted, email_nonce, username, username_normalized, password_hash, password_salt,
			totp_secret_encrypted, totp_nonce, totp_enabled, email_verified, 
			account_status, failed_login_attempts, locked_at, last_login_at, last_login_ip_encrypted, last_login_ip_nonce, role
		FROM users WHERE email_hash = $1`, emailHash).Scan(
		&user.ID, &user.EmailHash, &user.EmailEncrypted, &user.EmailNonce,
		&user.Username, &user.UsernameNormalized,
		&user.PasswordHash, &user.PasswordSalt,
		&user.TOTPSecretEncrypted, &user.TOTPNonce, &user.TOTPEnabled,
		&user.EmailVerified, &user.AccountStatus, &user.FailedLoginAttempts,
		&user.LockedAt, &user.LastLoginAt, &user.LastLoginIPEncrypted, &user.LastLoginIPNonce, &user.Role,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("user not found")
	}
	return user, err
}

func (s *UserStore) GetUserByID(ctx context.Context, userID string) (*goauth.User, error) {
	user := &goauth.User{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, email_hash, email_encrypted, email_nonce, username, username_normalized, password_hash, password_salt,
			totp_secret_encrypted, totp_nonce, totp_enabled, email_verified, 
			account_status, failed_login_attempts, locked_at, last_login_at, last_login_ip_encrypted, last_login_ip_nonce, role
		FROM users WHERE id = $1`, userID).Scan(
		&user.ID, &user.EmailHash, &user.EmailEncrypted, &user.EmailNonce,
		&user.Username, &user.UsernameNormalized,
		&user.PasswordHash, &user.PasswordSalt,
		&user.TOTPSecretEncrypted, &user.TOTPNonce, &user.TOTPEnabled,
		&user.EmailVerified, &user.AccountStatus, &user.FailedLoginAttempts,
		&user.LockedAt, &user.LastLoginAt, &user.LastLoginIPEncrypted, &user.LastLoginIPNonce, &user.Role,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("user not found")
	}
	return user, err
}

func (s *UserStore) SetUserVerified(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE users SET email_verified = true, account_status = 'active', 
			email_verified_at = NOW(), verification_deadline = NULL
		WHERE id = $1`, userID)
	return err
}

func (s *UserStore) IncrementLoginFailures(ctx context.Context, userID string) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		UPDATE users SET failed_login_attempts = failed_login_attempts + 1
		WHERE id = $1 RETURNING failed_login_attempts`, userID).Scan(&count)
	return count, err
}

func (s *UserStore) LockUser(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE users SET account_status = 'locked', locked_at = NOW() WHERE id = $1`, userID)
	return err
}

func (s *UserStore) UnlockUser(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE users SET account_status = 'active', locked_at = NULL WHERE id = $1`, userID)
	return err
}

func (s *UserStore) ResetLoginFailures(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE users SET failed_login_attempts = 0 WHERE id = $1`, userID)
	return err
}

func (s *UserStore) UpdateLastLogin(ctx context.Context, userID string, ipEnc, ipNonce []byte) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE users
		SET last_login_at = NOW(), last_login_ip_encrypted = $1, last_login_ip_nonce = $2
		WHERE id = $3
	`, ipEnc, ipNonce, userID)
	return err
}

func (s *UserStore) GetUserByUsername(ctx context.Context, usernameNormalized string) (*goauth.User, error) {
	user := &goauth.User{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, email_hash, email_encrypted, email_nonce, username, username_normalized, password_hash, password_salt,
			totp_secret_encrypted, totp_nonce, totp_enabled, email_verified, 
			account_status, failed_login_attempts, locked_at, last_login_at, last_login_ip_encrypted, last_login_ip_nonce, role
		FROM users WHERE username_normalized = $1`, usernameNormalized).Scan(
		&user.ID, &user.EmailHash, &user.EmailEncrypted, &user.EmailNonce,
		&user.Username, &user.UsernameNormalized,
		&user.PasswordHash, &user.PasswordSalt,
		&user.TOTPSecretEncrypted, &user.TOTPNonce, &user.TOTPEnabled,
		&user.EmailVerified, &user.AccountStatus, &user.FailedLoginAttempts,
		&user.LockedAt, &user.LastLoginAt, &user.LastLoginIPEncrypted, &user.LastLoginIPNonce, &user.Role,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("user not found")
	}
	return user, err
}

func (s *UserStore) UpdateUsername(ctx context.Context, userID, username, usernameNormalized string) error {
	usernameValue := nullString(username)
	usernameNormalizedValue := nullString(usernameNormalized)
	_, err := s.pool.Exec(ctx, `
		UPDATE users SET username = $1, username_normalized = $2 WHERE id = $3
	`, usernameValue, usernameNormalizedValue, userID)
	return err
}

func (s *UserStore) UpdatePassword(ctx context.Context, userID string, hash, salt []byte) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `UPDATE users SET password_hash = $1, password_salt = $2 WHERE id = $3`,
		hash, salt, userID)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `INSERT INTO password_history (user_id, password_hash, password_salt) VALUES ($1,$2,$3)`,
		userID, hash, salt)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *UserStore) UpdateEmail(ctx context.Context, userID string, emailHash, emailEnc, emailNonce []byte, verified bool) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE users
		SET email_hash = $1,
			email_encrypted = $2,
			email_nonce = $3,
			email_verified = $4,
			email_verified_at = CASE WHEN $4 THEN NOW() ELSE NULL END,
			account_status = CASE WHEN $4 THEN 'active' ELSE account_status END,
			updated_at = NOW()
		WHERE id = $5
	`, emailHash, emailEnc, emailNonce, verified, userID)
	return err
}

func (s *UserStore) RecentPasswordHistory(ctx context.Context, userID string, limit int) ([]goauth.PasswordHistory, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT password_hash, password_salt FROM password_history
		WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2`, userID, limit)
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
	_, err := s.pool.Exec(ctx, `UPDATE users SET totp_secret_encrypted = $1, totp_nonce = $2 WHERE id = $3`,
		secretEnc, secretNonce, userID)
	return err
}

func (s *UserStore) EnableTOTP(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET totp_enabled = true, totp_verified_at = NOW() WHERE id = $1`, userID)
	return err
}

func (s *UserStore) DisableTOTP(ctx context.Context, userID string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		UPDATE users SET totp_enabled = false, totp_secret_encrypted = NULL, 
			totp_nonce = NULL, totp_verified_at = NULL
		WHERE id = $1`, userID)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `DELETE FROM totp_backup_codes WHERE user_id = $1`, userID)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *UserStore) ReplaceBackupCodes(ctx context.Context, userID string, hashes [][]byte) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `DELETE FROM totp_backup_codes WHERE user_id = $1`, userID)
	if err != nil {
		return err
	}

	for _, hash := range hashes {
		_, err = tx.Exec(ctx, `INSERT INTO totp_backup_codes (user_id, code_hash) VALUES ($1, $2)`, userID, hash)
		if err != nil {
			return err
		}
	}

	return tx.Commit(ctx)
}

func (s *UserStore) UseBackupCode(ctx context.Context, userID string, codeHash []byte) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE totp_backup_codes SET used = true, used_at = NOW()
		WHERE user_id = $1 AND code_hash = $2 AND used = false`, userID, codeHash)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (s *UserStore) UpdateUserRole(ctx context.Context, userID string, role string) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET role = $1 WHERE id = $2`, role, userID)
	return err
}

// TokenStore handles token operations.
type TokenStore struct {
	pool *pgxpool.Pool
}

func (s *TokenStore) CreateVerificationToken(ctx context.Context, token goauth.VerificationToken, ipEnc, ipNonce []byte) (string, error) {
	// Invalidate existing tokens
	_, _ = s.pool.Exec(ctx, `
		UPDATE email_verification_tokens SET used = true WHERE user_id = $1 AND used = false`, token.UserID)

	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO email_verification_tokens 
			(user_id, code_hash, link_token_hash, email_hash, expires_at, max_code_attempts, ip_created_encrypted, ip_created_nonce)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id`,
		token.UserID, token.CodeHash, token.LinkHash, token.EmailHash,
		token.ExpiresAt, token.MaxAttempts, ipEnc, ipNonce,
	).Scan(&id)
	return id, err
}

func (s *TokenStore) GetActiveVerificationToken(ctx context.Context, userID string) (*goauth.VerificationToken, error) {
	token := &goauth.VerificationToken{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, user_id, code_hash, link_token_hash, email_hash, expires_at, code_attempts, max_code_attempts, used
		FROM email_verification_tokens
		WHERE user_id = $1 AND used = false ORDER BY created_at DESC LIMIT 1`, userID).Scan(
		&token.ID, &token.UserID, &token.CodeHash, &token.LinkHash, &token.EmailHash,
		&token.ExpiresAt, &token.CodeAttempts, &token.MaxAttempts, &token.Used,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("token not found")
	}
	return token, err
}

func (s *TokenStore) GetVerificationTokenByLinkHash(ctx context.Context, linkHash []byte) (*goauth.VerificationToken, error) {
	token := &goauth.VerificationToken{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, user_id, code_hash, link_token_hash, email_hash, expires_at, code_attempts, max_code_attempts, used
		FROM email_verification_tokens
		WHERE link_token_hash = $1`, linkHash).Scan(
		&token.ID, &token.UserID, &token.CodeHash, &token.LinkHash, &token.EmailHash,
		&token.ExpiresAt, &token.CodeAttempts, &token.MaxAttempts, &token.Used,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("token not found")
	}
	return token, err
}

func (s *TokenStore) IncrementVerificationAttempts(ctx context.Context, tokenID string) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, `
		UPDATE email_verification_tokens SET code_attempts = code_attempts + 1
		WHERE id = $1 RETURNING code_attempts`, tokenID).Scan(&count)
	return count, err
}

func (s *TokenStore) MarkVerificationTokenUsed(ctx context.Context, tokenID string, ipEnc, ipNonce []byte) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE email_verification_tokens SET used = true, used_at = NOW(), 
			ip_used_encrypted = $1, ip_used_nonce = $2
		WHERE id = $3`, ipEnc, ipNonce, tokenID)
	return err
}

func (s *TokenStore) CreatePasswordResetToken(ctx context.Context, token goauth.PasswordResetToken, ipEnc, ipNonce []byte) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, ip_request_encrypted, ip_request_nonce)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`, token.UserID, token.TokenHash, token.ExpiresAt, ipEnc, ipNonce).Scan(&id)
	return id, err
}

func (s *TokenStore) GetPasswordResetTokenByHash(ctx context.Context, tokenHash []byte) (*goauth.PasswordResetToken, error) {
	token := &goauth.PasswordResetToken{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, user_id, token_hash, expires_at, used
		FROM password_reset_tokens WHERE token_hash = $1`, tokenHash).Scan(
		&token.ID, &token.UserID, &token.TokenHash, &token.ExpiresAt, &token.Used,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("token not found")
	}
	return token, err
}

func (s *TokenStore) MarkPasswordResetUsed(ctx context.Context, tokenID string, ipEnc, ipNonce []byte) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE password_reset_tokens SET used = true, used_at = NOW(),
			ip_used_encrypted = $1, ip_used_nonce = $2
		WHERE id = $3`, ipEnc, ipNonce, tokenID)
	return err
}

func (s *TokenStore) CreateEmailChangeToken(ctx context.Context, token goauth.EmailChangeToken, ipEnc, ipNonce []byte) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO email_change_tokens (user_id, token_hash, new_email_hash, new_email_encrypted, new_email_nonce, expires_at, ip_created_encrypted, ip_created_nonce)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id
	`, token.UserID, token.TokenHash, token.NewEmailHash, token.NewEmailEncrypted, token.NewEmailNonce, token.ExpiresAt, ipEnc, ipNonce).Scan(&id)
	return id, err
}

func (s *TokenStore) GetEmailChangeTokenByHash(ctx context.Context, tokenHash []byte) (*goauth.EmailChangeToken, error) {
	token := &goauth.EmailChangeToken{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, user_id, token_hash, new_email_hash, new_email_encrypted, new_email_nonce, expires_at, used
		FROM email_change_tokens WHERE token_hash = $1
	`, tokenHash).Scan(
		&token.ID, &token.UserID, &token.TokenHash, &token.NewEmailHash, &token.NewEmailEncrypted, &token.NewEmailNonce, &token.ExpiresAt, &token.Used,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errors.New("token not found")
	}
	return token, err
}

func (s *TokenStore) MarkEmailChangeUsed(ctx context.Context, tokenID string, ipEnc, ipNonce []byte) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE email_change_tokens SET used = true, used_at = NOW(),
			ip_used_encrypted = $1, ip_used_nonce = $2
		WHERE id = $3
	`, ipEnc, ipNonce, tokenID)
	return err
}

func (s *TokenStore) StoreRefreshToken(ctx context.Context, userID, jti string, expiresAt time.Time, ipEnc, ipNonce []byte) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO refresh_tokens (jti, user_id, expires_at, ip_encrypted, ip_nonce)
		VALUES ($1, $2, $3, $4, $5)`, jti, userID, expiresAt, ipEnc, ipNonce)
	return err
}

func (s *TokenStore) RefreshTokenValid(ctx context.Context, jti string) (bool, error) {
	var valid bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM refresh_tokens 
			WHERE jti = $1 AND revoked_at IS NULL AND expires_at > NOW()
		)`, jti).Scan(&valid)
	return valid, err
}

func (s *TokenStore) RevokeRefreshToken(ctx context.Context, jti string) error {
	_, err := s.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = NOW() WHERE jti = $1`, jti)
	return err
}

func (s *TokenStore) RevokeAllRefreshTokens(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = NOW() 
		WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	return err
}

// AuditStore handles audit logging.
type AuditStore struct {
	pool *pgxpool.Pool
}

func (s *AuditStore) InsertAuditLog(ctx context.Context, log goauth.AuditLog) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_logs (user_id, event_type, ip_encrypted, ip_nonce, user_agent_hash, expires_at, metadata_encrypted, metadata_nonce)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		log.UserID, log.EventType, log.IPEncrypted, log.IPNonce,
		log.UserAgentHash, log.ExpiresAt, log.MetadataEnc, log.MetadataNonce,
	)
	return err
}

func (s *AuditStore) GetUserAuditLogs(ctx context.Context, userID string, limit int) ([]goauth.AuditLog, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT event_type, created_at FROM audit_logs WHERE user_id = $1
		ORDER BY created_at DESC LIMIT $2
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

func nullString(val string) any {
	if val == "" {
		return nil
	}
	return val
}

// WithDatabase returns a goauth.Option that configures PostgreSQL storage.
// Use this when initializing goauth:
//
//	goauth.New(postgres.WithDatabase(pool), ...)
func WithDatabase(pool *pgxpool.Pool) goauth.Option {
	return func(s *goauth.AuthService) error {
		store := New(pool, pool)
		return goauth.WithStore(store)(s)
	}
}

// WithDatabases returns a goauth.Option that configures PostgreSQL storage
// with separate pools for users and audit data.
func WithDatabases(usersPool, auditPool *pgxpool.Pool) goauth.Option {
	return func(s *goauth.AuthService) error {
		store := New(usersPool, auditPool)
		return goauth.WithStore(store)(s)
	}
}
