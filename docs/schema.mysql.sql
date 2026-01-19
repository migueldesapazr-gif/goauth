-- GoAuth Database Schema (MySQL 8+)

CREATE TABLE IF NOT EXISTS users (
    id CHAR(36) PRIMARY KEY,
    email_hash BLOB NOT NULL UNIQUE,
    email_encrypted BLOB NOT NULL,
    email_nonce BLOB NOT NULL,
    username VARCHAR(64) NULL,
    username_normalized VARCHAR(64) NULL,
    password_hash BLOB NULL,
    password_salt BLOB NULL,
    totp_secret_encrypted BLOB NULL,
    totp_nonce BLOB NULL,
    totp_enabled TINYINT(1) NOT NULL DEFAULT 0,
    email_verified TINYINT(1) NOT NULL DEFAULT 0,
    email_verified_at DATETIME NULL,
    account_status VARCHAR(32) NOT NULL DEFAULT 'pending_verification',
    role VARCHAR(32) NOT NULL DEFAULT 'user',
    failed_login_attempts INT NOT NULL DEFAULT 0,
    locked_at DATETIME NULL,
    last_login_at DATETIME NULL,
    last_login_ip_encrypted BLOB NULL,
    last_login_ip_nonce BLOB NULL,
    verification_deadline DATETIME NULL,
    metadata JSON NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX idx_users_username_normalized ON users(username_normalized);
CREATE INDEX idx_users_email_hash ON users(email_hash(32));
CREATE INDEX idx_users_account_status ON users(account_status);

CREATE TABLE IF NOT EXISTS profiles (
    user_id CHAR(36) PRIMARY KEY,
    display_name VARCHAR(100) NULL,
    display_photo_url VARCHAR(2048) NULL,
    bio VARCHAR(500) NULL,
    locale VARCHAR(32) NULL,
    timezone VARCHAR(64) NULL,
    metadata JSON NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS password_history (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    password_hash BLOB NOT NULL,
    password_salt BLOB NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_password_history_user (user_id, created_at DESC),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS totp_backup_codes (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    code_hash BLOB NOT NULL,
    used TINYINT(1) NOT NULL DEFAULT 0,
    used_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_backup_codes_user (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    code_hash BLOB NOT NULL,
    link_token_hash BLOB NOT NULL,
    email_hash BLOB NOT NULL,
    expires_at DATETIME NOT NULL,
    code_attempts INT NOT NULL DEFAULT 0,
    max_code_attempts INT NOT NULL DEFAULT 5,
    used TINYINT(1) NOT NULL DEFAULT 0,
    used_at DATETIME NULL,
    ip_created_encrypted BLOB NULL,
    ip_created_nonce BLOB NULL,
    ip_used_encrypted BLOB NULL,
    ip_used_nonce BLOB NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_verification_user (user_id),
    INDEX idx_verification_link (link_token_hash(32)),
    INDEX idx_verification_expires (expires_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    token_hash BLOB NOT NULL,
    expires_at DATETIME NOT NULL,
    used TINYINT(1) NOT NULL DEFAULT 0,
    used_at DATETIME NULL,
    ip_request_encrypted BLOB NULL,
    ip_request_nonce BLOB NULL,
    ip_used_encrypted BLOB NULL,
    ip_used_nonce BLOB NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_reset_token_hash (token_hash(32)),
    INDEX idx_reset_expires (expires_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS email_change_tokens (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    token_hash BLOB NOT NULL,
    new_email_hash BLOB NOT NULL,
    new_email_encrypted BLOB NOT NULL,
    new_email_nonce BLOB NOT NULL,
    expires_at DATETIME NOT NULL,
    used TINYINT(1) NOT NULL DEFAULT 0,
    used_at DATETIME NULL,
    ip_created_encrypted BLOB NULL,
    ip_created_nonce BLOB NULL,
    ip_used_encrypted BLOB NULL,
    ip_used_nonce BLOB NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_email_change_hash (token_hash(32)),
    INDEX idx_email_change_expires (expires_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    jti VARCHAR(64) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    device_id CHAR(36) NULL,
    expires_at DATETIME NOT NULL,
    revoked_at DATETIME NULL,
    ip_encrypted BLOB NULL,
    ip_nonce BLOB NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_refresh_user (user_id),
    INDEX idx_refresh_expires (expires_at),
    INDEX idx_refresh_device (device_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS magic_link_tokens (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    token_hash BLOB NOT NULL,
    expires_at DATETIME NOT NULL,
    used TINYINT(1) NOT NULL DEFAULT 0,
    used_at DATETIME NULL,
    ip_created_encrypted BLOB NULL,
    ip_created_nonce BLOB NULL,
    ip_used_encrypted BLOB NULL,
    ip_used_nonce BLOB NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_magic_token_hash (token_hash(32)),
    INDEX idx_magic_expires (expires_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    ip_encrypted BLOB NULL,
    ip_nonce BLOB NULL,
    user_agent_hash BLOB NULL,
    metadata_encrypted BLOB NULL,
    metadata_nonce BLOB NULL,
    expires_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_user (user_id),
    INDEX idx_audit_created_at (created_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS oauth_connections (
    id CHAR(36) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    provider VARCHAR(64) NOT NULL,
    provider_user_id VARCHAR(128) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE INDEX idx_oauth_provider_user (provider, provider_user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
