-- GoAuth PostgreSQL Schema

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email_hash BYTEA NOT NULL,
    email_encrypted BYTEA NOT NULL,
    email_nonce BYTEA NOT NULL,
    username TEXT UNIQUE,
    username_normalized TEXT UNIQUE,
    password_hash BYTEA,
    password_salt BYTEA,
    account_status TEXT NOT NULL DEFAULT 'active',
    email_verified BOOLEAN DEFAULT FALSE,
    email_verified_at TIMESTAMP WITH TIME ZONE,
    verification_deadline TIMESTAMP WITH TIME ZONE,
    totp_secret_encrypted BYTEA,
    totp_nonce BYTEA,
    totp_enabled BOOLEAN DEFAULT FALSE,
    totp_verified_at TIMESTAMP WITH TIME ZONE,
    failed_login_attempts INT DEFAULT 0,
    locked_at TIMESTAMP WITH TIME ZONE,
    last_login_at TIMESTAMP WITH TIME ZONE,
    last_login_ip_encrypted BYTEA,
    last_login_ip_nonce BYTEA,
    role TEXT DEFAULT 'user',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_users_email_hash ON users(email_hash);
CREATE INDEX idx_users_username_normalized ON users(username_normalized);

-- OAuth Connections table
CREATE TABLE IF NOT EXISTS oauth_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    access_token_encrypted BYTEA,
    access_token_nonce BYTEA,
    refresh_token_encrypted BYTEA,
    refresh_token_nonce BYTEA,
    token_expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(provider, provider_user_id),
    UNIQUE(user_id, provider)
);

-- Password History
CREATE TABLE IF NOT EXISTS password_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash BYTEA NOT NULL,
    password_salt BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- TOTP Backup Codes
CREATE TABLE IF NOT EXISTS totp_backup_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash BYTEA NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Email Verification Tokens
CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash BYTEA NOT NULL,
    link_token_hash BYTEA,
    email_hash BYTEA NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    code_attempts INT DEFAULT 0,
    max_code_attempts INT DEFAULT 3,
    used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP WITH TIME ZONE,
    ip_created_encrypted BYTEA,
    ip_created_nonce BYTEA,
    ip_used_encrypted BYTEA,
    ip_used_nonce BYTEA,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_verification_link_hash ON email_verification_tokens(link_token_hash);

-- Password Reset Tokens
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP WITH TIME ZONE,
    ip_request_encrypted BYTEA,
    ip_request_nonce BYTEA,
    ip_used_encrypted BYTEA,
    ip_used_nonce BYTEA,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_password_reset_hash ON password_reset_tokens(token_hash);

-- Email Change Tokens
CREATE TABLE IF NOT EXISTS email_change_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    new_email_hash BYTEA NOT NULL,
    new_email_encrypted BYTEA NOT NULL,
    new_email_nonce BYTEA NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP WITH TIME ZONE,
    ip_created_encrypted BYTEA,
    ip_created_nonce BYTEA,
    ip_used_encrypted BYTEA,
    ip_used_nonce BYTEA,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_email_change_hash ON email_change_tokens(token_hash);

-- Refresh Tokens
CREATE TABLE IF NOT EXISTS refresh_tokens (
    jti TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE,
    ip_encrypted BYTEA,
    ip_nonce BYTEA,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);

-- Audit Logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    ip_encrypted BYTEA,
    ip_nonce BYTEA,
    user_agent_hash BYTEA,
    expires_at TIMESTAMP WITH TIME ZONE,
    metadata_encrypted BYTEA,
    metadata_nonce BYTEA,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_audit_user ON audit_logs(user_id);
CREATE INDEX idx_audit_created_at ON audit_logs(created_at);
