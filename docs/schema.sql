-- GoAuth Database Schema
-- Compatible with PostgreSQL 13+
-- Optimized for large-scale deployments

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ==================== USERS ====================

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email_hash BYTEA NOT NULL UNIQUE,
    email_encrypted BYTEA NOT NULL,
    email_nonce BYTEA NOT NULL,
    username VARCHAR(64),
    username_normalized VARCHAR(64),
    password_hash BYTEA,
    password_salt BYTEA,
    totp_secret_encrypted BYTEA,
    totp_nonce BYTEA,
    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    email_verified_at TIMESTAMPTZ,
    account_status VARCHAR(32) NOT NULL DEFAULT 'pending_verification',
    role VARCHAR(32) NOT NULL DEFAULT 'user',
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_at TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    last_login_ip_encrypted BYTEA,
    last_login_ip_nonce BYTEA,
    verification_deadline TIMESTAMPTZ,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email_hash ON users(email_hash);
CREATE UNIQUE INDEX idx_users_username_normalized ON users(username_normalized) WHERE username_normalized IS NOT NULL;
CREATE INDEX idx_users_account_status ON users(account_status);
CREATE INDEX idx_users_created_at ON users(created_at);
CREATE INDEX idx_users_verification_deadline ON users(verification_deadline) WHERE verification_deadline IS NOT NULL;

-- ==================== PROFILES ====================

CREATE TABLE IF NOT EXISTS profiles (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    display_name VARCHAR(100),
    display_photo_url VARCHAR(2048),
    bio VARCHAR(500),
    locale VARCHAR(32),
    timezone VARCHAR(64),
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==================== PASSWORD HISTORY ====================

CREATE TABLE IF NOT EXISTS password_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash BYTEA NOT NULL,
    password_salt BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_password_history_user ON password_history(user_id, created_at DESC);

-- ==================== TOTP BACKUP CODES ====================

CREATE TABLE IF NOT EXISTS totp_backup_codes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash BYTEA NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_backup_codes_user ON totp_backup_codes(user_id);

-- ==================== VERIFICATION TOKENS ====================

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash BYTEA NOT NULL,
    link_token_hash BYTEA NOT NULL,
    email_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    code_attempts INTEGER NOT NULL DEFAULT 0,
    max_code_attempts INTEGER NOT NULL DEFAULT 5,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMPTZ,
    ip_created_encrypted BYTEA,
    ip_created_nonce BYTEA,
    ip_used_encrypted BYTEA,
    ip_used_nonce BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_verification_user ON email_verification_tokens(user_id);
CREATE INDEX idx_verification_link ON email_verification_tokens(link_token_hash);
CREATE INDEX idx_verification_expires ON email_verification_tokens(expires_at);

-- ==================== PASSWORD RESET TOKENS ====================

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMPTZ,
    ip_request_encrypted BYTEA,
    ip_request_nonce BYTEA,
    ip_used_encrypted BYTEA,
    ip_used_nonce BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_reset_token_hash ON password_reset_tokens(token_hash);
CREATE INDEX idx_reset_expires ON password_reset_tokens(expires_at);

-- ==================== EMAIL CHANGE TOKENS ====================

CREATE TABLE IF NOT EXISTS email_change_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    new_email_hash BYTEA NOT NULL,
    new_email_encrypted BYTEA NOT NULL,
    new_email_nonce BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMPTZ,
    ip_created_encrypted BYTEA,
    ip_created_nonce BYTEA,
    ip_used_encrypted BYTEA,
    ip_used_nonce BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_email_change_hash ON email_change_tokens(token_hash);
CREATE INDEX idx_email_change_expires ON email_change_tokens(expires_at);

-- ==================== REFRESH TOKENS ====================

CREATE TABLE IF NOT EXISTS refresh_tokens (
    jti VARCHAR(64) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    ip_encrypted BYTEA,
    ip_nonce BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_expires ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_device ON refresh_tokens(device_id);

-- ==================== MAGIC LINK TOKENS ====================

CREATE TABLE IF NOT EXISTS magic_link_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    used_at TIMESTAMPTZ,
    ip_created_encrypted BYTEA,
    ip_created_nonce BYTEA,
    ip_used_encrypted BYTEA,
    ip_used_nonce BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_magic_token_hash ON magic_link_tokens(token_hash);
CREATE INDEX idx_magic_expires ON magic_link_tokens(expires_at);

-- ==================== DEVICES ====================

CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    device_type VARCHAR(32) NOT NULL, -- 'browser', 'mobile', 'desktop', 'api'
    fingerprint_hash BYTEA,
    last_ip_encrypted BYTEA,
    last_ip_nonce BYTEA,
    last_active TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    trust_level VARCHAR(32) NOT NULL DEFAULT 'untrusted',
    refresh_token_jti VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_devices_user ON devices(user_id);
CREATE INDEX idx_devices_refresh ON devices(refresh_token_jti);

-- ==================== API KEYS ====================

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID,
    name VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(16) NOT NULL,
    key_hash BYTEA NOT NULL,
    scopes TEXT[],
    rate_limit INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ,
    last_used TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_user ON api_keys(user_id);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);

-- ==================== OAUTH CONNECTIONS ====================

CREATE TABLE IF NOT EXISTS oauth_connections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(32) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    access_token_encrypted BYTEA,
    access_token_nonce BYTEA,
    refresh_token_encrypted BYTEA,
    refresh_token_nonce BYTEA,
    token_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(provider, provider_user_id)
);

CREATE INDEX idx_oauth_user ON oauth_connections(user_id);
CREATE INDEX idx_oauth_provider ON oauth_connections(provider, provider_user_id);

-- ==================== WEBAUTHN/PASSKEYS ====================

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    attestation_type VARCHAR(32) NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    aaguid BYTEA,
    name VARCHAR(64),
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webauthn_creds_user ON webauthn_credentials(user_id);
CREATE UNIQUE INDEX idx_webauthn_creds_id ON webauthn_credentials(credential_id);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    challenge BYTEA NOT NULL UNIQUE,
    user_id UUID,
    type VARCHAR(32) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webauthn_challenges ON webauthn_challenges(challenge);
CREATE INDEX idx_webauthn_challenges_expires ON webauthn_challenges(expires_at);

-- ==================== TENANTS (MULTI-TENANT) ====================

CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(64) NOT NULL UNIQUE,
    plan VARCHAR(32) NOT NULL DEFAULT 'free',
    settings JSONB NOT NULL DEFAULT '{}',
    suspended_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tenants_slug ON tenants(slug);

CREATE TABLE IF NOT EXISTS tenant_users (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(32) NOT NULL DEFAULT 'member',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, user_id)
);

-- ==================== WEBHOOKS ====================

CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    url VARCHAR(2048) NOT NULL,
    secret_hash BYTEA NOT NULL,
    events TEXT[] NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    last_triggered TIMESTAMPTZ,
    failure_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhooks_tenant ON webhooks(tenant_id);
CREATE INDEX idx_webhooks_active ON webhooks(active) WHERE active = TRUE;

-- ==================== AUDIT LOGS ====================

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID,
    tenant_id UUID,
    event_type VARCHAR(64) NOT NULL,
    ip_encrypted BYTEA,
    ip_nonce BYTEA,
    user_agent_hash BYTEA,
    metadata_encrypted BYTEA,
    metadata_nonce BYTEA,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partitioning for large-scale deployments
-- CREATE TABLE audit_logs (
--     ...
-- ) PARTITION BY RANGE (created_at);

CREATE INDEX idx_audit_user ON audit_logs(user_id, created_at DESC);
CREATE INDEX idx_audit_tenant ON audit_logs(tenant_id, created_at DESC);
CREATE INDEX idx_audit_event ON audit_logs(event_type);
CREATE INDEX idx_audit_expires ON audit_logs(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_audit_created ON audit_logs(created_at);

-- ==================== SESSIONS ====================

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID,
    device_id UUID,
    expires_at TIMESTAMPTZ NOT NULL,
    last_active TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_encrypted BYTEA,
    ip_nonce BYTEA,
    user_agent VARCHAR(512),
    data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

-- ==================== FUNCTIONS ====================

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_tenants_updated_at BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_oauth_updated_at BEFORE UPDATE ON oauth_connections
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ==================== MAINTENANCE ====================

-- To be run periodically (via cron or application)
-- DELETE FROM email_verification_tokens WHERE expires_at < NOW();
-- DELETE FROM password_reset_tokens WHERE expires_at < NOW();
-- DELETE FROM refresh_tokens WHERE expires_at < NOW();
-- DELETE FROM magic_link_tokens WHERE expires_at < NOW();
-- DELETE FROM audit_logs WHERE expires_at IS NOT NULL AND expires_at < NOW();
-- DELETE FROM users WHERE email_verified = false AND verification_deadline < NOW();
