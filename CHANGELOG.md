# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.5] - 2026-01-20

### Fixed
- **Discord OAuth**: Token exchange now uses HTTP Basic Auth per official Discord API docs
- **hCaptcha**: Fixed verification endpoint URL (`api.hcaptcha.com/siteverify`)

### Added
- **OAuth Scope Customization**: All providers now support custom scopes via option patterns:
  - `WithGoogleScopes(scopes ...string)` for Google OAuth
  - `WithDiscordScopes(scopes ...string)` for Discord OAuth
  - `WithGitHubScopes(scopes ...string)` for GitHub OAuth
- `User-Agent` header added to all OAuth API requests for better compatibility
- PostgreSQL schema file (`schema/postgres.sql`) for easy database initialization

### Changed
- OAuth provider constructors now accept variadic options for scope configuration:
  - `NewGoogleProvider(clientID, secret, opts...)` 
  - `NewDiscordProvider(clientID, secret, opts...)`
  - `NewGitHubProvider(clientID, secret, opts...)`

## [1.1.0] - 2026-01-19

### Changed
- **BREAKING**: Store configuration moved to store packages
  - Use `postgres.WithDatabase(db)` instead of `goauth.WithDatabase(db)`
  - Import `github.com/migueldesapazr-gif/goauth/stores/postgres`
- Updated Go minimum version to 1.24
- Updated all dependencies to latest stable versions:
  - `pgx/v5` v5.5.5 → v5.7.4 (security patches)
  - `go-redis/v9` v9.5.1 → v9.7.3
  - `mongo-driver` v1.15.0 → v1.17.3
  - `golang.org/x/crypto` v0.23.0 → v0.37.0
  - `chi/v5` v5.0.10 → v5.2.1
  - `jwt/v5` v5.2.1 → v5.2.2
  - AWS SDK and other dependencies updated

### Added
- New error types: `ErrPasskeyLimitReached`, `ErrPasskeyNotAllowed`, `ErrMagicLinkExpired`, `ErrMagicLinkUsed`
- New error codes: `CodePasskeyLimit`, `CodePasskeyNotAllowed`, `CodeMagicLinkExpired`, `CodeMagicLinkUsed`
- `AuthError.Is()` method for proper error comparison
- `wrapError()` helper for contextual error wrapping
- `isNotFoundError()` helper function
- Configuration errors: `ErrStoreNotConfigured`, `ErrMailerNotConfigured`

### Fixed
- Import cycle between main package and store packages
- Missing `GetUserAuditLogs` method in postgres store
- Missing `UpdateUserRole` method in postgres store
- Duplicate `err` variable declaration in login handler

## [1.0.0] - 2026-01-19

### Added
- Initial release
- Email/password authentication with Argon2id
- OAuth support (Google, Discord, GitHub, Microsoft, Twitch)
- WebAuthn/Passkeys (FIDO2)
- Magic links (passwordless email)
- TOTP 2FA with backup codes
- CAPTCHA integration (Turnstile, reCAPTCHA, hCaptcha)
- Rate limiting with sliding window
- IP blocking for brute force protection
- Token blacklist for immediate revocation
- Multi-tenancy support
- RBAC (Role-Based Access Control)
- Device management
- Audit logging
- Webhooks
- API keys
- Prometheus metrics
- Health checks
- Security modes (permissive, balanced, strict)
- Disposable email blocking
- PostgreSQL, MySQL, MongoDB, SQLite adapters
- GDPR compliance features (data export, deletion)

### Security
- AES-256-GCM encryption for all PII
- HKDF key derivation from master key
- HIBP password breach detection
- Constant-time comparisons
- Secure session management
