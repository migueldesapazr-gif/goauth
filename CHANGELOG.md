# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
