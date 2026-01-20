# Database Schema

Canonical schemas live in:
- `docs/schema.sql` (PostgreSQL)
- `docs/schema.mysql.sql`
- `docs/schema.sqlite.sql`

This file summarizes the tables and naming used in the codebase.

## Core Tables

- `users`
- `profiles`
- `password_history`
- `totp_backup_codes`
- `email_verification_tokens`
- `password_reset_tokens`
- `email_change_tokens`
- `refresh_tokens`
- `magic_link_tokens`

## Auth Features

- `devices`
- `api_keys`
- `oauth_connections`
- `webauthn_credentials`
- `webauthn_challenges`
- `sessions`

## Enterprise

- `tenants`
- `tenant_users`
- `webhooks`
- `audit_logs`

## Maintenance

Use the cleanup queries at the bottom of `docs/schema.sql` for token and audit retention.
