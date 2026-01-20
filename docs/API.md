# API Reference

All paths below assume the handler is mounted at `/auth`:

```go
r.Mount("/auth", auth.Handler())
```

## Authentication

### Register

```http
POST /auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "username": "johndoe",
  "captcha_token": "..."
}
```

Response:
```json
{
  "user_id": "uuid",
  "access_token": "eyJhbG...",
  "email_masked": "u***@example.com",
  "email_verified": false,
  "message": "Please verify your email to activate your account"
}
```

### Login

```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePassword123!",
  "captcha_token": "..."
}
```

Response (success):
```json
{
  "access_token": "eyJhbG...",
  "refresh_token": "eyJhbG...",
  "user_id": "uuid",
  "email_verified": true,
  "totp_enabled": false
}
```

Response (2FA required):
```json
{
  "requires_2fa": true,
  "temp_token": "eyJhbG..."
}
```

### Login 2FA

```http
POST /auth/login/2fa
Content-Type: application/json

{
  "temp_token": "eyJhbG...",
  "totp_code": "123456"
}
```

Backup code:
```json
{
  "temp_token": "eyJhbG...",
  "backup_code": "12345678"
}
```

### Refresh Token

```http
POST /auth/refresh
Content-Type: application/json

{"refresh_token": "eyJhbG..."}
```

### Logout

```http
POST /auth/logout
Authorization: Bearer <access_token>
```

Optional body to revoke a single refresh token:
```json
{"refresh_token": "eyJhbG..."}
```

## Email Verification

```http
POST /auth/verify/send
Authorization: Bearer <access_token>
```

```http
POST /auth/verify/code
Content-Type: application/json

{"user_id":"uuid","code":"123456"}
```

```http
GET /auth/verify/link?token=...
```

## Password Reset

```http
POST /auth/password/reset/request
Content-Type: application/json

{"email":"user@example.com"}
```

```http
POST /auth/password/reset/confirm
Content-Type: application/json

{"token":"reset-token","password":"NewSecurePassword123!"}
```

## Email Change

```http
POST /auth/email/change/request
Authorization: Bearer <access_token>
Content-Type: application/json

{"new_email":"new@example.com","password":"...","totp_code":"123456"}
```

```http
GET /auth/email/change/confirm?token=...
```

## Two-Factor Authentication (TOTP)

```http
POST /auth/2fa/setup
Authorization: Bearer <access_token>
```

Response includes secret, URL, digits, and optional QR code:
```json
{
  "secret": "BASE32SECRET",
  "url": "otpauth://totp/...",
  "issuer": "My App",
  "account_name": "user@example.com",
  "digits": 6,
  "qr_code_png": "...",
  "qr_code_data_url": "data:image/png;base64,..."
}
```

```http
POST /auth/2fa/verify
Authorization: Bearer <access_token>
Content-Type: application/json

{"code":"123456"}
```

Response returns backup codes:
```json
{
  "backup_codes": ["12345678", "23456789"],
  "backup_codes_count": 10
}
```

```http
POST /auth/2fa/disable
Authorization: Bearer <access_token>
Content-Type: application/json

{"password":"..."} // or totp_code / backup_code
```

Regenerate codes:
```http
POST /auth/2fa/backup-codes
Authorization: Bearer <access_token>
```

Download TXT:
```http
GET /auth/2fa/backup-codes.txt
Authorization: Bearer <access_token>
```

## WebAuthn/Passkeys

```http
POST /auth/webauthn/register/begin
Authorization: Bearer <access_token>
```

```http
POST /auth/webauthn/register/finish
Authorization: Bearer <access_token>
Content-Type: application/json
```

```http
POST /auth/webauthn/login/begin
Content-Type: application/json
```

```http
POST /auth/webauthn/login/finish
Content-Type: application/json
```

```http
GET /auth/webauthn/list
Authorization: Bearer <access_token>
```

```http
DELETE /auth/webauthn/delete
Authorization: Bearer <access_token>
Content-Type: application/json

{"credential_id":"..."}
```

```http
POST /auth/webauthn/rename
Authorization: Bearer <access_token>
Content-Type: application/json

{"credential_id":"...","name":"My Laptop"}
```

## OAuth

```http
GET /auth/google
GET /auth/discord
GET /auth/github
GET /auth/microsoft
GET /auth/twitch

GET /auth/{provider}/callback?code=...&state=...
```

If 2FA is required after OAuth:
```json
{
  "requires_2fa": true,
  "temp_token": "eyJhbG..."
}
```

## User

```http
GET /auth/me
Authorization: Bearer <access_token>
```

## Health and Metrics

```http
GET /auth/health
GET /auth/health?detailed=true
GET /auth/metrics
```

## Error Responses

```json
{
  "error": "human readable message",
  "code": "ERROR_CODE"
}
```

Notes:
- Login errors are intentionally generic to reduce account enumeration.
