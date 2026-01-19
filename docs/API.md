# API Reference

Complete API endpoint documentation.

## Authentication

### Register

```http
POST /auth/register
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "username": "johndoe",           // optional
    "captcha_token": "..."           // if CAPTCHA enabled
}
```

**Response:**
```json
{
    "message": "registration successful",
    "user_id": "uuid",
    "email_verified": false
}
```

---

### Login

```http
POST /auth/login
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "SecurePassword123!",
    "captcha_token": "..."           // if CAPTCHA enabled
}
```

**Response (success):**
```json
{
    "access_token": "eyJhbG...",
    "refresh_token": "eyJhbG...",
    "user_id": "uuid",
    "email_verified": true
}
```

**Response (2FA required):**
```json
{
    "requires_2fa": true,
    "temp_token": "eyJhbG...",
    "user_id": "uuid"
}
```

---

### 2FA Validation

```http
POST /auth/2fa/validate
Content-Type: application/json

{
    "temp_token": "eyJhbG...",
    "totp_code": "123456"
}
```

---

### Refresh Token

```http
POST /auth/refresh
Content-Type: application/json

{
    "refresh_token": "eyJhbG..."
}
```

---

### Logout

```http
POST /auth/logout
Authorization: Bearer <access_token>
```

---

## Password Management

### Request Reset

```http
POST /auth/password/reset
Content-Type: application/json

{
    "email": "user@example.com"
}
```

### Confirm Reset

```http
POST /auth/password/reset/confirm
Content-Type: application/json

{
    "token": "reset-token",
    "new_password": "NewSecurePassword123!"
}
```

### Change Password

```http
POST /auth/password/change
Authorization: Bearer <access_token>
Content-Type: application/json

{
    "current_password": "OldPassword123!",
    "new_password": "NewPassword123!"
}
```

---

## Email Verification

### Verify Email

```http
POST /auth/verify-email
Content-Type: application/json

{
    "token": "verification-token"
}
```

### Resend Verification

```http
POST /auth/verify-email/resend
Authorization: Bearer <access_token>
```

---

## Two-Factor Authentication

### Setup 2FA

```http
POST /auth/2fa/setup
Authorization: Bearer <access_token>
```

**Response:**
```json
{
    "secret": "BASE32SECRET",
    "qr_code": "otpauth://totp/...",
    "backup_codes": ["code1", "code2", ...]
}
```

### Verify 2FA Setup

```http
POST /auth/2fa/verify
Authorization: Bearer <access_token>
Content-Type: application/json

{
    "totp_code": "123456"
}
```

### Disable 2FA

```http
POST /auth/2fa/disable
Authorization: Bearer <access_token>
Content-Type: application/json

{
    "totp_code": "123456"
}
```

---

## WebAuthn/Passkeys

### Begin Registration

```http
POST /auth/webauthn/register/begin
Authorization: Bearer <access_token>
```

### Finish Registration

```http
POST /auth/webauthn/register/finish
Authorization: Bearer <access_token>
Content-Type: application/json

{
    "id": "...",
    "rawId": "...",
    "type": "public-key",
    "response": {
        "clientDataJSON": "...",
        "attestationObject": "..."
    },
    "name": "My Passkey"
}
```

### Begin Login

```http
POST /auth/webauthn/login/begin
Content-Type: application/json

{
    "email": "user@example.com"    // optional
}
```

### Finish Login

```http
POST /auth/webauthn/login/finish
Content-Type: application/json

{
    "id": "...",
    "rawId": "...",
    "type": "public-key",
    "response": {
        "clientDataJSON": "...",
        "authenticatorData": "...",
        "signature": "...",
        "userHandle": "..."
    }
}
```

### List Passkeys

```http
GET /auth/webauthn/list
Authorization: Bearer <access_token>
```

### Delete Passkey

```http
DELETE /auth/webauthn/delete
Authorization: Bearer <access_token>
Content-Type: application/json

{
    "credential_id": "..."
}
```

---

## OAuth

### Begin OAuth Flow

```http
GET /auth/google
GET /auth/discord
GET /auth/github
GET /auth/microsoft
GET /auth/twitch
```

### OAuth Callback

```http
GET /auth/{provider}/callback?code=...&state=...
```

---

## User Profile

### Get Current User

```http
GET /auth/me
Authorization: Bearer <access_token>
```

**Response:**
```json
{
    "user_id": "uuid",
    "email": "u***@example.com",
    "username": "johndoe",
    "email_verified": true,
    "totp_enabled": true
}
```

---

## Health & Metrics

### Health Check

```http
GET /health
GET /health?detailed=true
```

### Prometheus Metrics

```http
GET /metrics
```

---

## Error Responses

All errors follow this format:

```json
{
    "error": {
        "code": "ERROR_CODE",
        "message": "Human readable message"
    }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_CREDENTIALS` | 401 | Wrong email/password |
| `ACCOUNT_LOCKED` | 403 | Too many failed attempts |
| `ACCOUNT_NOT_VERIFIED` | 403 | Email not verified |
| `ACCOUNT_SUSPENDED` | 403 | Account suspended |
| `EMAIL_EXISTS` | 409 | Email already registered |
| `WEAK_PASSWORD` | 400 | Password too weak |
| `INVALID_TOKEN` | 401 | Invalid/expired token |
| `2FA_REQUIRED` | 403 | 2FA code needed |
| `RATE_LIMITED` | 429 | Too many requests |
| `IP_BLOCKED` | 403 | IP temporarily blocked |
