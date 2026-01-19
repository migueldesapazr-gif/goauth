# UI Pages

This guide outlines secure defaults for login, register, and account pages.

## Login Page

Recommended fields:
- Email or username
- Password
- Optional: remember me (client-side only)

Security notes:
- Always send login over HTTPS.
- Show generic errors ("invalid credentials").
- Rate limit login attempts (server-side).
- Require 2FA if configured.

Example API call:

```http
POST /auth/login
Content-Type: application/json

{"email":"user@example.com","password":"..."}
```

If `requires_2fa=true`, prompt for TOTP or backup code and call:

```http
POST /auth/login/2fa
```

## Register Page

Recommended fields:
- Email
- Password
- Optional: username

Security notes:
- Validate email and username server-side.
- Show strength feedback client-side, but enforce rules on server.
- Require email verification if enabled.

Example API call:

```http
POST /auth/register
Content-Type: application/json

{"email":"user@example.com","password":"...","username":"user"}
```

## Account Page

Common actions:
- View profile: `GET /auth/me`
- Update profile: `PUT /auth/profile`
- Setup 2FA: `POST /auth/2fa/setup` then `POST /auth/2fa/verify`
- Disable 2FA: `POST /auth/2fa/disable`
- Change email: `POST /auth/email/change/request`
- Logout: `POST /auth/logout`

Security notes:
- Require current password for sensitive actions.
- Confirm email changes via link sent to new address.
- Notify users on password/email changes if enabled.
- Revoke sessions after password reset.

## Privacy and Consent

- Explain what data is stored (IP, user agent hash, audit logs).
- Offer opt-in settings only if supported by configuration.
- Provide a way to export/delete data if using GDPR endpoints.
