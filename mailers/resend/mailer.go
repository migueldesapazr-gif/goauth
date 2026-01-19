// Package resend provides a Resend email provider implementation.
package resend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Mailer implements goauth.Mailer using Resend API.
type Mailer struct {
	apiKey    string
	fromEmail string
	fromName  string
	client    *http.Client
}

// New creates a new Resend mailer.
func New(apiKey, fromEmail, fromName string) *Mailer {
	return &Mailer{
		apiKey:    apiKey,
		fromEmail: fromEmail,
		fromName:  fromName,
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// SendVerification sends a verification email with code and link.
func (m *Mailer) SendVerification(ctx context.Context, to, code, link string) error {
	subject := "Verify your email"
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<style>
		body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
		.container { max-width: 600px; margin: 0 auto; padding: 20px; }
		.code { font-size: 32px; font-weight: bold; letter-spacing: 4px; color: #2563eb; text-align: center; padding: 20px; background: #f3f4f6; border-radius: 8px; margin: 20px 0; }
		.button { display: inline-block; padding: 12px 24px; background: #2563eb; color: white; text-decoration: none; border-radius: 6px; margin: 20px 0; }
		.footer { font-size: 12px; color: #6b7280; margin-top: 40px; }
	</style>
</head>
<body>
	<div class="container">
		<h1>Verify your email</h1>
		<p>Enter this code to verify your email:</p>
		<div class="code">%s</div>
		<p>Or click the button below:</p>
		<a href="%s" class="button">Verify Email</a>
		<p class="footer">This code expires in 15 minutes. If you didn't request this, you can ignore this email.</p>
	</div>
</body>
</html>`, code, link)

	text := fmt.Sprintf(`Verify your email

Your verification code is: %s

Or click this link: %s

This code expires in 15 minutes.`, code, link)

	return m.send(ctx, to, subject, html, text)
}

// SendPasswordReset sends a password reset email.
func (m *Mailer) SendPasswordReset(ctx context.Context, to, link string) error {
	subject := "Reset your password"
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<style>
		body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
		.container { max-width: 600px; margin: 0 auto; padding: 20px; }
		.button { display: inline-block; padding: 12px 24px; background: #2563eb; color: white; text-decoration: none; border-radius: 6px; margin: 20px 0; }
		.footer { font-size: 12px; color: #6b7280; margin-top: 40px; }
	</style>
</head>
<body>
	<div class="container">
		<h1>Reset your password</h1>
		<p>Click the button below to reset your password:</p>
		<a href="%s" class="button">Reset Password</a>
		<p class="footer">This link expires in 1 hour. If you didn't request this, you can ignore this email.</p>
	</div>
</body>
</html>`, link)

	text := fmt.Sprintf(`Reset your password

Click this link to reset your password: %s

This link expires in 1 hour.`, link)

	return m.send(ctx, to, subject, html, text)
}

// SendPasswordChanged sends a password change notification.
func (m *Mailer) SendPasswordChanged(ctx context.Context, to string) error {
	subject := "Your password was changed"
	html := `
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<style>
		body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
		.container { max-width: 600px; margin: 0 auto; padding: 20px; }
		.footer { font-size: 12px; color: #6b7280; margin-top: 40px; }
	</style>
</head>
<body>
	<div class="container">
		<h1>Password changed</h1>
		<p>Your password was changed. If this wasn't you, reset your password immediately.</p>
		<p class="footer">If you did this, you can ignore this email.</p>
	</div>
</body>
</html>`

	text := "Your password was changed. If this wasn't you, reset your password immediately."

	return m.send(ctx, to, subject, html, text)
}

// SendEmailChange sends an email change confirmation link.
func (m *Mailer) SendEmailChange(ctx context.Context, to, link string) error {
	subject := "Confirm your new email"
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<style>
		body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
		.container { max-width: 600px; margin: 0 auto; padding: 20px; }
		.button { display: inline-block; padding: 12px 24px; background: #2563eb; color: white; text-decoration: none; border-radius: 6px; margin: 20px 0; }
		.footer { font-size: 12px; color: #6b7280; margin-top: 40px; }
	</style>
</head>
<body>
	<div class="container">
		<h1>Confirm your new email</h1>
		<p>Click the button below to confirm your new email:</p>
		<a href="%s" class="button">Confirm Email</a>
		<p class="footer">If you didn't request this, you can ignore this email.</p>
	</div>
</body>
</html>`, link)

	text := fmt.Sprintf("Confirm your new email: %s", link)

	return m.send(ctx, to, subject, html, text)
}

// SendEmailChanged sends a notification when email changes are completed.
func (m *Mailer) SendEmailChanged(ctx context.Context, to, newEmail string) error {
	subject := "Your email was changed"
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<style>
		body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; }
		.container { max-width: 600px; margin: 0 auto; padding: 20px; }
		.footer { font-size: 12px; color: #6b7280; margin-top: 40px; }
	</style>
</head>
<body>
	<div class="container">
		<h1>Email changed</h1>
		<p>Your email was changed to %s. If this wasn't you, contact support.</p>
	</div>
</body>
</html>`, newEmail)

	text := fmt.Sprintf("Your email was changed to %s. If this wasn't you, contact support.", newEmail)

	return m.send(ctx, to, subject, html, text)
}

func (m *Mailer) send(ctx context.Context, to, subject, html, text string) error {
	payload := map[string]any{
		"from":    fmt.Sprintf("%s <%s>", m.fromName, m.fromEmail),
		"to":      []string{to},
		"subject": subject,
		"html":    html,
		"text":    text,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.resend.com/emails", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+m.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("resend returned status %d", resp.StatusCode)
	}

	return nil
}
