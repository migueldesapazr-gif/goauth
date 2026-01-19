// Package sendgrid provides a SendGrid email provider implementation.
package sendgrid

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Mailer implements goauth.Mailer using SendGrid API.
type Mailer struct {
	apiKey    string
	fromEmail string
	fromName  string
	client    *http.Client
}

// New creates a new SendGrid mailer.
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
	text := fmt.Sprintf("Your verification code is: %s\n\nVerify link: %s", code, link)
	html := fmt.Sprintf("<p>Your verification code is: <strong>%s</strong></p><p>Verify link: <a href=\"%s\">%s</a></p>", code, link, link)
	return m.send(ctx, to, subject, text, html)
}

// SendPasswordReset sends a password reset email.
func (m *Mailer) SendPasswordReset(ctx context.Context, to, link string) error {
	subject := "Reset your password"
	text := fmt.Sprintf("Reset link: %s", link)
	html := fmt.Sprintf("<p>Reset link: <a href=\"%s\">%s</a></p>", link, link)
	return m.send(ctx, to, subject, text, html)
}

// SendPasswordChanged sends a password change notification.
func (m *Mailer) SendPasswordChanged(ctx context.Context, to string) error {
	subject := "Your password was changed"
	text := "Your password was changed. If this wasn't you, reset your password immediately."
	html := "<p>Your password was changed. If this wasn't you, reset your password immediately.</p>"
	return m.send(ctx, to, subject, text, html)
}

// SendEmailChange sends an email change confirmation link.
func (m *Mailer) SendEmailChange(ctx context.Context, to, link string) error {
	subject := "Confirm your new email"
	text := fmt.Sprintf("Confirm your new email: %s", link)
	html := fmt.Sprintf("<p>Confirm your new email: <a href=\"%s\">%s</a></p>", link, link)
	return m.send(ctx, to, subject, text, html)
}

// SendEmailChanged sends a notification when email changes are completed.
func (m *Mailer) SendEmailChanged(ctx context.Context, to, newEmail string) error {
	subject := "Your email was changed"
	text := fmt.Sprintf("Your email was changed to %s. If this wasn't you, contact support.", newEmail)
	html := fmt.Sprintf("<p>Your email was changed to %s. If this wasn't you, contact support.</p>", newEmail)
	return m.send(ctx, to, subject, text, html)
}

func (m *Mailer) send(ctx context.Context, to, subject, text, html string) error {
	payload := map[string]any{
		"personalizations": []map[string]any{
			{
				"to": []map[string]string{{"email": to}},
				"subject": subject,
			},
		},
		"from": map[string]string{
			"email": m.fromEmail,
			"name":  m.fromName,
		},
		"content": []map[string]string{
			{"type": "text/plain", "value": text},
			{"type": "text/html", "value": html},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.sendgrid.com/v3/mail/send", bytes.NewReader(body))
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
		return fmt.Errorf("sendgrid returned status %d", resp.StatusCode)
	}
	return nil
}
