// Package mailgun provides a Mailgun email provider implementation.
package mailgun

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Mailer implements goauth.Mailer using Mailgun API.
type Mailer struct {
	apiKey    string
	domain    string
	fromEmail string
	fromName  string
	baseURL   string
	client    *http.Client
}

// New creates a new Mailgun mailer.
func New(apiKey, domain, fromEmail, fromName string) *Mailer {
	return &Mailer{
		apiKey:    apiKey,
		domain:    domain,
		fromEmail: fromEmail,
		fromName:  fromName,
		baseURL:   "https://api.mailgun.net/v3",
		client:    &http.Client{Timeout: 10 * time.Second},
	}
}

// NewWithBaseURL creates a new Mailgun mailer with a custom base URL.
func NewWithBaseURL(apiKey, domain, fromEmail, fromName, baseURL string) *Mailer {
	m := New(apiKey, domain, fromEmail, fromName)
	if baseURL != "" {
		m.baseURL = baseURL
	}
	return m
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
	if m.domain == "" {
		return fmt.Errorf("mailgun domain not configured")
	}

	form := url.Values{}
	from := m.fromEmail
	if m.fromName != "" {
		from = fmt.Sprintf("%s <%s>", m.fromName, m.fromEmail)
	}
	form.Set("from", from)
	form.Set("to", to)
	form.Set("subject", subject)
	form.Set("text", text)
	form.Set("html", html)

	endpoint := fmt.Sprintf("%s/%s/messages", m.baseURL, m.domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth("api", m.apiKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("mailgun returned status %d", resp.StatusCode)
	}
	return nil
}
