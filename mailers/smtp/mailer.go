// Package smtp provides an SMTP email provider implementation.
package smtp

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
)

// Config holds SMTP configuration.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	FromEmail string
	FromName  string
	// UseTLS enables implicit TLS (e.g. port 465).
	UseTLS bool
}

// Mailer implements goauth.Mailer using SMTP.
type Mailer struct {
	host     string
	port     int
	username string
	password string
	fromEmail string
	fromName  string
	useTLS   bool
}

// New creates a new SMTP mailer.
func New(cfg Config) *Mailer {
	return &Mailer{
		host:      cfg.Host,
		port:      cfg.Port,
		username:  cfg.Username,
		password:  cfg.Password,
		fromEmail: cfg.FromEmail,
		fromName:  cfg.FromName,
		useTLS:    cfg.UseTLS,
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
	if m.host == "" || m.fromEmail == "" {
		return fmt.Errorf("smtp config incomplete")
	}

	from := m.fromEmail
	if m.fromName != "" {
		from = fmt.Sprintf("%s <%s>", m.fromName, m.fromEmail)
	}

	boundary := "goauth-boundary"
	var msg bytes.Buffer
	msg.WriteString(fmt.Sprintf("From: %s\r\n", from))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", to))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: multipart/alternative; boundary=" + boundary + "\r\n\r\n")
	msg.WriteString("--" + boundary + "\r\n")
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
	msg.WriteString(text + "\r\n\r\n")
	msg.WriteString("--" + boundary + "\r\n")
	msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n")
	msg.WriteString(html + "\r\n\r\n")
	msg.WriteString("--" + boundary + "--\r\n")

	addr := fmt.Sprintf("%s:%d", m.host, m.port)
	var auth smtp.Auth
	if m.username != "" || m.password != "" {
		auth = smtp.PlainAuth("", m.username, m.password, m.host)
	}

	if !m.useTLS {
		return smtp.SendMail(addr, auth, m.fromEmail, []string{to}, msg.Bytes())
	}

	tlsConfig := &tls.Config{ServerName: m.host}
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, m.host)
	if err != nil {
		return err
	}
	defer client.Close()

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return err
		}
	}

	if err := client.Mail(m.fromEmail); err != nil {
		return err
	}
	if err := client.Rcpt(strings.TrimSpace(to)); err != nil {
		return err
	}

	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg.Bytes()); err != nil {
		return err
	}
	return w.Close()
}
