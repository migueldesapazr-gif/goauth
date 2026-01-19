package goauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ==================== GOOGLE TOKEN REFRESH/REVOKE ====================

// RefreshToken refreshes a Google access token.
func (p *GoogleProvider) RefreshToken(ctx context.Context, refreshToken string) (*OAuthTokens, error) {
	data := url.Values{}
	data.Set("client_id", p.clientID)
	data.Set("client_secret", p.clientSecret)
	data.Set("refresh_token", refreshToken)
	data.Set("grant_type", "refresh_token")

	return exchangeToken(ctx, p.tokenURL, data)
}

// RevokeToken revokes a Google access token.
func (p *GoogleProvider) RevokeToken(ctx context.Context, token string) error {
	revokeURL := "https://oauth2.googleapis.com/revoke?token=" + url.QueryEscape(token)
	
	req, err := http.NewRequestWithContext(ctx, "POST", revokeURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Google returns 200 on success
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return &AuthError{Code: "REVOKE_FAILED", Message: string(body)}
	}
	return nil
}

// ==================== DISCORD TOKEN REFRESH/REVOKE ====================

// RefreshToken refreshes a Discord access token.
func (p *DiscordProvider) RefreshToken(ctx context.Context, refreshToken string) (*OAuthTokens, error) {
	data := url.Values{}
	data.Set("client_id", p.clientID)
	data.Set("client_secret", p.clientSecret)
	data.Set("refresh_token", refreshToken)
	data.Set("grant_type", "refresh_token")

	return exchangeToken(ctx, p.tokenURL, data)
}

// RevokeToken revokes a Discord access token.
func (p *DiscordProvider) RevokeToken(ctx context.Context, token string) error {
	revokeURL := "https://discord.com/api/oauth2/token/revoke"
	
	data := url.Values{}
	data.Set("client_id", p.clientID)
	data.Set("client_secret", p.clientSecret)
	data.Set("token", token)

	req, err := http.NewRequestWithContext(ctx, "POST", revokeURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return &AuthError{Code: "REVOKE_FAILED", Message: string(body)}
	}
	return nil
}

// ==================== GITHUB (No refresh, can delete token) ====================

// RevokeToken deletes a GitHub OAuth app authorization.
func (p *GitHubProvider) RevokeToken(ctx context.Context, token string) error {
	// GitHub doesn't support standard OAuth revocation
	// Users must revoke access from their GitHub settings
	return nil
}

// ==================== MICROSOFT TOKEN REFRESH ====================

// RefreshToken refreshes a Microsoft access token.
func (p *MicrosoftProvider) RefreshToken(ctx context.Context, refreshToken string) (*OAuthTokens, error) {
	data := url.Values{}
	data.Set("client_id", p.clientID)
	data.Set("client_secret", p.clientSecret)
	data.Set("refresh_token", refreshToken)
	data.Set("grant_type", "refresh_token")

	return exchangeToken(ctx, p.tokenURL, data)
}

// ==================== TWITCH TOKEN REFRESH/REVOKE ====================

// RefreshToken refreshes a Twitch access token.
func (p *TwitchProvider) RefreshToken(ctx context.Context, refreshToken string) (*OAuthTokens, error) {
	data := url.Values{}
	data.Set("client_id", p.clientID)
	data.Set("client_secret", p.clientSecret)
	data.Set("refresh_token", refreshToken)
	data.Set("grant_type", "refresh_token")

	return exchangeToken(ctx, p.tokenURL, data)
}

// RevokeToken revokes a Twitch access token.
func (p *TwitchProvider) RevokeToken(ctx context.Context, token string) error {
	revokeURL := "https://id.twitch.tv/oauth2/revoke"

	data := url.Values{}
	data.Set("client_id", p.clientID)
	data.Set("token", token)

	req, err := http.NewRequestWithContext(ctx, "POST", revokeURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return &AuthError{Code: "REVOKE_FAILED", Message: string(body)}
	}
	return nil
}

// ==================== HELPER ====================

func exchangeToken(ctx context.Context, tokenURL string, data url.Values) (*OAuthTokens, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &AuthError{Code: "TOKEN_REFRESH_FAILED", Message: string(body)}
	}

	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, err
	}

	return &OAuthTokens{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		ExpiresIn:    tokens.ExpiresIn,
		TokenType:    tokens.TokenType,
	}, nil
}
