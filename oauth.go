package goauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// BaseOAuthProvider provides common OAuth functionality.
type BaseOAuthProvider struct {
	name         string
	clientID     string
	clientSecret string
	authURL      string
	tokenURL     string
	userURL      string
	scopes       []string
	userParser   func(data []byte) (*OAuthUser, error)
}

func (p *BaseOAuthProvider) Name() string {
	return p.name
}

func (p *BaseOAuthProvider) AuthURL(state, redirectURL string) string {
	params := url.Values{}
	params.Set("client_id", p.clientID)
	params.Set("redirect_uri", redirectURL)
	params.Set("response_type", "code")
	params.Set("state", state)
	if len(p.scopes) > 0 {
		params.Set("scope", joinScopes(p.scopes))
	}
	return p.authURL + "?" + params.Encode()
}

func (p *BaseOAuthProvider) ExchangeCode(ctx context.Context, code, redirectURL string) (*OAuthTokens, error) {
	data := url.Values{}
	data.Set("client_id", p.clientID)
	data.Set("client_secret", p.clientSecret)
	data.Set("code", code)
	data.Set("grant_type", "authorization_code")
	data.Set("redirect_uri", redirectURL)

	req, err := http.NewRequestWithContext(ctx, "POST", p.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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
		return nil, fmt.Errorf("oauth token exchange failed: %s", string(body))
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

func (p *BaseOAuthProvider) GetUser(ctx context.Context, accessToken string) (*OAuthUser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.userURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
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
		return nil, fmt.Errorf("oauth user fetch failed: %s", string(body))
	}

	return p.userParser(body)
}

func joinScopes(scopes []string) string {
	result := ""
	for i, s := range scopes {
		if i > 0 {
			result += " "
		}
		result += s
	}
	return result
}

// ==================== GOOGLE ====================

// GoogleProvider implements OAuth for Google.
type GoogleProvider struct {
	BaseOAuthProvider
}

// NewGoogleProvider creates a Google OAuth provider.
func NewGoogleProvider(clientID, clientSecret string) *GoogleProvider {
	return &GoogleProvider{
		BaseOAuthProvider{
			name:         "google",
			clientID:     clientID,
			clientSecret: clientSecret,
			authURL:      "https://accounts.google.com/o/oauth2/v2/auth",
			tokenURL:     "https://oauth2.googleapis.com/token",
			userURL:      "https://www.googleapis.com/oauth2/v2/userinfo",
			scopes:       []string{"email", "profile"},
			userParser:   parseGoogleUser,
		},
	}
}

func parseGoogleUser(data []byte) (*OAuthUser, error) {
	var u struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}
	if err := json.Unmarshal(data, &u); err != nil {
		return nil, err
	}
	
	var raw map[string]any
	json.Unmarshal(data, &raw)

	return &OAuthUser{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.VerifiedEmail,
		Name:          u.Name,
		Avatar:        u.Picture,
		Raw:           raw,
	}, nil
}

// ==================== DISCORD ====================

// DiscordProvider implements OAuth for Discord.
type DiscordProvider struct {
	BaseOAuthProvider
}

// NewDiscordProvider creates a Discord OAuth provider.
func NewDiscordProvider(clientID, clientSecret string) *DiscordProvider {
	return &DiscordProvider{
		BaseOAuthProvider{
			name:         "discord",
			clientID:     clientID,
			clientSecret: clientSecret,
			authURL:      "https://discord.com/api/oauth2/authorize",
			tokenURL:     "https://discord.com/api/oauth2/token",
			userURL:      "https://discord.com/api/users/@me",
			scopes:       []string{"identify", "email"},
			userParser:   parseDiscordUser,
		},
	}
}

func parseDiscordUser(data []byte) (*OAuthUser, error) {
	var u struct {
		ID       string `json:"id"`
		Email    string `json:"email"`
		Verified bool   `json:"verified"`
		Username string `json:"username"`
		Avatar   string `json:"avatar"`
	}
	if err := json.Unmarshal(data, &u); err != nil {
		return nil, err
	}

	avatar := ""
	if u.Avatar != "" {
		avatar = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", u.ID, u.Avatar)
	}

	var raw map[string]any
	json.Unmarshal(data, &raw)

	return &OAuthUser{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.Verified,
		Name:          u.Username,
		Avatar:        avatar,
		Raw:           raw,
	}, nil
}

// ==================== GITHUB ====================

// GitHubProvider implements OAuth for GitHub.
type GitHubProvider struct {
	BaseOAuthProvider
}

// NewGitHubProvider creates a GitHub OAuth provider.
func NewGitHubProvider(clientID, clientSecret string) *GitHubProvider {
	return &GitHubProvider{
		BaseOAuthProvider{
			name:         "github",
			clientID:     clientID,
			clientSecret: clientSecret,
			authURL:      "https://github.com/login/oauth/authorize",
			tokenURL:     "https://github.com/login/oauth/access_token",
			userURL:      "https://api.github.com/user",
			scopes:       []string{"user:email"},
			userParser:   parseGitHubUser,
		},
	}
}

func parseGitHubUser(data []byte) (*OAuthUser, error) {
	var u struct {
		ID        int    `json:"id"`
		Email     string `json:"email"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.Unmarshal(data, &u); err != nil {
		return nil, err
	}

	var raw map[string]any
	json.Unmarshal(data, &raw)

	name := u.Name
	if name == "" {
		name = u.Login
	}

	return &OAuthUser{
		ID:            fmt.Sprintf("%d", u.ID),
		Email:         u.Email,
		EmailVerified: u.Email != "", // GitHub verifies emails
		Name:          name,
		Avatar:        u.AvatarURL,
		Raw:           raw,
	}, nil
}

// ==================== MICROSOFT ====================

// MicrosoftProvider implements OAuth for Microsoft.
type MicrosoftProvider struct {
	BaseOAuthProvider
}

// NewMicrosoftProvider creates a Microsoft OAuth provider.
func NewMicrosoftProvider(clientID, clientSecret string) *MicrosoftProvider {
	return &MicrosoftProvider{
		BaseOAuthProvider{
			name:         "microsoft",
			clientID:     clientID,
			clientSecret: clientSecret,
			authURL:      "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			tokenURL:     "https://login.microsoftonline.com/common/oauth2/v2.0/token",
			userURL:      "https://graph.microsoft.com/v1.0/me",
			scopes:       []string{"openid", "email", "profile"},
			userParser:   parseMicrosoftUser,
		},
	}
}

func parseMicrosoftUser(data []byte) (*OAuthUser, error) {
	var u struct {
		ID    string `json:"id"`
		Email string `json:"mail"`
		UPN   string `json:"userPrincipalName"`
		Name  string `json:"displayName"`
	}
	if err := json.Unmarshal(data, &u); err != nil {
		return nil, err
	}

	email := u.Email
	if email == "" {
		email = u.UPN
	}

	var raw map[string]any
	json.Unmarshal(data, &raw)

	return &OAuthUser{
		ID:            u.ID,
		Email:         email,
		EmailVerified: true, // Microsoft verifies emails
		Name:          u.Name,
		Raw:           raw,
	}, nil
}

// ==================== TWITCH ====================

// TwitchProvider implements OAuth for Twitch.
type TwitchProvider struct {
	BaseOAuthProvider
}

// NewTwitchProvider creates a Twitch OAuth provider.
func NewTwitchProvider(clientID, clientSecret string) *TwitchProvider {
	return &TwitchProvider{
		BaseOAuthProvider{
			name:         "twitch",
			clientID:     clientID,
			clientSecret: clientSecret,
			authURL:      "https://id.twitch.tv/oauth2/authorize",
			tokenURL:     "https://id.twitch.tv/oauth2/token",
			userURL:      "https://api.twitch.tv/helix/users",
			scopes:       []string{"user:read:email"},
			userParser:   parseTwitchUser,
		},
	}
}

func (p *TwitchProvider) GetUser(ctx context.Context, accessToken string) (*OAuthUser, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.userURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Client-Id", p.clientID)

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

	return parseTwitchUser(body)
}

func parseTwitchUser(data []byte) (*OAuthUser, error) {
	var resp struct {
		Data []struct {
			ID          string `json:"id"`
			Email       string `json:"email"`
			Login       string `json:"login"`
			DisplayName string `json:"display_name"`
			ProfileImg  string `json:"profile_image_url"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	
	if len(resp.Data) == 0 {
		return nil, errors.New("no user data returned")
	}

	u := resp.Data[0]
	var raw map[string]any
	json.Unmarshal(data, &raw)

	return &OAuthUser{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.Email != "",
		Name:          u.DisplayName,
		Avatar:        u.ProfileImg,
		Raw:           raw,
	}, nil
}

// ==================== CUSTOM PROVIDER ====================

// CustomOAuthProvider allows creating custom OAuth providers.
type CustomOAuthProvider struct {
	BaseOAuthProvider
}

// NewCustomProvider creates a custom OAuth provider.
func NewCustomProvider(name, clientID, clientSecret, authURL, tokenURL, userURL string, scopes []string, userParser func([]byte) (*OAuthUser, error)) *CustomOAuthProvider {
	if userParser == nil {
		userParser = parseGenericUser
	}
	return &CustomOAuthProvider{
		BaseOAuthProvider{
			name:         name,
			clientID:     clientID,
			clientSecret: clientSecret,
			authURL:      authURL,
			tokenURL:     tokenURL,
			userURL:      userURL,
			scopes:       scopes,
			userParser:   userParser,
		},
	}
}

func parseGenericUser(data []byte) (*OAuthUser, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	getString := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := raw[k].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}

	getBool := func(keys ...string) bool {
		for _, k := range keys {
			if v, ok := raw[k].(bool); ok {
				return v
			}
		}
		return false
	}

	return &OAuthUser{
		ID:            getString("id", "sub", "user_id"),
		Email:         getString("email", "mail"),
		EmailVerified: getBool("email_verified", "verified_email", "verified"),
		Name:          getString("name", "displayName", "username", "login"),
		Avatar:        getString("avatar", "picture", "avatar_url", "profile_image_url"),
		Raw:           raw,
	}, nil
}
