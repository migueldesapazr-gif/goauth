package goauth

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/migueldesapazr-gif/goauth/mailers/smtp"
)

// ==================== SECRETS FROM ENV ====================

// SecretsFromEnv loads secrets from environment variables.
// Expected variables:
//   - GOAUTH_JWT_SECRET (base64 encoded, 32 bytes)
//   - GOAUTH_ENCRYPTION_KEY (base64 encoded, 32 bytes)
//   - GOAUTH_PEPPER (base64 encoded, 32 bytes)
func SecretsFromEnv() (Secrets, error) {
	jwt, err := getEnvSecret("GOAUTH_JWT_SECRET")
	if err != nil {
		return Secrets{}, fmt.Errorf("GOAUTH_JWT_SECRET: %w", err)
	}

	enc, err := getEnvSecret("GOAUTH_ENCRYPTION_KEY")
	if err != nil {
		return Secrets{}, fmt.Errorf("GOAUTH_ENCRYPTION_KEY: %w", err)
	}

	pepper, err := getEnvSecret("GOAUTH_PEPPER")
	if err != nil {
		return Secrets{}, fmt.Errorf("GOAUTH_PEPPER: %w", err)
	}

	return Secrets{
		JWTSecret:     jwt,
		EncryptionKey: enc,
		Pepper:        pepper,
	}, nil
}

// SecretsFromEnvWithPrefix loads secrets with a custom prefix.
// Example: SecretsFromEnvWithPrefix("MYAPP") reads MYAPP_JWT_SECRET, etc.
func SecretsFromEnvWithPrefix(prefix string) (Secrets, error) {
	jwt, err := getEnvSecret(prefix + "_JWT_SECRET")
	if err != nil {
		return Secrets{}, fmt.Errorf("%s_JWT_SECRET: %w", prefix, err)
	}

	enc, err := getEnvSecret(prefix + "_ENCRYPTION_KEY")
	if err != nil {
		return Secrets{}, fmt.Errorf("%s_ENCRYPTION_KEY: %w", prefix, err)
	}

	pepper, err := getEnvSecret(prefix + "_PEPPER")
	if err != nil {
		return Secrets{}, fmt.Errorf("%s_PEPPER: %w", prefix, err)
	}

	return Secrets{
		JWTSecret:     jwt,
		EncryptionKey: enc,
		Pepper:        pepper,
	}, nil
}

// SecretsFromEnvFile loads secrets from a .env style file.
func SecretsFromEnvFile(path string) (Secrets, error) {
	values, err := parseEnvFile(path)
	if err != nil {
		return Secrets{}, err
	}
	return secretsFromKeyMap(values, map[string]string{
		"jwt":        "GOAUTH_JWT_SECRET",
		"encryption": "GOAUTH_ENCRYPTION_KEY",
		"pepper":     "GOAUTH_PEPPER",
	})
}

// SecretsFromEnvFileWithPrefix loads secrets from a .env file with a custom prefix.
func SecretsFromEnvFileWithPrefix(path, prefix string) (Secrets, error) {
	values, err := parseEnvFile(path)
	if err != nil {
		return Secrets{}, err
	}
	return secretsFromKeyMap(values, map[string]string{
		"jwt":        prefix + "_JWT_SECRET",
		"encryption": prefix + "_ENCRYPTION_KEY",
		"pepper":     prefix + "_PEPPER",
	})
}

// SecretsFromFiles loads secrets from three plain files (one per secret).
func SecretsFromFiles(jwtPath, encPath, pepperPath string) (Secrets, error) {
	jwt, err := readSecretFile(jwtPath)
	if err != nil {
		return Secrets{}, fmt.Errorf("jwt secret: %w", err)
	}
	enc, err := readSecretFile(encPath)
	if err != nil {
		return Secrets{}, fmt.Errorf("encryption key: %w", err)
	}
	pepper, err := readSecretFile(pepperPath)
	if err != nil {
		return Secrets{}, fmt.Errorf("pepper: %w", err)
	}
	return Secrets{
		JWTSecret:     jwt,
		EncryptionKey: enc,
		Pepper:        pepper,
	}, nil
}

// SecretsFromRawFile loads secrets from a single raw file with three lines.
// Line 1: JWT secret, Line 2: Encryption key, Line 3: Pepper.
func SecretsFromRawFile(path string) (Secrets, error) {
	values, err := readNonEmptyLines(path)
	if err != nil {
		return Secrets{}, err
	}
	if len(values) < 3 {
		return Secrets{}, errors.New("raw secrets file must have at least 3 lines")
	}
	jwt, err := decodeSecret(values[0])
	if err != nil {
		return Secrets{}, fmt.Errorf("jwt secret: %w", err)
	}
	enc, err := decodeSecret(values[1])
	if err != nil {
		return Secrets{}, fmt.Errorf("encryption key: %w", err)
	}
	pepper, err := decodeSecret(values[2])
	if err != nil {
		return Secrets{}, fmt.Errorf("pepper: %w", err)
	}
	return Secrets{
		JWTSecret:     jwt,
		EncryptionKey: enc,
		Pepper:        pepper,
	}, nil
}

// SecretsFromJSONFile loads secrets from a JSON file.
func SecretsFromJSONFile(path string, keys map[string]string) (Secrets, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return Secrets{}, err
	}
	return SecretsFromJSON(payload, keys)
}

// SecretsFromJSON loads secrets from a JSON payload.
func SecretsFromJSON(payload []byte, keys map[string]string) (Secrets, error) {
	var values map[string]string
	if err := json.Unmarshal(payload, &values); err != nil {
		return Secrets{}, err
	}
	return secretsFromKeyMap(values, keys)
}

// MustSecretsFromEnv loads secrets from environment or panics.
func MustSecretsFromEnv() Secrets {
	s, err := SecretsFromEnv()
	if err != nil {
		panic("goauth: " + err.Error())
	}
	return s
}

func getEnvSecret(key string) ([]byte, error) {
	val := os.Getenv(key)
	if val == "" {
		return nil, errors.New("not set")
	}

	// Try base64 first
	decoded, err := base64.StdEncoding.DecodeString(val)
	if err == nil && len(decoded) == 32 {
		return decoded, nil
	}

	// Try raw hex
	if len(val) == 64 {
		decoded, err = hexDecode(val)
		if err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}

	return nil, errors.New("must be 32 bytes base64-encoded")
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errors.New("odd length hex string")
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var v byte
		for j := 0; j < 2; j++ {
			c := s[i+j]
			switch {
			case c >= '0' && c <= '9':
				v = v*16 + c - '0'
			case c >= 'a' && c <= 'f':
				v = v*16 + c - 'a' + 10
			case c >= 'A' && c <= 'F':
				v = v*16 + c - 'A' + 10
			default:
				return nil, errors.New("invalid hex character")
			}
		}
		b[i/2] = v
	}
	return b, nil
}

// ==================== HASHICORP VAULT ====================

// VaultConfig holds HashiCorp Vault configuration.
type VaultConfig struct {
	// Address is the Vault server address (e.g., https://vault.example.com)
	Address string
	// Token is the Vault authentication token
	Token string
	// Path is the secret path (e.g., secret/data/myapp)
	Path string
	// Keys maps secret keys to our expected keys (optional)
	// Default: jwt_secret, encryption_key, pepper
	Keys map[string]string
}

// SecretsFromVault loads secrets from HashiCorp Vault.
func SecretsFromVault(ctx context.Context, cfg VaultConfig) (Secrets, error) {
	if cfg.Address == "" || cfg.Token == "" || cfg.Path == "" {
		return Secrets{}, errors.New("vault config incomplete")
	}

	// Default key mappings
	jwtKey := "jwt_secret"
	encKey := "encryption_key"
	pepperKey := "pepper"
	if cfg.Keys != nil {
		if v, ok := cfg.Keys["jwt"]; ok {
			jwtKey = v
		}
		if v, ok := cfg.Keys["encryption"]; ok {
			encKey = v
		}
		if v, ok := cfg.Keys["pepper"]; ok {
			pepperKey = v
		}
	}

	// Fetch from Vault
	url := strings.TrimRight(cfg.Address, "/") + "/v1/" + cfg.Path
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return Secrets{}, err
	}
	req.Header.Set("X-Vault-Token", cfg.Token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return Secrets{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Secrets{}, fmt.Errorf("vault returned status %d", resp.StatusCode)
	}

	var vaultResp struct {
		Data struct {
			Data map[string]string `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&vaultResp); err != nil {
		return Secrets{}, err
	}

	data := vaultResp.Data.Data

	jwt, err := decodeSecret(data[jwtKey])
	if err != nil {
		return Secrets{}, fmt.Errorf("jwt_secret: %w", err)
	}
	enc, err := decodeSecret(data[encKey])
	if err != nil {
		return Secrets{}, fmt.Errorf("encryption_key: %w", err)
	}
	pepper, err := decodeSecret(data[pepperKey])
	if err != nil {
		return Secrets{}, fmt.Errorf("pepper: %w", err)
	}

	return Secrets{
		JWTSecret:     jwt,
		EncryptionKey: enc,
		Pepper:        pepper,
	}, nil
}

// SecretsFromVaultEnv loads Vault config from environment and fetches secrets.
// Uses: VAULT_ADDR, VAULT_TOKEN, VAULT_SECRET_PATH
func SecretsFromVaultEnv(ctx context.Context) (Secrets, error) {
	cfg := VaultConfig{
		Address: os.Getenv("VAULT_ADDR"),
		Token:   os.Getenv("VAULT_TOKEN"),
		Path:    os.Getenv("VAULT_SECRET_PATH"),
	}
	if cfg.Path == "" {
		cfg.Path = os.Getenv("VAULT_PATH")
	}
	return SecretsFromVault(ctx, cfg)
}

func decodeSecret(val string) ([]byte, error) {
	if val == "" {
		return nil, errors.New("not found")
	}

	decoded, err := base64.StdEncoding.DecodeString(val)
	if err == nil && len(decoded) == 32 {
		return decoded, nil
	}

	if len(val) == 64 {
		decoded, err = hexDecode(val)
		if err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}

	return nil, errors.New("must be 32 bytes (base64 or hex encoded)")
}

func readSecretFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return decodeSecret(strings.TrimSpace(string(raw)))
}

func readNonEmptyLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func parseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	values := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		val = strings.Trim(val, `"'`)
		if key != "" {
			values[key] = val
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func secretsFromKeyMap(values map[string]string, keys map[string]string) (Secrets, error) {
	jwtKey := "jwt_secret"
	encKey := "encryption_key"
	pepperKey := "pepper"
	if keys != nil {
		if v, ok := keys["jwt"]; ok {
			jwtKey = v
		}
		if v, ok := keys["encryption"]; ok {
			encKey = v
		}
		if v, ok := keys["pepper"]; ok {
			pepperKey = v
		}
	}
	jwt, err := decodeSecret(values[jwtKey])
	if err != nil {
		return Secrets{}, fmt.Errorf("%s: %w", jwtKey, err)
	}
	enc, err := decodeSecret(values[encKey])
	if err != nil {
		return Secrets{}, fmt.Errorf("%s: %w", encKey, err)
	}
	pepper, err := decodeSecret(values[pepperKey])
	if err != nil {
		return Secrets{}, fmt.Errorf("%s: %w", pepperKey, err)
	}
	return Secrets{
		JWTSecret:     jwt,
		EncryptionKey: enc,
		Pepper:        pepper,
	}, nil
}

// ==================== AWS SECRETS MANAGER ====================

// AWSSecretsConfig holds AWS Secrets Manager configuration.
type AWSSecretsConfig struct {
	// SecretName is the name of the secret in AWS
	SecretName string
	// Region is the AWS region
	Region string
	// Keys maps secret keys (optional)
	Keys map[string]string
}

// ==================== OPTION HELPERS ====================

// WithSecretsFromEnv loads secrets from environment variables.
func WithSecretsFromEnv() Option {
	return func(s *AuthService) error {
		secrets, err := SecretsFromEnv()
		if err != nil {
			return err
		}
		return WithSecrets(secrets)(s)
	}
}

// WithSecretsFromEnvFile loads secrets from a .env file.
func WithSecretsFromEnvFile(path string) Option {
	return func(s *AuthService) error {
		secrets, err := SecretsFromEnvFile(path)
		if err != nil {
			return err
		}
		return WithSecrets(secrets)(s)
	}
}

// WithSecretsFromEnvFileWithPrefix loads secrets from a .env file with a custom prefix.
func WithSecretsFromEnvFileWithPrefix(path, prefix string) Option {
	return func(s *AuthService) error {
		secrets, err := SecretsFromEnvFileWithPrefix(path, prefix)
		if err != nil {
			return err
		}
		return WithSecrets(secrets)(s)
	}
}

// WithSecretsFromFiles loads secrets from three files (one per secret).
func WithSecretsFromFiles(jwtPath, encPath, pepperPath string) Option {
	return func(s *AuthService) error {
		secrets, err := SecretsFromFiles(jwtPath, encPath, pepperPath)
		if err != nil {
			return err
		}
		return WithSecrets(secrets)(s)
	}
}

// WithSecretsFromRawFile loads secrets from a raw file with three lines.
func WithSecretsFromRawFile(path string) Option {
	return func(s *AuthService) error {
		secrets, err := SecretsFromRawFile(path)
		if err != nil {
			return err
		}
		return WithSecrets(secrets)(s)
	}
}

// WithSecretsFromJSONFile loads secrets from a JSON file.
func WithSecretsFromJSONFile(path string, keys map[string]string) Option {
	return func(s *AuthService) error {
		secrets, err := SecretsFromJSONFile(path, keys)
		if err != nil {
			return err
		}
		return WithSecrets(secrets)(s)
	}
}

// WithSecretsFromVault loads secrets from HashiCorp Vault.
func WithSecretsFromVault(cfg VaultConfig) Option {
	return func(s *AuthService) error {
		secrets, err := SecretsFromVault(context.Background(), cfg)
		if err != nil {
			return err
		}
		return WithSecrets(secrets)(s)
	}
}

// WithSecretsFromVaultEnv loads Vault config from env and fetches secrets.
func WithSecretsFromVaultEnv() Option {
	return func(s *AuthService) error {
		secrets, err := SecretsFromVaultEnv(context.Background())
		if err != nil {
			return err
		}
		return WithSecrets(secrets)(s)
	}
}

// ==================== QUICK CONFIG FROM ENV ====================

// ConfigFromEnv creates common configuration from environment variables.
// See docs/env.md for the full list.
func ConfigFromEnv() []Option {
	var opts []Option

	if name := os.Getenv("GOAUTH_APP_NAME"); name != "" {
		opts = append(opts, WithAppName(name))
	}
	if url := os.Getenv("GOAUTH_APP_URL"); url != "" {
		opts = append(opts, WithAppURL(url))
	}
	if path := strings.TrimSpace(os.Getenv("GOAUTH_CALLBACK_PATH")); path != "" {
		opts = append(opts, WithCallbackPath(path))
	}
	if mode := strings.TrimSpace(os.Getenv("GOAUTH_SECURITY_MODE")); mode != "" {
		opts = append(opts, WithSecurityMode(SecurityMode(mode)))
	}

	if v, ok := envBool("GOAUTH_EMAIL_PASSWORD_ENABLED"); ok {
		opts = append(opts, WithEmailPassword(v))
	}
	if v, ok := envBool("GOAUTH_EMAIL_VERIFICATION_REQUIRED"); ok {
		opts = append(opts, WithEmailVerification(v))
	}
	if v, ok := envBool("GOAUTH_EMAIL_DOMAIN_CHECK"); ok {
		opts = append(opts, WithEmailDomainCheck(v))
	}
	blockDisposableSet := false
	if v, ok := envBool("GOAUTH_BLOCK_DISPOSABLE_EMAILS"); ok {
		opts = append(opts, WithBlockDisposableEmails(v))
		blockDisposableSet = true
	}
	if domains, ok := envStrings("GOAUTH_DISPOSABLE_EMAIL_DOMAINS"); ok {
		if !blockDisposableSet {
			opts = append(opts, WithBlockDisposableEmails(true))
		}
		opts = append(opts, WithDisposableEmailDomains(domains))
	}
	if v, ok := envBool("GOAUTH_TOTP_ENABLED"); ok {
		opts = append(opts, WithTOTP(v))
	}
	if v, ok := envBool("GOAUTH_PASSWORD_RESET_ENABLED"); ok {
		opts = append(opts, WithPasswordReset(v))
	}
	if v, ok := envBool("GOAUTH_MAGIC_LINKS_ENABLED"); ok && v {
		opts = append(opts, WithMagicLinks())
	}

	if v, ok := envBool("GOAUTH_USERNAME_ENABLED"); ok {
		opts = append(opts, WithUsername(v))
	}
	if v, ok := envBool("GOAUTH_USERNAME_REQUIRED"); ok {
		opts = append(opts, WithUsernameRequired(v))
	}
	usernameMin := DefaultConfig().MinUsernameLength
	usernameMax := DefaultConfig().MaxUsernameLength
	usernamePolicySet := false
	if v, ok := envInt("GOAUTH_USERNAME_MIN"); ok {
		usernameMin = v
		usernamePolicySet = true
	}
	if v, ok := envInt("GOAUTH_USERNAME_MAX"); ok {
		usernameMax = v
		usernamePolicySet = true
	}
	if usernamePolicySet {
		opts = append(opts, WithUsernamePolicy(usernameMin, usernameMax))
	}
	if pattern := strings.TrimSpace(os.Getenv("GOAUTH_USERNAME_PATTERN")); pattern != "" {
		opts = append(opts, WithUsernamePattern(pattern))
	}
	if reserved, ok := envStrings("GOAUTH_USERNAME_RESERVED"); ok {
		opts = append(opts, WithUsernameReserved(reserved))
	}
	if v, ok := envBool("GOAUTH_USERNAME_ALLOW_NUMERIC_ONLY"); ok {
		opts = append(opts, WithUsernameAllowNumericOnly(v))
	}

	if v, ok := envInt("GOAUTH_TOTP_DIGITS"); ok {
		opts = append(opts, WithTOTPDigits(v))
	}
	if name := strings.TrimSpace(os.Getenv("GOAUTH_TOTP_ACCOUNT_NAME")); name != "" {
		opts = append(opts, WithTOTPAccountName(name))
	}
	if v, ok := envBool("GOAUTH_TOTP_USE_USERNAME"); ok {
		opts = append(opts, WithTOTPUseUsername(v))
	}
	if v, ok := envBool("GOAUTH_TOTP_QR_ENABLED"); ok {
		opts = append(opts, WithTOTPQRCode(v))
	}
	if v, ok := envInt("GOAUTH_TOTP_QR_SIZE"); ok {
		opts = append(opts, WithTOTPQRCodeSize(v))
	}
	if v, ok := envInt("GOAUTH_BACKUP_CODE_LENGTH"); ok {
		opts = append(opts, WithBackupCodeLength(v))
	}
	if v, ok := envBool("GOAUTH_BACKUP_CODE_DIGITS_ONLY"); ok {
		opts = append(opts, WithBackupCodeDigitsOnly(v))
	}
	if v, ok := envInt("GOAUTH_BACKUP_CODE_COUNT"); ok {
		opts = append(opts, WithBackupCodeCount(v))
	}

	passwordMin := DefaultConfig().MinPasswordLength
	passwordComplex := DefaultConfig().RequirePasswordComplexity
	passwordHistory := DefaultConfig().PasswordHistorySize
	passwordPolicySet := false
	if v, ok := envInt("GOAUTH_MIN_PASSWORD_LENGTH"); ok {
		passwordMin = v
		passwordPolicySet = true
	}
	if v, ok := envBool("GOAUTH_PASSWORD_COMPLEXITY"); ok {
		passwordComplex = v
		passwordPolicySet = true
	}
	if v, ok := envInt("GOAUTH_PASSWORD_HISTORY"); ok {
		passwordHistory = v
		passwordPolicySet = true
	}
	if passwordPolicySet {
		opts = append(opts, WithPasswordPolicy(passwordMin, passwordComplex, passwordHistory))
	}

	lockoutAttempts := DefaultConfig().MaxLoginAttempts
	lockoutDuration := DefaultConfig().LockoutDuration
	lockoutSet := false
	if v, ok := envInt("GOAUTH_MAX_LOGIN_ATTEMPTS"); ok {
		lockoutAttempts = v
		lockoutSet = true
	}
	if v, ok := envDuration("GOAUTH_LOCKOUT_DURATION"); ok {
		lockoutDuration = v
		lockoutSet = true
	}
	if lockoutSet {
		opts = append(opts, WithLockout(lockoutAttempts, lockoutDuration))
	}

	if v, ok := envBool("GOAUTH_ROTATE_REFRESH_TOKENS"); ok {
		opts = append(opts, WithRotateRefreshTokens(v))
	}
	if v, ok := envBool("GOAUTH_REQUIRE_VERIFIED_EMAIL_FOR_AUTH"); ok {
		opts = append(opts, WithRequireVerifiedEmailForAuth(v))
	}
	if v, ok := envBool("GOAUTH_REQUIRE_2FA_FOR_AUTH"); ok {
		opts = append(opts, WithRequire2FAForAuth(v))
	}
	if v, ok := envBool("GOAUTH_REQUIRE_2FA_FOR_OAUTH"); ok {
		opts = append(opts, WithRequire2FAForOAuth(v))
	}
	if v, ok := envBool("GOAUTH_REQUIRE_2FA_FOR_MAGIC_LINK"); ok {
		opts = append(opts, WithRequire2FAForMagicLink(v))
	}
	if v, ok := envBool("GOAUTH_REQUIRE_2FA_FOR_SDK"); ok {
		opts = append(opts, WithRequire2FAForSDK(v))
	}
	if v, ok := envBool("GOAUTH_REQUIRE_2FA_FOR_EMAIL_CHANGE"); ok {
		opts = append(opts, WithRequire2FAForEmailChange(v))
	}

	if v, ok := envInt("GOAUTH_PASSKEYS_MAX_PER_USER"); ok {
		opts = append(opts, WithMaxPasskeysPerUser(v))
	}
	if roles, ok := envStrings("GOAUTH_PASSKEYS_ALLOWED_ROLES"); ok {
		parsed := make([]Role, 0, len(roles))
		for _, role := range roles {
			parsed = append(parsed, Role(strings.ToLower(role)))
		}
		opts = append(opts, WithAllowPasskeysForRoles(parsed...))
	}

	oauthLinkAllow := DefaultConfig().AllowOAuthEmailLinking
	oauthLinkUnverified := DefaultConfig().AllowUnverifiedOAuthEmailLinking
	oauthLinkSet := false
	if v, ok := envBool("GOAUTH_ALLOW_OAUTH_EMAIL_LINKING"); ok {
		oauthLinkAllow = v
		oauthLinkSet = true
	}
	if v, ok := envBool("GOAUTH_ALLOW_UNVERIFIED_OAUTH_EMAIL_LINKING"); ok {
		oauthLinkUnverified = v
		oauthLinkSet = true
	}
	if oauthLinkSet {
		opts = append(opts, WithOAuthEmailLinking(oauthLinkAllow, oauthLinkUnverified))
	}

	if v, ok := envBool("GOAUTH_TRUST_PROXY_HEADERS"); ok {
		opts = append(opts, WithTrustProxyHeaders(v))
	}
	if proxies, ok := envStrings("GOAUTH_TRUSTED_PROXIES"); ok {
		opts = append(opts, WithTrustedProxies(proxies))
	}

	rateCfg := DefaultConfig().RateLimits
	rateSet := false
	if v, ok := envInt("GOAUTH_RATE_LOGIN_LIMIT"); ok {
		rateCfg.LoginLimit = v
		rateSet = true
	}
	if v, ok := envDuration("GOAUTH_RATE_LOGIN_WINDOW"); ok {
		rateCfg.LoginWindow = v
		rateSet = true
	}
	if v, ok := envInt("GOAUTH_RATE_2FA_LIMIT"); ok {
		rateCfg.TwoFALimit = v
		rateSet = true
	}
	if v, ok := envDuration("GOAUTH_RATE_2FA_WINDOW"); ok {
		rateCfg.TwoFAWindow = v
		rateSet = true
	}
	if v, ok := envInt("GOAUTH_RATE_REGISTER_LIMIT"); ok {
		rateCfg.RegisterLimit = v
		rateSet = true
	}
	if v, ok := envDuration("GOAUTH_RATE_REGISTER_WINDOW"); ok {
		rateCfg.RegisterWindow = v
		rateSet = true
	}
	if v, ok := envInt("GOAUTH_RATE_PASSWORD_RESET_LIMIT"); ok {
		rateCfg.PasswordResetLimit = v
		rateSet = true
	}
	if v, ok := envDuration("GOAUTH_RATE_PASSWORD_RESET_WINDOW"); ok {
		rateCfg.PasswordResetWindow = v
		rateSet = true
	}
	if v, ok := envInt("GOAUTH_RATE_MAGIC_LINK_LIMIT"); ok {
		rateCfg.MagicLinkLimit = v
		rateSet = true
	}
	if v, ok := envDuration("GOAUTH_RATE_MAGIC_LINK_WINDOW"); ok {
		rateCfg.MagicLinkWindow = v
		rateSet = true
	}
	if rateSet {
		opts = append(opts, WithRateLimits(rateCfg))
	}

	ipBlockCfg := DefaultConfig().IPBlock
	ipBlockSet := false
	if v, ok := envBool("GOAUTH_IP_BLOCK_ENABLED"); ok {
		ipBlockCfg.Enabled = v
		ipBlockSet = true
	}
	if v, ok := envInt("GOAUTH_IP_BLOCK_FAILURE_THRESHOLD"); ok {
		ipBlockCfg.FailureThreshold = v
		ipBlockSet = true
	}
	if v, ok := envDuration("GOAUTH_IP_BLOCK_FAILURE_WINDOW"); ok {
		ipBlockCfg.FailureWindow = v
		ipBlockSet = true
	}
	if v, ok := envDuration("GOAUTH_IP_BLOCK_DURATION"); ok {
		ipBlockCfg.BlockDuration = v
		ipBlockSet = true
	}
	if ipBlockSet {
		opts = append(opts, WithIPBlock(ipBlockCfg))
	}

	ipPrivacyCfg := DefaultConfig().IPPrivacy
	ipPrivacySet := false
	if v, ok := envBool("GOAUTH_IP_STORE"); ok {
		ipPrivacyCfg.StoreIP = v
		ipPrivacySet = true
	}
	if v, ok := envBool("GOAUTH_IP_ENCRYPT"); ok {
		ipPrivacyCfg.EncryptIP = v
		ipPrivacySet = true
	}
	if v, ok := envBool("GOAUTH_IP_HASH_IN_LOGS"); ok {
		ipPrivacyCfg.HashIPInLogs = v
		ipPrivacySet = true
	}
	if v, ok := envInt("GOAUTH_IP_RETENTION_DAYS"); ok {
		ipPrivacyCfg.IPRetentionDays = v
		ipPrivacySet = true
	}
	if ipPrivacySet {
		opts = append(opts, WithIPPrivacy(ipPrivacyCfg))
	}

	if v, ok := envDuration("GOAUTH_AUDIT_RETENTION"); ok {
		opts = append(opts, WithAuditRetention(v))
	}
	if v, ok := envDuration("GOAUTH_UNVERIFIED_ACCOUNT_TTL"); ok {
		opts = append(opts, WithUnverifiedAccountTTL(v))
	}
	if v, ok := envBool("GOAUTH_USER_AGENT_HASH"); ok {
		opts = append(opts, WithUserAgentHashInLogs(v))
	}
	if v, ok := envBool("GOAUTH_NOTIFY_PASSWORD_CHANGE"); ok {
		opts = append(opts, WithNotifyOnPasswordChange(v))
	}
	if v, ok := envBool("GOAUTH_NOTIFY_EMAIL_CHANGE"); ok {
		opts = append(opts, WithNotifyOnEmailChange(v))
	}
	if v, ok := envDuration("GOAUTH_EMAIL_CHANGE_TTL"); ok {
		opts = append(opts, WithEmailChangeTTL(v))
	}

	if v, ok := envBool("GOAUTH_HIBP_ENABLED"); ok && v {
		opts = append(opts, WithHIBP())
	}
	if url := os.Getenv("GOAUTH_HIBP_API_URL"); url != "" {
		opts = append(opts, WithHIBPAPIURL(url))
	}

	// OAuth providers
	if id, secret := os.Getenv("GOAUTH_GOOGLE_CLIENT_ID"), os.Getenv("GOAUTH_GOOGLE_CLIENT_SECRET"); id != "" && secret != "" {
		opts = append(opts, WithGoogle(id, secret))
	}
	if id, secret := os.Getenv("GOAUTH_DISCORD_CLIENT_ID"), os.Getenv("GOAUTH_DISCORD_CLIENT_SECRET"); id != "" && secret != "" {
		opts = append(opts, WithDiscord(id, secret))
	}
	if id, secret := os.Getenv("GOAUTH_GITHUB_CLIENT_ID"), os.Getenv("GOAUTH_GITHUB_CLIENT_SECRET"); id != "" && secret != "" {
		opts = append(opts, WithGitHub(id, secret))
	}
	if id, secret := os.Getenv("GOAUTH_MICROSOFT_CLIENT_ID"), os.Getenv("GOAUTH_MICROSOFT_CLIENT_SECRET"); id != "" && secret != "" {
		opts = append(opts, WithMicrosoft(id, secret))
	}

	// CAPTCHA
	captchaProvider := strings.ToLower(strings.TrimSpace(os.Getenv("GOAUTH_CAPTCHA_PROVIDER")))
	switch captchaProvider {
	case "turnstile":
		if secret := os.Getenv("GOAUTH_TURNSTILE_SECRET"); secret != "" {
			opts = append(opts, WithTurnstile(secret))
		}
	case "recaptcha_v3":
		if secret := os.Getenv("GOAUTH_RECAPTCHA_V3_SECRET"); secret != "" {
			score := 0.5
			if v, ok := envFloat("GOAUTH_RECAPTCHA_MIN_SCORE"); ok {
				score = v
			}
			opts = append(opts, WithReCaptchaV3(secret, score))
		}
	case "recaptcha":
		if secret := os.Getenv("GOAUTH_RECAPTCHA_SECRET"); secret != "" {
			opts = append(opts, WithReCaptcha(secret))
		}
	case "hcaptcha":
		if secret := os.Getenv("GOAUTH_HCAPTCHA_SECRET"); secret != "" {
			opts = append(opts, WithHCaptcha(secret))
		}
	default:
		if secret := os.Getenv("GOAUTH_TURNSTILE_SECRET"); secret != "" {
			opts = append(opts, WithTurnstile(secret))
		} else if secret := os.Getenv("GOAUTH_RECAPTCHA_V3_SECRET"); secret != "" {
			score := 0.5
			if v, ok := envFloat("GOAUTH_RECAPTCHA_MIN_SCORE"); ok {
				score = v
			}
			opts = append(opts, WithReCaptchaV3(secret, score))
		} else if secret := os.Getenv("GOAUTH_RECAPTCHA_SECRET"); secret != "" {
			opts = append(opts, WithReCaptcha(secret))
		} else if secret := os.Getenv("GOAUTH_HCAPTCHA_SECRET"); secret != "" {
			opts = append(opts, WithHCaptcha(secret))
		}
	}

	captchaPolicy := CaptchaPolicy{
		Required:       DefaultConfig().CaptchaRequired,
		OnRegister:     DefaultConfig().CaptchaOnRegister,
		OnLogin:        DefaultConfig().CaptchaOnLogin,
		OnPasswordReset: DefaultConfig().CaptchaOnPasswordReset,
		OnMagicLink:    DefaultConfig().CaptchaOnMagicLink,
	}
	captchaPolicySet := false
	if v, ok := envBool("GOAUTH_CAPTCHA_REQUIRED"); ok {
		captchaPolicy.Required = v
		captchaPolicySet = true
	}
	if v, ok := envBool("GOAUTH_CAPTCHA_ON_REGISTER"); ok {
		captchaPolicy.OnRegister = v
		captchaPolicySet = true
	}
	if v, ok := envBool("GOAUTH_CAPTCHA_ON_LOGIN"); ok {
		captchaPolicy.OnLogin = v
		captchaPolicySet = true
	}
	if v, ok := envBool("GOAUTH_CAPTCHA_ON_PASSWORD_RESET"); ok {
		captchaPolicy.OnPasswordReset = v
		captchaPolicySet = true
	}
	if v, ok := envBool("GOAUTH_CAPTCHA_ON_MAGIC_LINK"); ok {
		captchaPolicy.OnMagicLink = v
		captchaPolicySet = true
	}
	if captchaPolicySet {
		opts = append(opts, WithCaptchaPolicy(captchaPolicy))
	}
	if v, ok := envBool("GOAUTH_CAPTCHA_FAIL_OPEN"); ok {
		opts = append(opts, WithCaptchaFailOpen(v))
	}

	// Email
	emailProvider := strings.ToLower(strings.TrimSpace(os.Getenv("GOAUTH_EMAIL_PROVIDER")))
	switch emailProvider {
	case "resend":
		if key := os.Getenv("GOAUTH_RESEND_API_KEY"); key != "" {
			from := os.Getenv("GOAUTH_RESEND_FROM_EMAIL")
			name := os.Getenv("GOAUTH_RESEND_FROM_NAME")
			if from != "" {
				opts = append(opts, WithResend(key, from, name))
			}
		}
	case "sendgrid":
		if key := os.Getenv("GOAUTH_SENDGRID_API_KEY"); key != "" {
			from := os.Getenv("GOAUTH_SENDGRID_FROM_EMAIL")
			name := os.Getenv("GOAUTH_SENDGRID_FROM_NAME")
			if from != "" {
				opts = append(opts, WithSendGrid(key, from, name))
			}
		}
	case "mailgun":
		if key := os.Getenv("GOAUTH_MAILGUN_API_KEY"); key != "" {
			domain := os.Getenv("GOAUTH_MAILGUN_DOMAIN")
			from := os.Getenv("GOAUTH_MAILGUN_FROM_EMAIL")
			name := os.Getenv("GOAUTH_MAILGUN_FROM_NAME")
			if domain != "" && from != "" {
				opts = append(opts, WithMailgun(key, domain, from, name))
			}
		}
	case "smtp":
		host := os.Getenv("GOAUTH_SMTP_HOST")
		if host != "" {
			port := 587
			if v, ok := envInt("GOAUTH_SMTP_PORT"); ok {
				port = v
			}
			from := os.Getenv("GOAUTH_SMTP_FROM_EMAIL")
			if from != "" {
				cfg := smtp.Config{
					Host:      host,
					Port:      port,
					Username:  os.Getenv("GOAUTH_SMTP_USERNAME"),
					Password:  os.Getenv("GOAUTH_SMTP_PASSWORD"),
					FromEmail: from,
					FromName:  os.Getenv("GOAUTH_SMTP_FROM_NAME"),
				}
				if v, ok := envBool("GOAUTH_SMTP_TLS"); ok {
					cfg.UseTLS = v
				}
				opts = append(opts, WithSMTP(cfg))
			}
		}
	default:
		if key := os.Getenv("GOAUTH_RESEND_API_KEY"); key != "" {
			from := os.Getenv("GOAUTH_RESEND_FROM_EMAIL")
			name := os.Getenv("GOAUTH_RESEND_FROM_NAME")
			if from != "" {
				opts = append(opts, WithResend(key, from, name))
			}
		} else if key := os.Getenv("GOAUTH_SENDGRID_API_KEY"); key != "" {
			from := os.Getenv("GOAUTH_SENDGRID_FROM_EMAIL")
			name := os.Getenv("GOAUTH_SENDGRID_FROM_NAME")
			if from != "" {
				opts = append(opts, WithSendGrid(key, from, name))
			}
		} else if key := os.Getenv("GOAUTH_MAILGUN_API_KEY"); key != "" {
			domain := os.Getenv("GOAUTH_MAILGUN_DOMAIN")
			from := os.Getenv("GOAUTH_MAILGUN_FROM_EMAIL")
			name := os.Getenv("GOAUTH_MAILGUN_FROM_NAME")
			if domain != "" && from != "" {
				opts = append(opts, WithMailgun(key, domain, from, name))
			}
		} else if host := os.Getenv("GOAUTH_SMTP_HOST"); host != "" {
			port := 587
			if v, ok := envInt("GOAUTH_SMTP_PORT"); ok {
				port = v
			}
			from := os.Getenv("GOAUTH_SMTP_FROM_EMAIL")
			if from != "" {
				cfg := smtp.Config{
					Host:      host,
					Port:      port,
					Username:  os.Getenv("GOAUTH_SMTP_USERNAME"),
					Password:  os.Getenv("GOAUTH_SMTP_PASSWORD"),
					FromEmail: from,
					FromName:  os.Getenv("GOAUTH_SMTP_FROM_NAME"),
				}
				if v, ok := envBool("GOAUTH_SMTP_TLS"); ok {
					cfg.UseTLS = v
				}
				opts = append(opts, WithSMTP(cfg))
			}
		}
	}

	return opts
}

func envBool(key string) (bool, bool) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return false, false
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return false, false
	}
	return v, true
}

func envInt(key string) (int, bool) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return 0, false
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return v, true
}

func envFloat(key string) (float64, bool) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return 0, false
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

func envDuration(key string) (time.Duration, bool) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return 0, false
	}
	if d, err := time.ParseDuration(raw); err == nil {
		return d, true
	}
	if v, err := strconv.Atoi(raw); err == nil {
		return time.Duration(v) * time.Second, true
	}
	return 0, false
}

func envStrings(key string) ([]string, bool) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil, false
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}
