// Package crypto provides cryptographic utilities for secure authentication.
//
// This package implements:
//   - Password hashing with Argon2id (memory-hard, GPU-resistant)
//   - Symmetric encryption with AES-256-GCM (authenticated encryption)
//   - Key derivation with HKDF-SHA256 (secure key expansion)
//   - Secure random number generation
//   - Constant-time comparison functions
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// Argon2 parameters - these are the recommended settings from OWASP
const (
	// Argon2Time is the number of iterations
	Argon2Time = 3
	// Argon2Memory is the memory usage in KB (64 MB)
	Argon2Memory = 64 * 1024
	// Argon2Threads is the degree of parallelism
	Argon2Threads = 4
	// Argon2KeyLen is the output key length in bytes
	Argon2KeyLen = 32
	// DefaultSaltSize is the default salt size in bytes
	DefaultSaltSize = 16
)

// DerivedKeys holds the keys derived from the Master Encryption Key (MEK).
type DerivedKeys struct {
	// EmailKey is used for encrypting email addresses
	EmailKey []byte
	// TOTPKey is used for encrypting TOTP secrets
	TOTPKey []byte
	// IPKey is used for encrypting IP addresses
	IPKey []byte
	// MetaKey is used for hashing metadata (e.g., IP addresses in logs)
	MetaKey []byte
}

// DeriveKeys derives purpose-specific keys from a Master Encryption Key using HKDF.
func DeriveKeys(mek []byte) (DerivedKeys, error) {
	if len(mek) != 32 {
		return DerivedKeys{}, errors.New("MEK must be 32 bytes")
	}

	emailKey, err := hkdfKey(mek, "dek_email")
	if err != nil {
		return DerivedKeys{}, err
	}
	totpKey, err := hkdfKey(mek, "dek_totp")
	if err != nil {
		return DerivedKeys{}, err
	}
	ipKey, err := hkdfKey(mek, "dek_ip")
	if err != nil {
		return DerivedKeys{}, err
	}
	metaKey, err := hkdfKey(mek, "dek_meta")
	if err != nil {
		return DerivedKeys{}, err
	}

	return DerivedKeys{
		EmailKey: emailKey,
		TOTPKey:  totpKey,
		IPKey:    ipKey,
		MetaKey:  metaKey,
	}, nil
}

// hkdfKey derives a 32-byte key using HKDF-SHA256.
func hkdfKey(mek []byte, info string) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, mek, nil, []byte(info))
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt encrypts plaintext using AES-256-GCM.
// Returns the ciphertext and nonce (both required for decryption).
func Encrypt(plaintext []byte, key []byte) (ciphertext []byte, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM.
func Decrypt(ciphertext, nonce, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// HashWithPepper hashes input with a pepper using SHA-256.
// Used for creating blind indexes (e.g., email lookup).
func HashWithPepper(input string, pepper []byte) []byte {
	h := sha256.New()
	h.Write([]byte(input))
	h.Write(pepper)
	return h.Sum(nil)
}

// HashToken hashes a token using SHA-256.
// Used for storing token hashes in the database.
func HashToken(input string) []byte {
	sum := sha256.Sum256([]byte(input))
	return sum[:]
}

// HashHex hashes input with SHA-256 and returns hex string.
func HashHex(input []byte) string {
	sum := sha256.Sum256(input)
	return hex.EncodeToString(sum[:])
}

// GenerateSalt generates a cryptographically secure random salt.
func GenerateSalt(size int) ([]byte, error) {
	if size < 8 {
		return nil, errors.New("salt size must be at least 8 bytes")
	}
	salt := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// HashPassword hashes a password using Argon2id.
func HashPassword(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
}

// VerifyPassword verifies a password against a hash using constant-time comparison.
func VerifyPassword(password string, hash, salt []byte) bool {
	candidate := HashPassword(password, salt)
	return ConstantTimeEquals(candidate, hash)
}

// ConstantTimeEquals compares two byte slices in constant time.
// This prevents timing attacks.
func ConstantTimeEquals(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// RandomBytes generates cryptographically secure random bytes.
func RandomBytes(size int) ([]byte, error) {
	if size < 1 {
		return nil, errors.New("size must be positive")
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// RandomCode generates a random numeric code of the specified length.
func RandomCode(length int) (string, error) {
	if length < 1 || length > 10 {
		return "", errors.New("code length must be between 1 and 10")
	}

	const digits = "0123456789"
	b := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}

	for i := range b {
		b[i] = digits[int(b[i])%len(digits)]
	}
	return string(b), nil
}

// RandomToken generates a URL-safe random token.
func RandomToken(length int) (string, error) {
	b, err := RandomBytes(length)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// MaskEmail masks an email address for display (e.g., ab****@gm****)
func MaskEmail(email string) string {
	at := -1
	for i := 0; i < len(email); i++ {
		if email[i] == '@' {
			at = i
			break
		}
	}
	if at <= 1 {
		return "***"
	}

	local := email[:at]
	domain := email[at+1:]

	if len(domain) == 0 {
		return local[:1] + "***@***"
	}

	maskedLocal := local[:2] + "****"
	maskedDomain := "****"
	if len(domain) >= 2 {
		maskedDomain = domain[:2] + "****"
	}

	return maskedLocal + "@" + maskedDomain
}
