package labtest

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/migueldesapazr-gif/goauth/crypto"
)

// ==================== ENCRYPTION TESTS ====================

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("Hello, GoAuth! This is sensitive data.")

	ciphertext, nonce, err := crypto.Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if len(nonce) != 12 {
		t.Errorf("Expected nonce length 12, got %d", len(nonce))
	}

	if bytes.Equal(ciphertext, plaintext) {
		t.Error("Ciphertext should not equal plaintext")
	}

	decrypted, err := crypto.Decrypt(ciphertext, nonce, key)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted text doesn't match original. Got: %s, Want: %s", decrypted, plaintext)
	}
}

func TestEncryptDecryptWithDifferentKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	for i := range key1 {
		key1[i] = byte(i)
		key2[i] = byte(i + 1)
	}

	plaintext := []byte("Secret message")

	ciphertext, nonce, err := crypto.Encrypt(plaintext, key1)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = crypto.Decrypt(ciphertext, nonce, key2)
	if err == nil {
		t.Error("Expected decryption to fail with wrong key")
	}
}

// ==================== HASHING TESTS ====================

func TestHashWithPepper(t *testing.T) {
	pepper := make([]byte, 32)
	for i := range pepper {
		pepper[i] = byte(i)
	}

	data := "user@example.com"

	hash1 := crypto.HashWithPepper(data, pepper)
	hash2 := crypto.HashWithPepper(data, pepper)

	if !bytes.Equal(hash1, hash2) {
		t.Error("Same data with same pepper should produce identical hash")
	}

	differentHash := crypto.HashWithPepper("different@example.com", pepper)
	if bytes.Equal(hash1, differentHash) {
		t.Error("Different data should produce different hashes")
	}

	differentPepper := make([]byte, 32)
	for i := range differentPepper {
		differentPepper[i] = byte(i + 1)
	}
	hashWithDiffPepper := crypto.HashWithPepper(data, differentPepper)
	if bytes.Equal(hash1, hashWithDiffPepper) {
		t.Error("Same data with different pepper should produce different hash")
	}
}

func TestHashToken(t *testing.T) {
	token := "abc123xyz789"

	hash1 := crypto.HashToken(token)
	hash2 := crypto.HashToken(token)

	if !bytes.Equal(hash1, hash2) {
		t.Error("Same token should produce identical hash")
	}

	differentHash := crypto.HashToken("different-token")
	if bytes.Equal(hash1, differentHash) {
		t.Error("Different tokens should produce different hashes")
	}
}

// ==================== PASSWORD HASHING TESTS ====================

func TestHashPassword(t *testing.T) {
	password := "MySecurePassword123!"

	salt, err := crypto.GenerateSalt(crypto.DefaultSaltSize)
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	hash := crypto.HashPassword(password, salt)

	if len(hash) == 0 {
		t.Error("Hash should not be empty")
	}

	hash2 := crypto.HashPassword(password, salt)
	if !bytes.Equal(hash, hash2) {
		t.Error("Same password and salt should produce identical hash")
	}
}

func TestVerifyPassword(t *testing.T) {
	password := "MySecurePassword123!"

	salt, _ := crypto.GenerateSalt(crypto.DefaultSaltSize)
	hash := crypto.HashPassword(password, salt)

	if !crypto.VerifyPassword(password, hash, salt) {
		t.Error("VerifyPassword should return true for correct password")
	}

	if crypto.VerifyPassword("WrongPassword", hash, salt) {
		t.Error("VerifyPassword should return false for wrong password")
	}
}

// ==================== KEY DERIVATION TESTS ====================

func TestDeriveKeys(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	keys, err := crypto.DeriveKeys(masterKey)
	if err != nil {
		t.Fatalf("DeriveKeys failed: %v", err)
	}

	if len(keys.EmailKey) != 32 {
		t.Errorf("EmailKey should be 32 bytes, got %d", len(keys.EmailKey))
	}
	if len(keys.IPKey) != 32 {
		t.Errorf("IPKey should be 32 bytes, got %d", len(keys.IPKey))
	}
	if len(keys.TOTPKey) != 32 {
		t.Errorf("TOTPKey should be 32 bytes, got %d", len(keys.TOTPKey))
	}
	if len(keys.MetaKey) != 32 {
		t.Errorf("MetaKey should be 32 bytes, got %d", len(keys.MetaKey))
	}

	if bytes.Equal(keys.EmailKey, keys.IPKey) {
		t.Error("Derived keys should be different from each other")
	}
}

// ==================== RANDOM GENERATION TESTS ====================

func TestRandomBytes(t *testing.T) {
	bytes1, err := crypto.RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes failed: %v", err)
	}

	if len(bytes1) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(bytes1))
	}

	bytes2, _ := crypto.RandomBytes(32)
	if bytes.Equal(bytes1, bytes2) {
		t.Error("Two random byte sequences should not be equal")
	}
}

func TestRandomCode(t *testing.T) {
	code1, err := crypto.RandomCode(6)
	if err != nil {
		t.Fatalf("RandomCode failed: %v", err)
	}

	if len(code1) != 6 {
		t.Errorf("Expected 6 digit code, got %d characters", len(code1))
	}

	for _, c := range code1 {
		if c < '0' || c > '9' {
			t.Errorf("Code should only contain digits, found: %c", c)
		}
	}

	code2, _ := crypto.RandomCode(6)
	if code1 == code2 {
		t.Error("Two random codes should likely not be equal")
	}
}

func TestRandomToken(t *testing.T) {
	token, err := crypto.RandomToken(32)
	if err != nil {
		t.Fatalf("RandomToken failed: %v", err)
	}

	_, err = base64.URLEncoding.DecodeString(token)
	if err != nil {
		t.Errorf("Token should be valid base64url: %v", err)
	}
}

// ==================== CONSTANT TIME COMPARISON ====================

func TestConstantTimeEquals(t *testing.T) {
	a := []byte("hello")
	b := []byte("hello")
	c := []byte("world")

	if !crypto.ConstantTimeEquals(a, b) {
		t.Error("Identical slices should be equal")
	}

	if crypto.ConstantTimeEquals(a, c) {
		t.Error("Different slices should not be equal")
	}

	if crypto.ConstantTimeEquals([]byte("short"), []byte("longer string")) {
		t.Error("Different length slices should not be equal")
	}
}

// ==================== EMAIL MASKING ====================

func TestMaskEmail(t *testing.T) {
	tests := []struct {
		email    string
		expected string
	}{
		{"john@example.com", "j***@example.com"},
		{"ab@test.org", "a*@test.org"},
		{"a@x.co", "a@x.co"},
		{"test.user@domain.com", "t*******@domain.com"},
	}

	for _, tt := range tests {
		masked := crypto.MaskEmail(tt.email)
		if masked != tt.expected {
			t.Errorf("MaskEmail(%s) = %s, want %s", tt.email, masked, tt.expected)
		}
	}
}
