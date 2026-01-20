package labtest

import (
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// ==================== TOTP GENERATION TESTS ====================

func TestTOTPGeneration(t *testing.T) {
	// Generate a new TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "GoAuth Test",
		AccountName: "user@example.com",
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("Failed to generate TOTP key: %v", err)
	}

	t.Logf("TOTP Key Secret: %s", key.Secret())
	t.Logf("TOTP Key URL: %s", key.URL())

	if key.Secret() == "" {
		t.Error("Secret should not be empty")
	}
}

func TestTOTPValidation(t *testing.T) {
	// Generate key
	key, _ := totp.Generate(totp.GenerateOpts{
		Issuer:      "GoAuth Test",
		AccountName: "user@example.com",
		Period:      30,
		Digits:      otp.DigitsSix,
	})

	// Generate valid code
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("Failed to generate code: %v", err)
	}

	t.Logf("Generated code: %s", code)

	// Validate the code
	valid := totp.Validate(code, key.Secret())
	if !valid {
		t.Error("Generated code should be valid")
	}

	// Test with wrong code
	valid = totp.Validate("000000", key.Secret())
	if valid {
		t.Error("Wrong code should not be valid")
	}

	t.Log("✓ TOTP validation working correctly")
}

func TestTOTPWithDifferentDigits(t *testing.T) {
	tests := []struct {
		digits otp.Digits
		name   string
	}{
		{otp.DigitsSix, "6 digits"},
		{otp.DigitsEight, "8 digits"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := totp.Generate(totp.GenerateOpts{
				Issuer:      "GoAuth Test",
				AccountName: "user@example.com",
				Digits:      tt.digits,
			})
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			code, _ := totp.GenerateCodeCustom(key.Secret(), time.Now(), totp.ValidateOpts{
				Digits: tt.digits,
			})

			expectedLen := 6
			if tt.digits == otp.DigitsEight {
				expectedLen = 8
			}

			if len(code) != expectedLen {
				t.Errorf("Expected %d digit code, got %d", expectedLen, len(code))
			}

			t.Logf("✓ %s: code=%s", tt.name, code)
		})
	}
}

// ==================== BACKUP CODE TESTS ====================

func TestBackupCodeGeneration(t *testing.T) {
	// Simulate backup code generation
	codeCount := 10
	codeLength := 8
	
	codes := generateTestBackupCodes(codeCount, codeLength)
	
	if len(codes) != codeCount {
		t.Errorf("Expected %d codes, got %d", codeCount, len(codes))
	}

	for i, code := range codes {
		if len(code) != codeLength {
			t.Errorf("Code %d: expected length %d, got %d", i, codeLength, len(code))
		}
		
		// Check all digits
		for _, c := range code {
			if c < '0' || c > '9' {
				t.Errorf("Code %d contains non-digit: %c", i, c)
			}
		}
	}

	// Check uniqueness
	seen := make(map[string]bool)
	for _, code := range codes {
		if seen[code] {
			t.Error("Duplicate backup code generated")
		}
		seen[code] = true
	}

	t.Logf("✓ Generated %d unique backup codes", codeCount)
}

func generateTestBackupCodes(count, length int) []string {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		// Simulate random code generation
		code := ""
		for j := 0; j < length; j++ {
			code += string(rune('0' + (i*length+j)%10))
		}
		codes[i] = code
	}
	return codes
}

func TestBackupCodeFormat(t *testing.T) {
	tests := []struct {
		format   string
		expected string
	}{
		{"12345678", "1234-5678"},
		{"87654321", "8765-4321"},
	}

	for _, tt := range tests {
		result := formatBackupCode(tt.format)
		if result != tt.expected {
			t.Errorf("formatBackupCode(%s) = %s, want %s", tt.format, result, tt.expected)
		}
	}
}

func formatBackupCode(code string) string {
	if len(code) != 8 {
		return code
	}
	return code[:4] + "-" + code[4:]
}
