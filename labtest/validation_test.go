package labtest

import (
	"regexp"
	"testing"
	"unicode"
)

// ==================== PASSWORD VALIDATION TESTS ====================

func TestPasswordComplexity(t *testing.T) {
	tests := []struct {
		password string
		minLen   int
		wantOk   bool
		desc     string
	}{
		{"short", 8, false, "too short"},
		{"password", 8, false, "no numbers or symbols"},
		{"password1", 8, false, "no uppercase or symbols"},
		{"Password1", 8, false, "no symbols"},
		{"Password1!", 8, true, "meets all requirements"},
		{"MyStr0ng!Pass", 8, true, "strong password"},
		{"12345678", 8, false, "only numbers"},
		{"UPPERCASE1!", 8, false, "no lowercase"},
		{"aB1!", 8, false, "too short despite complexity"},
	}

	for _, tt := range tests {
		ok := validatePasswordComplexity(tt.password, tt.minLen)
		if ok != tt.wantOk {
			t.Errorf("validatePasswordComplexity(%q) = %v, want %v (%s)",
				tt.password, ok, tt.wantOk, tt.desc)
		}
	}
}

// validatePasswordComplexity checks if password meets complexity requirements.
func validatePasswordComplexity(password string, minLen int) bool {
	if len(password) < minLen {
		return false
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasDigit && hasSpecial
}

// ==================== EMAIL VALIDATION TESTS ====================

func TestEmailValidation(t *testing.T) {
	tests := []struct {
		email  string
		wantOk bool
		desc   string
	}{
		{"user@example.com", true, "valid email"},
		{"user.name@example.com", true, "email with dot in local part"},
		{"user+tag@example.com", true, "email with plus sign"},
		{"user@subdomain.example.com", true, "subdomain email"},
		{"", false, "empty string"},
		{"invalid", false, "no @ symbol"},
		{"@example.com", false, "no local part"},
		{"user@", false, "no domain"},
		{"user@.com", false, "domain starts with dot"},
		{"user space@example.com", false, "space in local part"},
		{"user@example", true, "no TLD (technically valid RFC 5321)"},
	}

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+$`)

	for _, tt := range tests {
		ok := emailRegex.MatchString(tt.email)
		if ok != tt.wantOk {
			t.Errorf("email validation(%q) = %v, want %v (%s)",
				tt.email, ok, tt.wantOk, tt.desc)
		}
	}
}

// ==================== USERNAME VALIDATION TESTS ====================

func TestUsernameValidation(t *testing.T) {
	tests := []struct {
		username string
		wantOk   bool
		desc     string
	}{
		{"john_doe", true, "valid with underscore"},
		{"john-doe", true, "valid with hyphen"},
		{"johndoe123", true, "valid alphanumeric"},
		{"JohnDoe", true, "valid with uppercase"},
		{"jo", false, "too short"},
		{"a", false, "single character"},
		{"john@doe", false, "contains @"},
		{"john doe", false, "contains space"},
		{".johndoe", false, "starts with dot"},
		{"johndoe.", false, "ends with dot"},
		{"-johndoe", false, "starts with hyphen"},
		{"johndoe-", false, "ends with hyphen"},
		{"123456", false, "numeric only"},
		{"john__doe", true, "double underscore ok"},
		{"admin", true, "reserved name (should be blocked separately)"},
	}

	for _, tt := range tests {
		ok := validateUsername(tt.username)
		if ok != tt.wantOk {
			t.Errorf("validateUsername(%q) = %v, want %v (%s)",
				tt.username, ok, tt.wantOk, tt.desc)
		}
	}
}

// validateUsername checks basic username format.
func validateUsername(username string) bool {
	if len(username) < 3 || len(username) > 32 {
		return false
	}

	// Check for invalid characters
	validRegex := regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)
	if !validRegex.MatchString(username) {
		return false
	}

	// Cannot start or end with . or -
	first, last := username[0], username[len(username)-1]
	if first == '.' || first == '-' || last == '.' || last == '-' {
		return false
	}

	// Cannot be numeric only
	for _, r := range username {
		if !unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// ==================== RESERVED USERNAME TESTS ====================

func TestReservedUsernames(t *testing.T) {
	reserved := []string{
		"admin", "administrator", "root", "system", "support",
		"help", "info", "contact", "noreply", "no-reply",
		"postmaster", "webmaster", "abuse", "security",
	}

	reservedMap := make(map[string]bool)
	for _, r := range reserved {
		reservedMap[r] = true
	}

	tests := []struct {
		username string
		wantOk   bool
	}{
		{"admin", false},
		{"Administrator", false},
		{"ROOT", false},
		{"johndoe", true},
		{"support", false},
		{"my_support", true},
	}

	for _, tt := range tests {
		isReserved := reservedMap[normalizeUsername(tt.username)]
		ok := !isReserved
		if ok != tt.wantOk {
			t.Errorf("reserved check for %q = %v, want %v", tt.username, ok, tt.wantOk)
		}
	}
}

func normalizeUsername(username string) string {
	result := []rune{}
	for _, r := range username {
		result = append(result, unicode.ToLower(r))
	}
	return string(result)
}
