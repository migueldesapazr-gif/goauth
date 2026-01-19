package goauth

import "strings"

var defaultDisposableDomains = map[string]struct{}{
	"10minutemail.com":      {},
	"10minutemail.net":      {},
	"10minutemail.org":      {},
	"0email.net":            {},
	"dispostable.com":       {},
	"emailondeck.com":       {},
	"fakeinbox.com":         {},
	"getairmail.com":        {},
	"guerrillamail.com":     {},
	"guerrillamail.net":     {},
	"guerrillamail.org":     {},
	"guerrillamail.de":      {},
	"guerrillamailblock.com": {},
	"inboxkitten.com":       {},
	"mailcatch.com":         {},
	"maildrop.cc":           {},
	"mailinator.com":        {},
	"mailinator.net":        {},
	"mailnesia.com":         {},
	"mintemail.com":         {},
	"sharklasers.com":       {},
	"spambog.com":           {},
	"spambog.de":            {},
	"spambog.ru":            {},
	"temp-mail.org":         {},
	"temp-mail.io":          {},
	"tempmail.com":          {},
	"throwawaymail.com":     {},
	"trashmail.com":         {},
	"trashmail.net":         {},
	"yopmail.com":           {},
	"yopmail.net":           {},
	"yopmail.fr":            {},
	"yopmail.computer":      {},
}

func normalizeDomainList(domains []string) []string {
	out := make([]string, 0, len(domains))
	for _, domain := range domains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		domain = strings.TrimPrefix(domain, "@")
		if domain == "" {
			continue
		}
		out = append(out, domain)
	}
	return out
}

func (s *AuthService) isDisposableEmail(email string) bool {
	at := strings.LastIndex(email, "@")
	if at < 0 || at >= len(email)-1 {
		return false
	}
	domain := strings.ToLower(strings.TrimSpace(email[at+1:]))
	if domain == "" {
		return false
	}
	return isDisposableDomain(domain, s.config.DisposableEmailDomains)
}

func isDisposableDomain(domain string, override []string) bool {
	if len(override) == 0 {
		return domainInMap(domain, defaultDisposableDomains)
	}
	custom := make(map[string]struct{}, len(override))
	for _, d := range override {
		if d == "" {
			continue
		}
		custom[strings.ToLower(d)] = struct{}{}
	}
	return domainInMap(domain, custom)
}

func domainInMap(domain string, domains map[string]struct{}) bool {
	labels := strings.Split(domain, ".")
	for i := 0; i < len(labels); i++ {
		candidate := strings.Join(labels[i:], ".")
		if _, ok := domains[candidate]; ok {
			return true
		}
	}
	return false
}
