package egress

import (
	"regexp"
	"strings"
	"unicode"
)

var (
	reCreditCard = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
	rePrivateKey = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	reAWSKey     = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	reOpenAIKey  = regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b`)
	reGitHubKey  = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b`)
)

// DLPMatch describes a sensitive data detection.
type DLPMatch struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

// luhnValid checks if a numeric string passes the Luhn checksum algorithm.
func luhnValid(s string) bool {
	var digits []int
	for _, r := range s {
		if unicode.IsDigit(r) {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}

	sum := 0
	alternate := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := digits[i]
		if alternate {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alternate = !alternate
	}
	return sum%10 == 0
}

// ScanDLP inspects text for potential accidental data exfiltration.
func ScanDLP(text string) []DLPMatch {
	var matches []DLPMatch

	// 1. Private keys
	if rePrivateKey.MatchString(text) {
		matches = append(matches, DLPMatch{
			Type:        "private_key",
			Description: "Cryptographic private key header detected",
		})
	}

	// 2. High-entropy Cloud/Git keys
	if reAWSKey.MatchString(text) {
		matches = append(matches, DLPMatch{
			Type:        "api_key",
			Description: "AWS Access Key ID pattern detected",
		})
	}
	if reOpenAIKey.MatchString(text) {
		matches = append(matches, DLPMatch{
			Type:        "api_key",
			Description: "OpenAI API key pattern detected",
		})
	}
	if reGitHubKey.MatchString(text) {
		matches = append(matches, DLPMatch{
			Type:        "api_key",
			Description: "GitHub personal/OAuth token pattern detected",
		})
	}

	// 3. Credit Cards with Luhn check
	for _, candidate := range reCreditCard.FindAllString(text, -1) {
		clean := strings.Map(func(r rune) rune {
			if unicode.IsDigit(r) {
				return r
			}
			return -1
		}, candidate)
		if len(clean) >= 13 && len(clean) <= 19 && luhnValid(clean) {
			// Check that it starts with valid IIN (4 = Visa, 5 = MC, 3 = Amex, 6 = Discover)
			if clean[0] == '4' || clean[0] == '5' || strings.HasPrefix(clean, "34") || strings.HasPrefix(clean, "37") || clean[0] == '6' {
				matches = append(matches, DLPMatch{
					Type:        "credit_card",
					Description: "Valid payment card number (Luhn match) detected: " + clean[:4] + "...*" + clean[len(clean)-4:],
				})
				break
			}
		}
	}

	return matches
}
