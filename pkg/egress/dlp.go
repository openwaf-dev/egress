package egress

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
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

	reBase64Run = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)
	reHexRun    = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{2}){8,}\b`)
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

// zeroWidth are the invisible characters used to break a signature without changing what a model reads.
var zeroWidth = map[rune]bool{
	'\u00ad': true, // soft hyphen
	'\u180e': true, // mongolian vowel separator
	'\u200b': true, '\u200c': true, '\u200d': true, '\u200e': true, '\u200f': true,
	'\u202a': true, '\u202b': true, '\u202c': true, '\u202d': true, '\u202e': true,
	'\u2060': true, '\u2061': true, '\u2062': true, '\u2063': true, '\u2064': true,
	'\u2066': true, '\u2067': true, '\u2068': true, '\u2069': true, '\ufeff': true,
}

// normalizeDLP removes invisible formatting, folds fullwidth ASCII (U+FF01-U+FF5E) to ASCII and turns the
// non-ASCII spaces that look like a space into one, so a payload cannot hide behind them.
func normalizeDLP(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case zeroWidth[r], unicode.Is(unicode.Cf, r):
			continue
		case r >= 0xFF01 && r <= 0xFF5E:
			b.WriteRune(r - 0xFEE0)
		case r == 0x3000, r == 0x00A0, r == 0x2028, r == 0x2029:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// decodeURL decodes percent escapes once when the text carries them.
func decodeURL(s string) string {
	if !strings.Contains(s, "%") {
		return ""
	}
	if d, err := url.PathUnescape(s); err == nil {
		return d
	}
	return ""
}

// readable reports whether most of b is printable text (a decoded blob of binary is not worth scanning).
func readable(b []byte) bool {
	if len(b) < 8 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			printable++
		}
	}
	return printable*4 >= len(b)*3
}

// decodeEncodings returns the readable text of every base64 and hex run in s.
func decodeEncodings(s string) []string {
	var out []string
	for _, run := range reBase64Run.FindAllString(s, -1) {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if dec, err := enc.DecodeString(run); err == nil && readable(dec) {
				out = append(out, string(dec))
				break
			}
		}
	}
	for _, run := range reHexRun.FindAllString(s, -1) {
		if dec, err := hex.DecodeString(run); err == nil && readable(dec) {
			out = append(out, string(dec))
		}
	}
	return out
}

// normalizationVariants returns the forms of text a filter must look through: the text as it arrives, its normal
// form (invisible formatting removed, fullwidth ASCII folded), its URL escapes decoded, its base64 and hex runs
// decoded, and each of those normalized and decoded again (an agent that hides a card number as base64 of
// zero-width-broken text is still hiding a card number).
func normalizationVariants(text string) []string {
	var out []string
	seen := make(map[string]bool, 4)
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}

	add(text)
	for range 3 {
		n := len(out)
		for _, v := range out[:n] {
			add(normalizeDLP(v))
			add(decodeURL(v))
			for _, d := range decodeEncodings(v) {
				add(d)
				add(normalizeDLP(d))
			}
		}
	}
	return out
}

// ScanDLP inspects text for potential accidental data exfiltration, also through the encodings and invisible
// characters an agent could hide it in (see normalizationVariants).
func ScanDLP(text string) []DLPMatch {
	var matches []DLPMatch
	seen := make(map[string]bool, 2)
	for _, variant := range normalizationVariants(text) {
		for _, m := range scanDLPPlain(variant) {
			if key := m.Type + "|" + m.Description; !seen[key] {
				seen[key] = true
				matches = append(matches, m)
			}
		}
	}
	return matches
}

// scanDLPPlain inspects one already-normalized text.
func scanDLPPlain(text string) []DLPMatch {
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
