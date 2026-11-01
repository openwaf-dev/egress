package egress

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

var (
	reCreditCard = regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)
	rePrivateKey = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	reAWSKey     = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	reOpenAIKey  = regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b`)
	reGitHubKey  = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b`)

	reUnicodeEsc = regexp.MustCompile(`\\+u([0-9a-fA-F]{4})`)
)

// Limits of the decoding: they bound the work a body can cause, and what they leave undecoded is refused, not let through.
const (
	// dlpLevels is how many encodings deep ScanDLP decodes (base58 of base64 of hex is three). Normalization and
	// escapes do not count as a level.
	dlpLevels = 3
	// dlpCheapDepth bounds the chain of normalizations and escape decodings applied to each text.
	dlpCheapDepth = 3
	// dlpMinRun is the shortest run of an encoding's alphabet worth decoding (12 bytes in base64).
	dlpMinRun = 16
	// dlpMinText is the shortest printable segment of a decoded blob that is kept (a card has at least 13 digits).
	dlpMinText = 12
	// dlpMaxBase58Run is the longest base58 run decoded: base58 is one big number and decoding it is quadratic. A longer
	// run (over 3 KB of data, a whole PEM key fits) is refused as uninspectable.
	dlpMaxBase58Run = 4096
	// dlpBudgetFactor bounds the text all variants of a body add up to (times the body, plus dlpBudgetBase); a body that
	// needs more is refused as uninspectable.
	dlpBudgetFactor = 16
	dlpBudgetBase   = 1 << 20
)

// DLPMatch describes a sensitive data detection.
type DLPMatch struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	// Rule is the detector that matched (credit_card, iban, private_key, aws_access_key, openai_key, github_token, or
	// base58_run_too_long and inspection_limit when the body could not be inspected).
	Rule string `json:"-"`
	// Chain is how the text that matched was reached from the body, outermost first: "plain" for the body as sent,
	// "base58>base64" for base64 inside base58, "hex>normalize" for zero-width text inside hex.
	Chain string `json:"-"`
	// Hash identifies the matched fragment without revealing it: 12 hex digits of HMAC-SHA256 under a key drawn when
	// the process starts, so the same secret gives the same hash for the life of the gateway and cannot be brute-forced
	// from it.
	Hash string `json:"-"`

	fragment string
}

var dlpHashKey = func() []byte {
	k := make([]byte, 32)
	rand.Read(k) // never fails (crypto/rand panics on a broken source)
	return k
}()

func dlpHash(rule, fragment string) string {
	m := hmac.New(sha256.New, dlpHashKey)
	m.Write([]byte(rule))
	m.Write([]byte{0})
	m.Write([]byte(fragment))
	return hex.EncodeToString(m.Sum(nil)[:6])
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

// ibanLength is the IBAN length of each country of the SWIFT IBAN registry.
var ibanLength = map[string]int{
	"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BI": 27, "BR": 29,
	"BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DJ": 27, "DK": 18, "DO": 28, "EE": 20, "EG": 29,
	"ES": 24, "FI": 18, "FK": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28,
	"HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28,
	"LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20,
	"MR": 27, "MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23, "PK": 24, "PL": 28, "PS": 29, "PT": 25,
	"QA": 29, "RO": 24, "RS": 22, "RU": 33, "SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27,
	"SO": 23, "ST": 25, "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20, "YE": 30,
}

func isAlnum(c byte) bool { return c-'0' < 10 || (c|0x20)-'a' < 26 }

// findIBAN returns the first IBAN in text: a registry country code and two digits at a word start, then exactly the
// country's length of letters and digits (single spaces between groups allowed), ending at a word end, whose ISO 7064
// mod-97 check is 1.
func findIBAN(text string) string {
	for i := 0; i+4 <= len(text); i++ {
		if i > 0 && isAlnum(text[i-1]) || text[i+2]-'0' >= 10 || text[i+3]-'0' >= 10 {
			continue
		}
		cc := strings.ToUpper(text[i : i+2])
		want, ok := ibanLength[cc]
		if !ok {
			continue
		}
		var iban []byte
		j := i
		for j < len(text) && len(iban) < want {
			c := text[j]
			if c == ' ' && len(iban) >= 4 && j+1 < len(text) && isAlnum(text[j+1]) && text[j-1] != ' ' {
				j++
				continue
			}
			if !isAlnum(c) {
				break
			}
			if c >= 'a' {
				c -= 'a' - 'A'
			}
			iban = append(iban, c)
			j++
		}
		if len(iban) != want || j < len(text) && isAlnum(text[j]) {
			continue
		}
		if ibanMod97(iban) == 1 {
			return string(iban)
		}
	}
	return ""
}

// ibanMod97 computes the ISO 7064 MOD 97-10 remainder of an upper-case IBAN (country and check digits moved last).
func ibanMod97(iban []byte) int {
	r := 0
	for k := range iban {
		c := iban[(k+4)%len(iban)]
		if c >= 'A' {
			r = (r*100 + int(c-'A') + 10) % 97
		} else {
			r = (r*10 + int(c-'0')) % 97
		}
	}
	return r
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

// decodeUnicodeEscapes replaces literal \uXXXX sequences (a JSON body quoting a string the client built, or a payload
// that was meant to be decoded twice) with the character they name, so the invisibles and fullwidth forms they hide are
// the ones the normal form removes.
func decodeUnicodeEscapes(s string) string {
	if !strings.Contains(s, "\\u") {
		return ""
	}
	return reUnicodeEsc.ReplaceAllStringFunc(s, func(m string) string {
		// One or more backslashes, then u and exactly four hex digits.
		i := strings.LastIndexByte(m, 'u')
		n, err := strconv.ParseUint(m[i+1:], 16, 32)
		if err != nil {
			return m
		}
		return string(rune(n))
	})
}

// decodeJSONEscapes decodes the escapes of a JSON string once (\" \\ \/ \n \r \t \b \f and \uXXXX, surrogate pairs
// included), so an encoding whose alphabet has a quote, a backslash or < > & (Ascii85) is decoded as the client wrote
// it, not as the JSON body quotes it. decodeUnicodeEscapes is the looser form for text escaped more than once.
func decodeJSONEscapes(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 == len(s) {
			b.WriteByte(c)
			continue
		}
		switch e := s[i+1]; e {
		case '"', '\\', '/':
			b.WriteByte(e)
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'b', 'f':
			b.WriteByte(' ')
		case 'u':
			r, ok := hex4(s, i+2)
			if !ok {
				b.WriteByte(c)
				continue
			}
			i += 4
			if utf16.IsSurrogate(r) && i+7 < len(s) && s[i+2] == '\\' && s[i+3] == 'u' {
				if r2, ok := hex4(s, i+4); ok {
					if p := utf16.DecodeRune(r, r2); p != utf8.RuneError {
						r = p
						i += 6
					}
				}
			}
			b.WriteRune(r)
		default:
			b.WriteByte(c)
			continue
		}
		changed = true
		i++
	}
	if !changed {
		return ""
	}
	return b.String()
}

// hex4 reads the four hex digits at s[i:].
func hex4(s string, i int) (rune, bool) {
	if i+4 > len(s) {
		return 0, false
	}
	n, err := strconv.ParseUint(s[i:i+4], 16, 32)
	return rune(n), err == nil
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

// textByte marks the ASCII bytes that are text: printable characters and layout whitespace.
var textByte = func() (t [utf8.RuneSelf]bool) {
	for c := 0x20; c < 0x7f; c++ {
		t[c] = true
	}
	t['\t'], t['\n'], t['\r'] = true, true, true
	return t
}()

// textSegments returns the text worth scanning in a decoded blob: the whole blob when at least three quarters of its
// runes are text (printable, layout whitespace, or the invisible formatting the normal form removes; bytes that are
// not UTF-8 are not text), otherwise each stretch of at least dlpMinText text runes (a secret padded with binary
// noise, or the payload of an encoded run that started with other characters). A wrong guess at an encoding yields
// binary and costs nothing further.
func textSegments(b []byte) []string {
	if len(b) < dlpMinText {
		return nil
	}
	var spans [][2]int
	text, total := 0, 0
	start, runes := -1, 0
	for i := 0; i <= len(b); {
		ok, size := false, 1
		if i < len(b) {
			if c := b[i]; c < utf8.RuneSelf {
				ok = textByte[c]
			} else {
				var r rune
				r, size = utf8.DecodeRune(b[i:])
				ok = size > 1 && (unicode.IsPrint(r) || unicode.Is(unicode.Cf, r))
			}
			total++
		}
		if ok {
			text++
			if start < 0 {
				start, runes = i, 0
			}
			runes++
		} else {
			if start >= 0 && runes >= dlpMinText {
				spans = append(spans, [2]int{start, i})
			}
			start = -1
		}
		i += size
	}
	if text*4 >= total*3 {
		return []string{string(b)}
	}
	out := make([]string, len(spans))
	for k, sp := range spans {
		out[k] = string(b[sp[0]:sp[1]])
	}
	return out
}

// alphabet is a byte class of an encoding.
type alphabet [256]bool

func newAlphabet(chars string) *alphabet {
	var a alphabet
	for i := range len(chars) {
		a[chars[i]] = true
	}
	return &a
}

const (
	digits    = "0123456789"
	upper     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lower     = "abcdefghijklmnopqrstuvwxyz"
	b58Chars  = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	z85Chars  = digits + lower + upper + ".-:+=^!/*?&<>()[]{}@%$#"
	b85Chars  = digits + upper + lower + "!#$%&()*+-;<=>?@^_`{|}~"
	a85Digits = "!\"#$%&'()*+,-./" + digits + ":;<=>?@" + upper + "[\\]^_`" + "abcdefghijklmnopqrstu"
)

var (
	alphaBase64    = newAlphabet(digits + upper + lower + "+/-_")
	alphaBase32    = newAlphabet(upper + lower + "234567")
	alphaBase32Hex = newAlphabet(digits + "ABCDEFGHIJKLMNOPQRSTUVabcdefghijklmnopqrstuv")
	alphaHex       = newAlphabet(digits + "ABCDEFabcdef")
	alphaBase58    = newAlphabet(b58Chars)
	alphaAscii85   = newAlphabet(a85Digits + "z")

	base58Value = digitValues(b58Chars)
)

func digitValues(chars string) *[256]int8 {
	var v [256]int8
	for i := range v {
		v[i] = -1
	}
	for i := range len(chars) {
		v[chars[i]] = int8(i)
	}
	return &v
}

// base85 is one alphabet of the base85 family: 4 bytes as 5 digits, most significant first.
type base85 struct {
	name  string
	chars *alphabet
	value *[256]int8
	zero  bool // 'z' stands for four zero bytes (Ascii85)
}

var base85Family = []base85{
	{"ascii85", alphaAscii85, digitValues(a85Digits), true},
	{"z85", newAlphabet(z85Chars), digitValues(z85Chars), false},
	{"base85", newAlphabet(b85Chars), digitValues(b85Chars), false}, // RFC 1924, Python's b85encode, git
}

// decode decodes s leniently into dst (reused): a group over 2^32-1 is skipped, a final partial group of k digits
// gives k-1 bytes (padded with the highest digit, as the encoders do).
func (e *base85) decode(dst []byte, s string) []byte {
	out := dst[:0]
	var v uint64
	n := 0
	emit := func(k int) {
		if v <= 0xFFFFFFFF {
			group := [4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
			out = append(out, group[:k]...)
		}
		v, n = 0, 0
	}
	for i := range len(s) {
		c := s[i]
		if e.zero && c == 'z' {
			if n == 0 {
				out = append(out, 0, 0, 0, 0)
			}
			continue
		}
		d := e.value[c]
		if d < 0 {
			continue
		}
		v = v*85 + uint64(d)
		n++
		if n == 5 {
			emit(4)
		}
	}
	if n >= 2 {
		k := n - 1
		for ; n < 5; n++ {
			v = v*85 + 84
		}
		emit(k)
	}
	return out
}

// decodeBase58 decodes s (Bitcoin alphabet, every byte of s in it) as one big number, five digits per step.
func decodeBase58(s string) []byte {
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	limbs := make([]uint32, 0, len(s)*3/16+2) // little-endian base 2^32; 58^4 < 2^24
	for i := zeros; i < len(s); {
		acc, mult := uint64(0), uint64(1)
		for end := min(i+5, len(s)); i < end; i++ {
			acc = acc*58 + uint64(base58Value[s[i]])
			mult *= 58
		}
		carry := acc
		for k := range limbs {
			t := uint64(limbs[k])*mult + carry
			limbs[k] = uint32(t)
			carry = t >> 32
		}
		for ; carry > 0; carry >>= 32 {
			limbs = append(limbs, uint32(carry))
		}
	}
	out := make([]byte, zeros, zeros+len(limbs)*4)
	started := false
	for k := len(limbs) - 1; k >= 0; k-- {
		for sh := 24; sh >= 0; sh -= 8 {
			b := byte(limbs[k] >> sh)
			if started || b != 0 {
				started = true
				out = append(out, b)
			}
		}
	}
	return out
}

// runs calls fn with every maximal run of at least dlpMinRun bytes of a in s.
func runs(s string, a *alphabet, fn func(run string)) {
	for i := 0; i < len(s); {
		if !a[s[i]] {
			i++
			continue
		}
		j := i + 1
		for j < len(s) && a[s[j]] {
			j++
		}
		if j-i >= dlpMinRun {
			fn(s[i:j])
		}
		i = j
	}
}

// decoded is a text found inside an encoded run.
type decoded struct {
	text, encoding string
}

// dlpScan collects the variants of one body.
type dlpScan struct {
	seen     map[string]bool
	variants []dlpVariant
	budget   int
	// limit names the limit that left part of the body undecoded (a DLP rule), "" when none did.
	limit, limitFragment string
}

type dlpVariant struct {
	text  string
	chain string // steps from the body, outermost first, ">"-joined; "" for the body as sent
}

func joinChain(chain, step string) string {
	if chain == "" {
		return step
	}
	return chain + ">" + step
}

// add records text reached by chain, then its normal form and escape decodings (up to depth of them in a row).
func (sc *dlpScan) add(text, chain string, depth int) {
	if text == "" || sc.seen[text] {
		return
	}
	if len(text) > sc.budget {
		sc.limit = "inspection_limit"
		return
	}
	sc.budget -= len(text)
	sc.seen[text] = true
	sc.variants = append(sc.variants, dlpVariant{text, chain})
	if depth == 0 {
		return
	}
	sc.add(normalizeDLP(text), joinChain(chain, "normalize"), depth-1)
	sc.add(decodeURL(text), joinChain(chain, "url"), depth-1)
	sc.add(decodeUnicodeEscapes(text), joinChain(chain, "unicode_escape"), depth-1)
	sc.add(decodeJSONEscapes(text), joinChain(chain, "json_escape"), depth-1)
}

// decode returns the text inside every base64, base32, base32hex, hex, base58 and base85-family run of s.
func (sc *dlpScan) decode(s string) []decoded {
	var out []decoded
	keep := func(b []byte, encoding string) {
		for _, t := range textSegments(b) {
			out = append(out, decoded{t, encoding})
		}
	}
	var buf, src []byte // reused: what keep retains is copied
	grow := func(n int) []byte {
		if cap(buf) < n {
			buf = make([]byte, n)
		}
		return buf[:n]
	}
	runs(s, alphaBase64, func(run string) {
		enc := base64.RawStdEncoding
		if strings.ContainsAny(run, "-_") {
			enc = base64.RawURLEncoding
		}
		src = append(src[:0], run...)
		dst := grow(enc.DecodedLen(len(src)) + 3)
		n, _ := enc.Decode(dst, src) // a bad final quantum still yields what came before it
		keep(dst[:n], "base64")
	})
	for _, b32 := range []struct {
		chars *alphabet
		enc   *base32.Encoding
		name  string
	}{
		{alphaBase32, base32.StdEncoding.WithPadding(base32.NoPadding), "base32"},
		{alphaBase32Hex, base32.HexEncoding.WithPadding(base32.NoPadding), "base32hex"},
	} {
		runs(s, b32.chars, func(run string) {
			src = append(src[:0], run...)
			for k, c := range src {
				if c >= 'a' {
					src[k] = c - ('a' - 'A')
				}
			}
			dst := grow(b32.enc.DecodedLen(len(src)) + 5)
			n, _ := b32.enc.Decode(dst, src)
			keep(dst[:n], b32.name)
		})
	}
	runs(s, alphaHex, func(run string) {
		for _, r := range []string{run[:len(run)&^1], run[len(run)&1:]} {
			src = append(src[:0], r...)
			dst := grow(len(r) / 2)
			if n, err := hex.Decode(dst, src); err == nil {
				keep(dst[:n], "hex")
			}
			if len(run)%2 == 0 {
				break
			}
		}
	})
	runs(s, alphaBase58, func(run string) {
		if len(run) > dlpMaxBase58Run {
			sc.limit, sc.limitFragment = "base58_run_too_long", run
			return
		}
		keep(decodeBase58(run), "base58")
	})
	for i := range base85Family {
		e := &base85Family[i]
		runs(s, e.chars, func(run string) {
			// The run may start with characters that are not the payload (a key, a quote): every alignment is tried.
			// It may also end after the payload (Ascii85 takes the quote that closes a JSON string), which moves the
			// last partial group: the last 80 characters are decoded again without each of the trailing 1-4.
			for off := 0; off < 5 && len(run)-off >= dlpMinRun; off++ {
				r := run[off:]
				buf = e.decode(buf, r)
				keep(buf, e.name)
				for trim := 1; trim < 5 && len(r)-trim >= dlpMinRun; trim++ {
					t := r[:len(r)-trim]
					buf = e.decode(buf, t[max(0, (len(t)-80)/5*5):])
					keep(buf, e.name)
				}
			}
		})
	}
	// Adobe Ascii85 wraps its lines: <~ … ~> is decoded with the whitespace removed.
	for rest := s; ; {
		i := strings.Index(rest, "<~")
		if i < 0 {
			break
		}
		j := strings.Index(rest[i+2:], "~>")
		if j < 0 {
			break
		}
		body := rest[i+2 : i+2+j]
		if strings.ContainsAny(body, " \t\r\n") {
			body = strings.Join(strings.Fields(body), "")
			buf = base85Family[0].decode(buf, body)
			keep(buf, "ascii85")
		}
		rest = rest[i+2+j+2:]
	}
	return out
}

// dlpVariants returns the forms of text a filter must look through, each with the chain that reached it: the text as
// it arrives; its normal form (invisible formatting removed, fullwidth ASCII folded), its URL, \uXXXX and JSON escapes
// decoded; the text inside its base64, base32, base32hex, hex, base58, Ascii85, Z85 and base85 runs, normalized and
// decoded again up to dlpLevels encodings deep (base32 of base64, base58 of hex, hex of zero-width-broken text). The
// returned limit names the limit that stopped decoding, "" when none did.
func dlpVariants(text string) (variants []dlpVariant, limit, limitFragment string) {
	sc := &dlpScan{seen: make(map[string]bool, 8), budget: dlpBudgetBase + dlpBudgetFactor*len(text)}
	sc.add(text, "", dlpCheapDepth)
	start := 0
	for range dlpLevels {
		end := len(sc.variants)
		for i := start; i < end && sc.limit != "inspection_limit"; i++ {
			v := sc.variants[i]
			for _, d := range sc.decode(v.text) {
				sc.add(d.text, joinChain(v.chain, d.encoding), dlpCheapDepth)
			}
		}
		start = end
	}
	return sc.variants, sc.limit, sc.limitFragment
}

// ScanDLP inspects text for potential accidental data exfiltration, also through the encodings and invisible
// characters an agent could hide it in (see dlpVariants). Each match carries the rule, the chain of encodings that
// hid it and a keyed hash of what matched. A body the decoders cannot finish within their limits is reported as
// uninspectable, so a secret cannot hide behind the limits either.
func ScanDLP(text string) []DLPMatch {
	var matches []DLPMatch
	seen := make(map[string]bool, 2)
	variants, limit, limitFragment := dlpVariants(text)
	for _, v := range variants {
		for _, m := range scanDLPPlain(v.text) {
			key := m.Rule + "\x00" + m.fragment
			if seen[key] {
				continue
			}
			seen[key] = true
			m.Chain = v.chain
			if m.Chain == "" {
				m.Chain = "plain"
			}
			m.Hash = dlpHash(m.Rule, m.fragment)
			m.fragment = ""
			matches = append(matches, m)
		}
	}
	if limit != "" {
		desc := "Encoded content too large to decode for inspection (base58 run over 4096 characters)"
		if limit == "inspection_limit" {
			desc = "Encoded content nested too deeply or too large to inspect within the gateway's limits"
		}
		matches = append(matches, DLPMatch{Type: "uninspectable", Description: desc, Rule: limit, Chain: "plain",
			Hash: dlpHash(limit, limitFragment)})
	}
	return matches
}

// hasDigits reports whether s has at least n ASCII digits.
func hasDigits(s string, n int) bool {
	for i := 0; i < len(s) && n > 0; i++ {
		if s[i]-'0' < 10 {
			n--
		}
	}
	return n == 0
}

// scanDLPPlain inspects one already-normalized text.
func scanDLPPlain(text string) []DLPMatch {
	var matches []DLPMatch

	// 1. Private keys
	if strings.Contains(text, "PRIVATE KEY-----") {
		if m := rePrivateKey.FindString(text); m != "" {
			matches = append(matches, DLPMatch{
				Type:        "private_key",
				Description: "Cryptographic private key header detected",
				Rule:        "private_key",
				fragment:    m,
			})
		}
	}

	// 2. High-entropy Cloud/Git keys
	if strings.Contains(text, "AKIA") {
		if m := reAWSKey.FindString(text); m != "" {
			matches = append(matches, DLPMatch{
				Type:        "api_key",
				Description: "AWS Access Key ID pattern detected",
				Rule:        "aws_access_key",
				fragment:    m,
			})
		}
	}
	if strings.Contains(text, "sk-") {
		if m := reOpenAIKey.FindString(text); m != "" {
			matches = append(matches, DLPMatch{
				Type:        "api_key",
				Description: "OpenAI API key pattern detected",
				Rule:        "openai_key",
				fragment:    m,
			})
		}
	}
	if strings.Contains(text, "_") && strings.Contains(text, "gh") {
		if m := reGitHubKey.FindString(text); m != "" {
			matches = append(matches, DLPMatch{
				Type:        "api_key",
				Description: "GitHub personal/OAuth token pattern detected",
				Rule:        "github_token",
				fragment:    m,
			})
		}
	}

	// 3. Credit Cards with Luhn check
	if hasDigits(text, 13) {
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
						Rule:        "credit_card",
						fragment:    clean,
					})
					break
				}
			}
		}
	}

	// 4. IBAN with a valid check (ISO 13616)
	if hasDigits(text, 4) {
		if iban := findIBAN(text); iban != "" {
			matches = append(matches, DLPMatch{
				Type:        "iban",
				Description: "IBAN with a valid check digit detected: " + iban[:4] + "...*" + iban[len(iban)-4:],
				Rule:        "iban",
				fragment:    iban,
			})
		}
	}

	return matches
}
