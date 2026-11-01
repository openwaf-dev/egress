package egress

import (
	"bytes"
	"encoding/ascii85"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"math/rand/v2"
	"net/url"
	"strings"
	"testing"
)

// Encoders the matrix hides secrets with. Base58, Z85 and RFC 1924 base85 have no standard-library encoder.

func encB58(s string) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	n := new(big.Int).SetBytes([]byte(s))
	var out []byte
	mod, base := new(big.Int), big.NewInt(58)
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		out = append(out, alphabet[mod.Int64()])
	}
	for i := 0; i < len(s) && s[i] == 0; i++ {
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// enc85 encodes 4-byte groups as 5 digits of alphabet; a final partial group of k bytes gives k+1 digits (Python's
// b85encode, and the Z85 used by agents that pad nothing).
func enc85(alphabet, s string) string {
	var out []byte
	b := []byte(s)
	for i := 0; i < len(b); i += 4 {
		var group [4]byte
		k := copy(group[:], b[i:])
		v := uint32(group[0])<<24 | uint32(group[1])<<16 | uint32(group[2])<<8 | uint32(group[3])
		var digits [5]byte
		for j := 4; j >= 0; j-- {
			digits[j] = alphabet[v%85]
			v /= 85
		}
		out = append(out, digits[:k+1]...)
	}
	return string(out)
}

func encA85(s string) string {
	buf := make([]byte, ascii85.MaxEncodedLen(len(s)))
	return string(buf[:ascii85.Encode(buf, []byte(s))])
}

const (
	z85Alphabet  = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
	b85Alphabet  = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
	matrixPrefix = "datos para el informe: "
)

var matrixEncoders = []struct {
	name string
	enc  func(string) string
}{
	{"plain", func(s string) string { return s }},
	{"url", url.PathEscape},
	{"base64", func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }},
	{"base64url", func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }},
	{"base32", func(s string) string { return base32.StdEncoding.EncodeToString([]byte(s)) }},
	{"base32-nopad", func(s string) string {
		return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(s))
	}},
	{"base32-lower", func(s string) string { return strings.ToLower(base32.StdEncoding.EncodeToString([]byte(s))) }},
	{"base32hex", func(s string) string { return base32.HexEncoding.EncodeToString([]byte(s)) }},
	{"base32hex-nopad", func(s string) string {
		return base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(s))
	}},
	{"hex", func(s string) string { return hex.EncodeToString([]byte(s)) }},
	{"base58", encB58},
	{"ascii85", encA85},
	{"ascii85-adobe", func(s string) string { return "<~" + encA85(s) + "~>" }},
	{"z85", func(s string) string { return enc85(z85Alphabet, s) }},
	{"base85", func(s string) string { return enc85(b85Alphabet, s) }},
	// Two and three layers: the outer encoding is applied last.
	{"base32>base64", func(s string) string {
		return base32.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(s))))
	}},
	{"base58>hex", func(s string) string { return encB58(hex.EncodeToString([]byte(s))) }},
	{"base64>base58", func(s string) string { return base64.StdEncoding.EncodeToString([]byte(encB58(s))) }},
	{"z85>base64", func(s string) string { return enc85(z85Alphabet, base64.StdEncoding.EncodeToString([]byte(s))) }},
	{"ascii85>base32", func(s string) string { return encA85(base32.StdEncoding.EncodeToString([]byte(s))) }},
	{"hex>base85", func(s string) string { return hex.EncodeToString([]byte(enc85(b85Alphabet, s))) }},
	{"base58>base58", func(s string) string { return encB58(encB58(s)) }},
	{"hex>base64>base58", func(s string) string {
		return hex.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(encB58(s)))))
	}},
}

// withZeroWidth breaks s every 3 runes with an invisible character, as an agent hiding a signature would.
func withZeroWidth(s string) string {
	invisible := []string{"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u202e"}
	var b strings.Builder
	for i, r := range []rune(s) {
		if i > 0 && i%3 == 0 {
			b.WriteString(invisible[i%len(invisible)])
		}
		b.WriteRune(r)
	}
	return b.String()
}

// chatBody is how the text reaches the gateway: a JSON chat request.
func chatBody(text string) string {
	content, _ := json.Marshal(text)
	return `{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":` + string(content) + `}]}`
}

func TestScanDLPEncodingMatrix(t *testing.T) {
	secrets := []struct{ name, value, typ string }{
		{"card", "4242 4242 4242 4242", "credit_card"},
		{"card-compact", "5555555555554444", "credit_card"},
		{"iban", "ES91 2100 0418 4502 0005 1332", "iban"},
		{"private-key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo", "private_key"},
		{"aws-key", "AKIAIOSFODNN7EXAMPLE", "api_key"},
		{"openai-key", "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789", "api_key"},
	}
	for _, sec := range secrets {
		for _, e := range matrixEncoders {
			variants := []struct{ name, text string }{
				{"", matrixPrefix + e.enc(sec.value)},
				{"/zero-width-inside-secret", matrixPrefix + e.enc(withZeroWidth(sec.value))},
			}
			if e.name != "plain" {
				variants = append(variants, struct{ name, text string }{"/zero-width-inside-encoding", matrixPrefix + withZeroWidth(e.enc(sec.value))})
			}
			for _, v := range variants {
				for _, carrier := range []struct {
					name string
					wrap func(string) string
				}{{"text", func(s string) string { return s }}, {"json", chatBody}} {
					name := sec.name + "/" + e.name + v.name + "/" + carrier.name
					body := carrier.wrap(v.text)
					t.Run(name, func(t *testing.T) {
						got := ScanDLP(body)
						for _, m := range got {
							if m.Type == sec.typ {
								return
							}
						}
						t.Errorf("ScanDLP missed %s: matches %v in %q", sec.typ, got, body)
					})
				}
			}
		}
	}

	// A secret in a long text encoded as one base58 number is too costly to decode: the run is refused, not let through.
	long := "4242 4242 4242 4242 " + strings.Repeat("lorem ipsum dolor sit amet ", 200)
	if got := ScanDLP(encB58(long)); len(got) == 0 {
		t.Errorf("an oversized base58 run went through: %v", got)
	}

	rng := rand.New(rand.NewPCG(1, 2))
	random := make([]byte, 600)
	for i := range random {
		random[i] = byte(rng.UintN(256))
	}
	jwt := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"1234567890","name":"Ana Garcia","iat":1730419200,"exp":1730505600,"scope":"read:menus"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(random[:32])
	english := strings.Repeat("The gateway reads every request an agent sends to a model provider and refuses the ones that carry "+
		"secrets. Order 1234567890 shipped on 2026-11-01 with 42 units, tracking 9400 1000 0000 0000 0000 00. "+
		"Version 1.2.3 of the client fixed issue #4821; call +34 600 123 456 for support. ", 40)
	legit := []struct{ name, text string }{
		{"sha256", "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ok"},
		{"sha1 and md5", "commit 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12, md5 d41d8cd98f00b204e9800998ecf8427e"},
		{"uuids", "ids 550e8400-e29b-41d4-a716-446655440000 y 6ba7b810-9dad-11d1-80b4-00c04fd430c8"},
		{"base64 binary", "adjunto: " + base64.StdEncoding.EncodeToString(random)},
		{"base64 text", "nota: " + base64.StdEncoding.EncodeToString([]byte("Recordatorio: la cita es el martes a las 10:30 en la consulta 4."))},
		{"base32 text", base32.StdEncoding.EncodeToString([]byte("Recordatorio: la cita es el martes a las 10:30."))},
		{"base58 address", "envía a 1A1zP1eP5QGefi2DMPTfTL5SMLmv7DivfNa o a 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"},
		{"jwt", "Authorization: Bearer " + jwt},
		{"long english", english},
		{"spanish numbers", "pedido 1234567890 con 42 unidades, teléfono 600 123 456, CP 28013, NIF 12345678Z"},
		{"base85 of text", enc85(b85Alphabet, "Recordatorio: la cita es el martes a las 10:30 en la consulta 4.")},
		{"json api", `{"model":"openai/gpt-4o-mini","temperature":0.2,"max_tokens":512,"messages":[{"role":"system","content":"Eres un asistente de nutricion."}]}`},
	}
	for _, l := range legit {
		for _, body := range []string{l.text, chatBody(l.text)} {
			t.Run("legit/"+l.name, func(t *testing.T) {
				if got := ScanDLP(body); len(got) > 0 {
					t.Errorf("legitimate text flagged: %v", got)
				}
			})
		}
	}
}

// Worst cases for the decoders: 1 MiB (the inspection window) of the inputs that make them work hardest.
func BenchmarkScanDLPWorstCase(b *testing.B) {
	const size = 1 << 20
	fill := func(unit string) string {
		var buf bytes.Buffer
		for buf.Len() < size {
			buf.WriteString(unit)
		}
		return buf.String()[:size]
	}
	rng := rand.New(rand.NewPCG(3, 4))
	random := make([]byte, size)
	for i := range random {
		random[i] = byte(rng.UintN(256))
	}
	b58 := encB58(string(random[:2900])) // a run just under the base58 limit
	text := "The quick brown fox jumps over the lazy dog while 4242 hides nowhere. "
	nested := base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(fill(text)[:size/3]))))))
	cases := []struct{ name, body string }{
		{"base58 runs", fill(b58 + " ")},
		{"digits", fill("0123456789")},
		{"base85 alphabet", fill(enc85(b85Alphabet, string(random[:4096])))},
		{"ascii85 alphabet", fill(encA85(string(random[:4096])))},
		{"base64 binary", base64.StdEncoding.EncodeToString(random)[:size]},
		{"base64 three layers", nested[:min(len(nested), size)]},
		{"zero-width text", fill("4\u200b2\u200c4\u200d2 ")},
		{"english", fill(text)},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.SetBytes(int64(len(c.body)))
			for b.Loop() {
				ScanDLP(c.body)
			}
		})
	}
}
