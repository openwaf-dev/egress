package egress

import (
	"encoding/base64"
	"testing"
)

func TestScanDLPThroughEncodings(t *testing.T) {
	const card = "4242 4242 4242 4242"
	cases := []struct {
		name string
		text string
		want bool
	}{
		{"plain card", "mi tarjeta es " + card, true},
		{"base64 card", "tarjeta: " + base64.StdEncoding.EncodeToString([]byte(card)), true},
		{"zero-width card", "4\u200b242 4\u200c242 42\u200d42 4242", true},
		{"fullwidth card", "\uff14\uff12\uff14\uff12 \uff14\uff12\uff14\uff12 \uff14\uff12\uff14\uff12 \uff14\uff12\uff14\uff12", true},
		{"url-escaped card", "card=4242%204242%204242%204242", true},
		{"base64 of zero-width card", base64.StdEncoding.EncodeToString([]byte("4242\u200b4242 4242 4242")), true},
		{"hex of card", "34323432203432343220343234322034323432", true},
		{"json escape zero-width card", `4242\u200b4242\u200b4242\u200b4242`, true},
		{"json escape fullwidth card", `\uff14\uff12\uff14\uff12 \uff14\uff12\uff14\uff12 \uff14\uff12\uff14\uff12 \uff14\uff12\uff14\uff12`, true},
		{"base64 of escape zero-width card", base64.StdEncoding.EncodeToString([]byte(`4242\u200b4242\u200b4242\u200b4242`)), true},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----", true},
		{"benign", "hola, quiero reservar una cita el 12 de marzo", false},
		{"numbers only", "pedido 1234567890 con 42 unidades", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ScanDLP(c.text)
			if (len(got) > 0) != c.want {
				t.Fatalf("ScanDLP(%q) = %v, want match %v", c.text, got, c.want)
			}
		})
	}
}
