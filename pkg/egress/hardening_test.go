package egress

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// bearerToken: the scheme is case-insensitive, at least one space separates it from the
// token, and anything that is not a present Bearer header is not a token.
func TestBearerTokenParsing(t *testing.T) {
	cases := []struct {
		header string
		token  string
		ok     bool
	}{
		{"", "", false},
		{"Bearer", "", false},
		{"Bearer ", "", false},
		{"Bearer\tabc", "", false}, // non-space separator is not accepted
		{"Bearer  abc", "abc", true},
		{"bearer abc", "abc", true},
		{"BEARER abc def", "abc def", true},
		{"Basic abc", "", false},
		{"Basic", "", false},
		{"abc", "", false},
		{"X-API-Key abc", "", false},
		{"Bearer abc ", "abc", true},
		{"Bearer \t abc", "abc", true},
	}
	for _, c := range cases {
		tok, ok := bearerToken(c.header)
		if tok != c.token || ok != c.ok {
			t.Errorf("%q: got (%q,%v), want (%q,%v)", c.header, tok, ok, c.token, c.ok)
		}
	}
}

// A non-Bearer Authorization header is refused with its own code before any agent token is
// compared; a lower-case scheme still authenticates.
func TestResolveRejectsForeignScheme(t *testing.T) {
	srv, _, _ := testSetup()
	cfg := srv.resolver.(*Config)

	route := ResolveRequest{RouteAgent: "support-agent", Target: "openrouter", Authorization: "Basic abc"}
	if _, err := cfg.Resolve(nil, route); err == nil {
		t.Fatal("Basic scheme must be refused")
	} else {
		var re *ResolveError
		if !errors.As(err, &re) || re.Status != http.StatusUnauthorized || re.Code != "invalid_scheme" {
			t.Fatalf("got %v", err)
		}
	}

	ok := ResolveRequest{RouteAgent: "support-agent", Target: "openrouter", Authorization: "bearer OWE_TOKEN_SUPPORT_AGENT"}
	if _, err := cfg.Resolve(nil, ok); err != nil {
		t.Fatalf("lower-case scheme must authenticate: %v", err)
	}
}

// Every 401 carries the WWW-Authenticate challenge; a missing token, a wrong one and a
// foreign scheme all 401 and never reach an upstream.
func TestUnauthorizedCarriesChallenge(t *testing.T) {
	srv, upstream, _ := testSetup()
	defer upstream.Close()

	cases := map[string]struct {
		auth string
		code string
	}{
		"no token":       {"", "token_required"},
		"wrong token":    {"Bearer WRONG", "invalid_token"},
		"foreign scheme": {"Basic dXNlcjpwYXNz", "invalid_scheme"},
	}
	for name, c := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/v1/agent/support-agent/proxy/openrouter/chat/completions", strings.NewReader(`{"model":"gpt-4o"}`))
		if c.auth != "" {
			req.Header.Set("Authorization", c.auth)
		}
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: got %d, want 401", name, rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
			t.Errorf("%s: WWW-Authenticate = %q, want Bearer", name, got)
		}
		if !strings.Contains(rec.Body.String(), c.code) {
			t.Errorf("%s: body %s lacks %q", name, rec.Body.String(), c.code)
		}
	}
}

// Numeric IP spellings netip rejects must be refused before any DNS lookup; a trailing dot
// normalizes to the same IP and 8.8.8.8 stays allowed (public). Hex-dotted forms ("0x7f.0.0.1",
// "0x7f.1") are not caught here; TestHexDottedHostBlockedAtDial covers them at dial time.
func TestValidatePublicDestinationNumericForms(t *testing.T) {
	cases := []struct {
		host    string
		wantErr bool
	}{
		{"8.8.8.8", false},    // public, direct
		{"8.8.8.8.", false},   // trailing dot normalized to the same IP
		{"2130706433", true},  // decimal 127.0.0.1
		{"0x7f000001", true},  // hex 127.0.0.1
		{"0177.0.0.1", true},  // octal-style dotted
		{"127.1", true},       // short decimal dotted
		{"127.0.0.01", true},  // zero-padded component
		{"2130706433.", true}, // decimal with trailing dot
	}
	for _, c := range cases {
		err := ValidatePublicDestination(c.host)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err %v, want error=%v", c.host, err, c.wantErr)
		}
	}
}

// Fail-fast configuration: bad base_url, missing host and allowlists naming unknown targets
// are refused at load time; control-plane style files (agents without targets) still load.
func TestLoadConfigValidation(t *testing.T) {
	write := func(name, body string) string {
		p := filepath.Join(t.TempDir(), name)
		os.WriteFile(p, []byte(body), 0o600)
		return p
	}
	bad := map[string]string{
		"ftp scheme": `{"targets":{"x":{"base_url":"ftp://host/x","host":"host"}}}`,
		"no host":    `{"targets":{"x":{"base_url":"not a url","host":"h"}}}`,
		"empty host": `{"targets":{"x":{"base_url":"https://api.openai.com/v1","host":""}}}`,
		"unknown allowed target": `{"targets":{"openai":{"base_url":"https://api.openai.com/v1","host":"api.openai.com"}},
			"agents":{"a":{"token":"t","allowed_targets":["openai","typo"]}}}`,
	}
	for name, body := range bad {
		if _, err := LoadConfig(write("bad.json", body)); err == nil {
			t.Errorf("%s: config accepted, want error", name)
		}
	}
	good := `{"targets":{"openai":{"base_url":"https://api.openai.com/v1","host":"api.openai.com"}},
		"agents":{"a":{"token":"t","allowed_targets":["openai"]}}}`
	if _, err := LoadConfig(write("good.json", good)); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
	cpStyle := `{"agents":{"a":{"token":"t","allowed_targets":["from-control-plane"]}}}`
	if _, err := LoadConfig(write("cp.json", cpStyle)); err != nil {
		t.Errorf("control-plane style config rejected: %v", err)
	}
}

// stubDNS answers every A query on a local UDP socket: the first with first, later ones with
// later (a DNS-rebinding resolver); AAAA queries get no answer. It replaces net.DefaultResolver
// for the test, so no real DNS is involved.
func stubDNS(t *testing.T, first, later [4]byte) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var aQueries atomic.Int32
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			q := buf[:n]
			// Header (12) + question name + QTYPE(2) + QCLASS(2).
			end := 12
			for end < n && q[end] != 0 {
				end += int(q[end]) + 1
			}
			end += 5
			if end > n {
				continue
			}
			resp := append([]byte(nil), q[:end]...)
			resp[2], resp[3] = 0x81, 0x80 // response, recursion desired+available, NOERROR
			resp[6], resp[7] = 0, 0       // ANCOUNT
			resp[8], resp[9], resp[10], resp[11] = 0, 0, 0, 0
			if q[end-4] == 0 && q[end-3] == 1 { // QTYPE A
				ip := later
				if aQueries.Add(1) == 1 {
					ip = first
				}
				resp[7] = 1
				resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4)
				resp = append(resp, ip[:]...)
			}
			pc.WriteTo(resp, from)
		}
	}()
	prev := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", pc.LocalAddr().String())
	}}
	t.Cleanup(func() { net.DefaultResolver = prev; pc.Close() })
}

// Hex-dotted spellings ("0x7f.1") are not numeric literals for the pre-DNS check and go to the
// resolver. If it first answers a public address and then the private one (rebinding, or a
// resolver that reads the name as 127.0.0.1), the dial-time check still refuses the connection.
func TestHexDottedHostBlockedAtDial(t *testing.T) {
	if suspiciousIPLiteral("0x7f.1") || suspiciousIPLiteral("0x7f.0.0.1") {
		t.Fatal("hex-dotted forms are now caught pre-DNS; this test no longer covers the dial-time path")
	}
	called := false
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer upstream.Close()
	_, port, _ := net.SplitHostPort(upstream.Listener.Addr().String())
	stubDNS(t, [4]byte{8, 8, 8, 8}, [4]byte{127, 0, 0, 1})

	res := &Resolution{
		AgentID: "a", AgentName: "a",
		Policy: AgentPolicy{AllowedTargets: []string{"x"}},
		Target: &TargetConfig{BaseURL: "http://0x7f.1:" + port, Host: "0x7f.1", AuthHeader: "Authorization"},
	}
	srv := NewServerWithResolver(staticResolution{res}, nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/agent/a/proxy/x/models", nil))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), CodeSSRFBlocked) || called {
		t.Fatalf("got %d %s, upstream called %v", rec.Code, rec.Body.String(), called)
	}
}
