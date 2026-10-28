package egress

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
// normalizes to the same IP and 8.8.8.8 stays allowed (public).
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
