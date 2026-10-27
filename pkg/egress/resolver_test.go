package egress

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An agent configured with token_sha256 authenticates with the token whose hash it holds,
// both when named in the route and when found by its token.
func TestTokenSHA256Agent(t *testing.T) {
	srv, upstream, _ := testSetup()
	defer upstream.Close()

	sum := sha256.Sum256([]byte("OWE_TOKEN_HASHED_AGENT"))
	cfg := srv.resolver.(*Config)
	cfg.Agents["hashed-agent"] = AgentConfig{
		TokenSHA256:       hex.EncodeToString(sum[:]),
		AllowedTargets:    []string{"openrouter"},
		CredentialMapping: map[string]CredRef{"openrouter": {Path: "secret/data/agents/support", Key: "OPENROUTER_API_KEY"}},
	}

	cases := []struct {
		path, token string
		want        int
	}{
		{"/v1/agent/hashed-agent/proxy/openrouter/chat/completions", "OWE_TOKEN_HASHED_AGENT", http.StatusOK},
		{"/v1/proxy/openrouter/chat/completions", "OWE_TOKEN_HASHED_AGENT", http.StatusOK},
		{"/v1/agent/hashed-agent/proxy/openrouter/chat/completions", "OWE_TOKEN_HASHED_AGENTX", http.StatusUnauthorized},
		{"/v1/agent/hashed-agent/proxy/openrouter/chat/completions", "", http.StatusUnauthorized},
		// The hash itself is not a valid token.
		{"/v1/agent/hashed-agent/proxy/openrouter/chat/completions", hex.EncodeToString(sum[:]), http.StatusUnauthorized},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", c.path, strings.NewReader(`{"model":"m"}`))
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		srv.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s token %q: got %d, want %d: %s", c.path, c.token, rec.Code, c.want, rec.Body.String())
		}
		if c.want == http.StatusOK && rec.Header().Get("X-Upstream-Auth-Echo") != "Bearer sk-or-v1-REAL-SECRET-KEY" {
			t.Errorf("%s: real credential not injected", c.path)
		}
	}
}

func TestLoadConfigRejectsBadTokenSHA256(t *testing.T) {
	for name, agent := range map[string]string{
		"not hex":    `{"token_sha256":"zz"}`,
		"short":      `{"token_sha256":"abcd"}`,
		"both forms": `{"token":"t","token_sha256":"` + strings.Repeat("a", 64) + `"}`,
	} {
		p := filepath.Join(t.TempDir(), "c.json")
		os.WriteFile(p, []byte(`{"agents":{"a":`+agent+`}}`), 0o600)
		if _, err := LoadConfig(p); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// A credential reference that names a KV mount is read from that mount, not openbao.kv_mount.
func TestCredentialFromExplicitMount(t *testing.T) {
	var got string
	bao := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "t", "lease_duration": 3600}})
			return
		}
		got = r.URL.Path
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{"api_key": "sk-tenant-" + strings.Split(r.URL.Path, "/")[2]}}})
	}))
	defer bao.Close()

	vc, err := NewVaultClient(OpenBaoConfig{Addr: bao.URL, RoleID: "r", SecretID: "s", KVMount: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Auth-Echo", r.Header.Get("Authorization"))
	}))
	defer upstream.Close()

	res := staticResolution{&Resolution{
		AgentName:  "a",
		Policy:     AgentPolicy{AllowedTargets: []string{"openrouter"}},
		Target:     &TargetConfig{BaseURL: upstream.URL, Host: "openrouter.ai", AuthHeader: "Authorization", AuthPrefix: "Bearer "},
		Credential: &CredRef{Mount: "tenantkv", Path: "tenants/o/egress/openrouter", Key: "api_key"},
	}}
	srv := NewServerWithResolver(res, vc, allowLoopbackUpstream)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/agent/a/proxy/openrouter/models", nil))
	if got != "/v1/tenantkv/data/tenants/o/egress/openrouter" || rec.Header().Get("X-Upstream-Auth-Echo") != "Bearer sk-tenant-tenantkv" {
		t.Errorf("read %q, injected %q", got, rec.Header().Get("X-Upstream-Auth-Echo"))
	}
}

// A required credential that cannot be read refuses the request instead of forwarding it
// with the agent's token.
func TestCredentialRequiredAndAuthorizationDropped(t *testing.T) {
	var seenAuth []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = append(seenAuth, r.Header.Get("Authorization"))
	}))
	defer upstream.Close()

	r := &Resolution{
		AgentName:          "a",
		Policy:             AgentPolicy{AllowedTargets: []string{"anthropic"}},
		Target:             &TargetConfig{BaseURL: upstream.URL, Host: "api.anthropic.com", AuthHeader: "x-api-key"},
		CredentialRequired: true,
		DropAuthorization:  true,
	}
	srv := NewServerWithResolver(staticResolution{r}, &mockVault{secrets: map[string]string{"p:k": "sk-ant"}}, allowLoopbackUpstream)

	send := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/v1/agent/a/proxy/anthropic/models", nil)
		req.Header.Set("Authorization", "Bearer OWE_TOKEN_X")
		srv.ServeHTTP(rec, req)
		return rec
	}
	if rec := send(); rec.Code != http.StatusBadGateway || len(seenAuth) != 0 {
		t.Fatalf("no credential: got %d, upstream calls %d", rec.Code, len(seenAuth))
	}
	r.Credential = &CredRef{Path: "p", Key: "k"}
	if rec := send(); rec.Code != http.StatusOK || len(seenAuth) != 1 || seenAuth[0] != "" {
		t.Fatalf("with credential: got %d, upstream Authorization %q", rec.Code, seenAuth)
	}
}

type staticResolution struct{ r *Resolution }

func (s staticResolution) Resolve(context.Context, ResolveRequest) (*Resolution, error) {
	return s.r, nil
}
