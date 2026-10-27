package egress

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Header-specific providers (Anthropic's x-api-key) get the bare key; Authorization gets Bearer.
func TestLoadConfigAuthPrefixDefaults(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(p, []byte(`{"targets":{
		"openai":{"base_url":"https://api.openai.com/v1","host":"api.openai.com"},
		"anthropic":{"base_url":"https://api.anthropic.com/v1","host":"api.anthropic.com","auth_header":"x-api-key","auth_prefix":""}}}`), 0o600)
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Targets["openai"]; got.AuthHeader != "Authorization" || got.AuthPrefix != "Bearer " {
		t.Errorf("openai defaults: %+v", got)
	}
	if got := cfg.Targets["anthropic"]; got.AuthHeader != "x-api-key" || got.AuthPrefix != "" {
		t.Errorf("anthropic must send the bare key: %+v", got)
	}
	if cfg.ListenAddr != "127.0.0.1:8070" || cfg.OpenBao.KVMount != "kv" {
		t.Errorf("defaults: listen %q kv_mount %q", cfg.ListenAddr, cfg.OpenBao.KVMount)
	}
}

// Secrets are read from /v1/<kv_mount>/data/<path>.
func TestVaultReadsFromConfiguredMount(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/auth/approle/login" {
			json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": "t", "lease_duration": 3600}})
			return
		}
		got = r.URL.Path
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": map[string]any{"OPENROUTER_API_KEY": "sk-test"}}})
	}))
	defer srv.Close()

	for mount, want := range map[string]string{"": "/v1/kv/data/agents/support", "secret": "/v1/secret/data/agents/support"} {
		vc, err := NewVaultClient(OpenBaoConfig{Addr: srv.URL, RoleID: "r", SecretID: "s", KVMount: mount})
		if err != nil {
			t.Fatal(err)
		}
		val, err := vc.GetSecret(context.Background(), "/agents/support/", "OPENROUTER_API_KEY")
		if err != nil || val != "sk-test" || got != want {
			t.Errorf("mount %q: got path %q value %q err %v, want path %q", mount, got, val, err, want)
		}
	}
}
