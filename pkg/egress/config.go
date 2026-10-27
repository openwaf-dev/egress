package egress

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Config defines the configuration for the OpenWAF Egress Gateway.
type Config struct {
	ListenAddr string                  `json:"listen_addr"` // e.g. ":8070"
	OpenBao    OpenBaoConfig           `json:"openbao"`
	Targets    map[string]TargetConfig `json:"targets"` // target_alias -> target config
	Agents     map[string]AgentConfig  `json:"agents"`  // agent_name -> agent policy
}

// OpenBaoConfig specifies connection parameters to OpenBao (or HashiCorp Vault).
type OpenBaoConfig struct {
	Addr        string `json:"addr"`         // e.g. "https://vault.example.com:8200"
	CAFile      string `json:"ca_file"`      // path to ca.crt (optional)
	AppRoleFile string `json:"approle_file"` // path to json with {role_id, secret_id}
	RoleID      string `json:"role_id"`      // inline role_id (optional if approle_file provided)
	SecretID    string `json:"secret_id"`    // inline secret_id (optional)
	KVMount     string `json:"kv_mount"`     // KV v2 mount, default "kv" (Vault's default is "secret")
}

// TargetConfig specifies the destination upstream service.
type TargetConfig struct {
	BaseURL    string `json:"base_url"`    // e.g. "https://openrouter.ai/api/v1"
	Host       string `json:"host"`        // e.g. "openrouter.ai"
	AuthHeader string `json:"auth_header"` // default "Authorization"
	AuthPrefix string `json:"auth_prefix"` // default "Bearer " when the header is Authorization, else none
}

// AgentConfig defines egress security policy for an AI agent.
type AgentConfig struct {
	Token             string             `json:"token"`              // expected placeholder or bearer token
	TokenSHA256       string             `json:"token_sha256"`       // or: hex SHA-256 of the token (keeps the token out of the file)
	AllowedTargets    []string           `json:"allowed_targets"`    // e.g. ["openrouter", "openai"]
	CredentialMapping map[string]CredRef `json:"credential_mapping"` // target_alias -> secret in OpenBao
	EnforceInjection  bool               `json:"enforce_injection"`  // scan request body for prompt-injection attacks
	BlockDLP          bool               `json:"block_dlp"`          // scan for leaked credentials / credit cards
}

// CredRef references a secret path (under the KV v2 mount) and key.
type CredRef struct {
	Path string `json:"path"` // e.g. "agents/support" → GET /v1/<kv_mount>/data/agents/support
	Key  string `json:"key"`  // e.g. "OPENROUTER_API_KEY"
	// Mount overrides openbao.kv_mount for this secret (set by a Resolver, e.g. from the
	// control-plane document; not read from the config file).
	Mount string `json:"-"`
}

// LoadConfig reads and parses a JSON config file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config json: %w", err)
	}

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:8070"
	}
	if cfg.OpenBao.KVMount == "" {
		cfg.OpenBao.KVMount = "kv"
	}

	// Apply target defaults
	for k, t := range cfg.Targets {
		if t.AuthHeader == "" {
			t.AuthHeader = "Authorization"
		}
		if t.AuthPrefix == "" && strings.EqualFold(t.AuthHeader, "Authorization") {
			t.AuthPrefix = "Bearer "
		}
		cfg.Targets[k] = t
	}
	if err := cfg.validateAgents(); err != nil {
		return nil, err
	}

	return &cfg, nil
}
