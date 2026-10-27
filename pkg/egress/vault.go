package egress

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// SecretProvider fetches credentials for egress targets.
type SecretProvider interface {
	GetSecret(ctx context.Context, path, key string) (string, error)
	Health(ctx context.Context) error
}

type cachedSecret struct {
	value     string
	expiresAt time.Time
}

// VaultClient connects to OpenBao via AppRole and caches secret values.
type VaultClient struct {
	addr        string
	httpClient  *http.Client
	roleID      string
	secretID    string
	approleFile string
	kvMount     string

	mu       sync.RWMutex
	token    string
	tokenExp time.Time
	cache    map[string]cachedSecret // "path:key" -> cached value
	cacheTTL time.Duration
}

// NewVaultClient creates and initializes a VaultClient.
func NewVaultClient(cfg OpenBaoConfig) (*VaultClient, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("openbao address is required")
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if cfg.CAFile != "" {
		caBytes, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("failed to append CA certs from %s", cfg.CAFile)
		}
		tlsConfig.RootCAs = pool
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		MaxIdleConns:    10,
		IdleConnTimeout: 90 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	vc := &VaultClient{
		addr:        strings.TrimRight(cfg.Addr, "/"),
		httpClient:  client,
		roleID:      cfg.RoleID,
		secretID:    cfg.SecretID,
		approleFile: cfg.AppRoleFile,
		kvMount:     strings.Trim(cmp.Or(cfg.KVMount, "kv"), "/"),
		cache:       make(map[string]cachedSecret),
		cacheTTL:    5 * time.Minute,
	}

	// Read approleFile if provided
	if vc.approleFile != "" && (vc.roleID == "" || vc.secretID == "") {
		data, err := os.ReadFile(vc.approleFile)
		if err != nil {
			return nil, fmt.Errorf("reading approle file: %w", err)
		}
		var ar struct {
			RoleID   string `json:"role_id"`
			SecretID string `json:"secret_id"`
		}
		if err := json.Unmarshal(data, &ar); err != nil {
			return nil, fmt.Errorf("parsing approle file: %w", err)
		}
		vc.roleID = ar.RoleID
		vc.secretID = ar.SecretID
	}

	return vc, nil
}

func (v *VaultClient) getToken(ctx context.Context) (string, error) {
	v.mu.RLock()
	if v.token != "" && time.Now().Before(v.tokenExp.Add(-2*time.Minute)) {
		t := v.token
		v.mu.RUnlock()
		return t, nil
	}
	v.mu.RUnlock()

	v.mu.Lock()
	defer v.mu.Unlock()

	// Double check under write lock
	if v.token != "" && time.Now().Before(v.tokenExp.Add(-2*time.Minute)) {
		return v.token, nil
	}

	if v.roleID == "" || v.secretID == "" {
		return "", fmt.Errorf("approle credentials not configured")
	}

	body, _ := json.Marshal(map[string]string{
		"role_id":   v.roleID,
		"secret_id": v.secretID,
	})

	req, err := http.NewRequestWithContext(ctx, "POST", v.addr+"/v1/auth/approle/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("approle login request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("approle login failed with status %d", resp.StatusCode)
	}

	var res struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", fmt.Errorf("decoding login response: %w", err)
	}

	v.token = res.Auth.ClientToken
	ttl := time.Duration(res.Auth.LeaseDuration) * time.Second
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}
	v.tokenExp = time.Now().Add(ttl)

	return v.token, nil
}

// GetSecret fetches a specific key from OpenBao KV v2 (with cache).
func (v *VaultClient) GetSecret(ctx context.Context, path, key string) (string, error) {
	cacheKey := path + ":" + key

	v.mu.RLock()
	c, ok := v.cache[cacheKey]
	if ok && time.Now().Before(c.expiresAt) {
		val := c.value
		v.mu.RUnlock()
		return val, nil
	}
	v.mu.RUnlock()

	token, err := v.getToken(ctx)
	if err != nil {
		return "", fmt.Errorf("obtaining vault token: %w", err)
	}

	cleanPath := strings.Trim(path, "/")
	reqURL := fmt.Sprintf("%s/v1/%s/data/%s", v.addr, v.kvMount, cleanPath)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching secret from vault: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault error %d reading %s", resp.StatusCode, path)
	}

	var res struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", fmt.Errorf("decoding secret payload: %w", err)
	}

	rawVal, exists := res.Data.Data[key]
	if !exists {
		return "", fmt.Errorf("key %q not found in path %q", key, path)
	}

	strVal := fmt.Sprintf("%v", rawVal)

	// Update cache
	v.mu.Lock()
	v.cache[cacheKey] = cachedSecret{
		value:     strVal,
		expiresAt: time.Now().Add(v.cacheTTL),
	}
	v.mu.Unlock()

	return strVal, nil
}

// Health checks OpenBao connectivity and seal status.
func (v *VaultClient) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", v.addr+"/v1/sys/health", nil)
	if err != nil {
		return err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != 429 {
		return fmt.Errorf("vault unhealthy: HTTP %d", resp.StatusCode)
	}
	return nil
}
