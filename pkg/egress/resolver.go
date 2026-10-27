package egress

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

// ResolveRequest is what the gateway knows about a proxied request before applying a policy.
type ResolveRequest struct {
	RouteAgent    string // agent name from /v1/agent/<name>/proxy/…; empty for /v1/proxy/…
	HeaderAgent   string // X-OpenWAF-Agent request header (may be ignored by a Resolver)
	Authorization string // raw Authorization request header
	Target        string // target alias from the route
}

// AgentPolicy is the security policy applied to one agent's requests.
type AgentPolicy struct {
	AllowedTargets   []string // target aliases; "*" allows every target
	EnforceInjection bool     // refuse bodies with prompt-injection patterns
	BlockDLP         bool     // refuse bodies with secrets or card numbers
}

// Resolution is the policy, destination and credential that apply to one identified agent.
type Resolution struct {
	TenantID  string // owning tenant (organization id); empty in static config mode
	AgentID   string // stable agent id; the agent name in static config mode
	AgentName string // agent name as used in /v1/agent/<name>/
	Policy    AgentPolicy

	// Target is the destination for the requested alias, nil when the alias is unknown.
	Target *TargetConfig
	// Credential locates the upstream key in the secret store, nil when none is mapped.
	Credential *CredRef
	// CredentialRequired refuses the request when no credential can be injected instead of
	// forwarding it without one.
	CredentialRequired bool
	// DropAuthorization removes the caller's Authorization header (the agent token) from the
	// upstream request.
	DropAuthorization bool
}

// ResolveError refuses a request before an agent is identified (no tenant is known yet).
type ResolveError struct {
	Status  int    // HTTP status, e.g. 401
	Code    string // error code returned to the caller, e.g. "invalid_token"
	Message string
}

func (e *ResolveError) Error() string { return e.Code + ": " + e.Message }

// Resolver maps a request to the agent policy that governs it. Implementations must be safe
// for concurrent use. A refusal is returned as *ResolveError; any other error answers 503.
type Resolver interface {
	Resolve(ctx context.Context, req ResolveRequest) (*Resolution, error)
}

// ResolverStats is optionally implemented by a Resolver to report sizes on /health.
type ResolverStats interface {
	Counts() (agents, targets int)
}

// bearerToken returns the Authorization value without its "Bearer " prefix.
func bearerToken(authorization string) string {
	return strings.TrimPrefix(authorization, "Bearer ")
}

// tokenMatches compares the presented token with the agent's token or token_sha256 in
// constant time (both sides are hashed, so the comparison does not depend on token length).
func (a *AgentConfig) tokenMatches(token string) bool {
	got := sha256.Sum256([]byte(token))
	var want []byte
	if a.TokenSHA256 != "" {
		w, err := hex.DecodeString(strings.ToLower(a.TokenSHA256))
		if err != nil || len(w) != sha256.Size {
			return false
		}
		want = w
	} else {
		w := sha256.Sum256([]byte(a.Token))
		want = w[:]
	}
	return subtle.ConstantTimeCompare(got[:], want) == 1
}

func (a *AgentConfig) hasToken() bool { return a.Token != "" || a.TokenSHA256 != "" }

// Resolve implements Resolver for the static config file: the agent is named by the
// X-OpenWAF-Agent header or the route, or else found by its token; whenever the agent has a
// token (token or token_sha256), the request must present it.
func (c *Config) Resolve(_ context.Context, req ResolveRequest) (*Resolution, error) {
	name := req.RouteAgent
	if req.HeaderAgent != "" {
		name = req.HeaderAgent
	}
	token := bearerToken(req.Authorization)

	var agent AgentConfig
	found := false
	if name != "" {
		agent, found = c.Agents[name]
	} else if req.Authorization != "" {
		for n, a := range c.Agents {
			if a.tokenMatches(token) {
				agent, name, found = a, n, true
				break
			}
		}
	}
	if !found {
		return nil, &ResolveError{http.StatusUnauthorized, "unauthorized_agent", "Agent not identified or token mismatch"}
	}

	// Require the agent's placeholder token whenever one is configured, regardless of how
	// the agent was identified (route, X-OpenWAF-Agent header, or token lookup). A caller
	// who knows only the agent name must not be able to use the gateway: doing so would
	// also hand them the real upstream credential.
	if agent.hasToken() {
		if req.Authorization == "" {
			return nil, &ResolveError{http.StatusUnauthorized, "token_required", "Agent placeholder token required: Authorization: Bearer <token>"}
		}
		if !agent.tokenMatches(token) {
			return nil, &ResolveError{http.StatusUnauthorized, "invalid_token", "Agent placeholder token did not match policy"}
		}
	}

	res := &Resolution{
		AgentID:   name,
		AgentName: name,
		Policy: AgentPolicy{
			AllowedTargets:   agent.AllowedTargets,
			EnforceInjection: agent.EnforceInjection,
			BlockDLP:         agent.BlockDLP,
		},
		// The agent's placeholder token never leaves the gateway, also when the target takes
		// its key in another header (x-api-key, x-goog-api-key).
		DropAuthorization: agent.hasToken(),
	}
	if t, ok := c.Targets[req.Target]; ok {
		res.Target = &t
	}
	if ref, ok := agent.CredentialMapping[req.Target]; ok {
		res.Credential = &ref
	}
	return res, nil
}

// Counts implements ResolverStats.
func (c *Config) Counts() (agents, targets int) { return len(c.Agents), len(c.Targets) }

// validateAgents checks token_sha256 values when the config is loaded.
func (c *Config) validateAgents() error {
	for name, a := range c.Agents {
		if a.TokenSHA256 == "" {
			continue
		}
		if a.Token != "" {
			return fmt.Errorf("agent %q: set token or token_sha256, not both", name)
		}
		if b, err := hex.DecodeString(a.TokenSHA256); err != nil || len(b) != sha256.Size {
			return fmt.Errorf("agent %q: token_sha256 must be 64 hex characters", name)
		}
	}
	return nil
}
