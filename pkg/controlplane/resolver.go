package controlplane

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/openwaf-dev/egress/pkg/egress"
)

// DocumentVersion is the node configuration document version this package understands.
const DocumentVersion = 1

// CredentialKey is the KV v2 key holding a target's upstream API key.
const CredentialKey = "api_key"

// Document is the node configuration served by GET /v1/egress/node/config.
type Document struct {
	Version     int       `json:"version"`
	NodeID      string    `json:"node_id"`
	Serial      int64     `json:"serial"`
	GeneratedAt time.Time `json:"generated_at"`
	KVMount     string    `json:"kv_mount"`
	Tenants     []Tenant  `json:"tenants"`
}

// Tenant is one organization with the egress feature.
type Tenant struct {
	OrgID   string            `json:"org_id"`
	Targets map[string]Target `json:"targets"`
	Agents  []Agent           `json:"agents"`
}

// Target is a provider the tenant's agents may use. Credentials are never in the document.
type Target struct {
	BaseURL    string `json:"base_url"`
	Host       string `json:"host"`
	AuthHeader string `json:"auth_header"`
	AuthPrefix string `json:"auth_prefix"`
	Credential bool   `json:"credential"` // a credential is stored for the target
}

// Agent is one enabled egress agent; it is identified by the SHA-256 of its token.
type Agent struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	TokenSHA256      string   `json:"token_sha256"`
	AllowedTargets   []string `json:"allowed_targets"`
	EnforceInjection bool     `json:"enforce_injection"`
	BlockDLP         bool     `json:"block_dlp"`
}

var (
	reUUID      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reTargetID  = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	reAgentName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	reTokenHash = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reKVMount   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}(?:/[A-Za-z0-9_-]{1,64}){0,3}$`)
)

type tenantEntry struct {
	orgID   string
	targets map[string]egress.TargetConfig
	creds   map[string]bool
}

type agentEntry struct {
	tenant *tenantEntry
	agent  Agent
	hash   [sha256.Size]byte
}

// snapshot is an immutable index of one accepted document.
type snapshot struct {
	serial  int64
	kvMount string
	byToken map[[sha256.Size]byte]*agentEntry
	agents  int
	targets int
}

// Resolver resolves agents from the node configuration document it polls from the control
// plane. It implements egress.Resolver and egress.ResolverStats. Until a first document is
// accepted every request answers 503. Afterwards the last good document stays in force across
// network and server errors for at most MaxStale since the control plane last confirmed it
// (200 or 304); a 401 or 403 from the control plane (node revoked or key replaced) withdraws it
// at once.
type Resolver struct {
	client   *Client
	interval time.Duration
	maxStale time.Duration
	now      func() time.Time
	cur      atomic.Pointer[snapshot]
	lastOK   atomic.Int64 // unix nanoseconds of the last 200/304; 0 before any
}

// ResolverOptions tunes a Resolver; zero values take the defaults.
type ResolverOptions struct {
	Interval time.Duration // poll interval (default 15s)
	MaxStale time.Duration // longest time a document stays in force unconfirmed (default 10m)
}

// NewResolver returns a Resolver that polls the control plane through client.
func NewResolver(client *Client, opts ResolverOptions) *Resolver {
	if opts.Interval <= 0 {
		opts.Interval = 15 * time.Second
	}
	if opts.MaxStale <= 0 {
		opts.MaxStale = 10 * time.Minute
	}
	return &Resolver{client: client, interval: opts.Interval, maxStale: opts.MaxStale, now: time.Now}
}

// current returns the document in force, or an error when there is none or it is stale.
func (r *Resolver) current() (*snapshot, error) {
	snap := r.cur.Load()
	if snap == nil {
		return nil, errors.New("no control plane configuration in force")
	}
	if age := r.now().Sub(time.Unix(0, r.lastOK.Load())); age > r.maxStale {
		return nil, fmt.Errorf("control plane configuration serial %d is stale: last confirmed %s ago", snap.serial, age.Round(time.Second))
	}
	return snap, nil
}

// Ready reports whether a document is in force and not stale.
func (r *Resolver) Ready() bool {
	_, err := r.current()
	return err == nil
}

// Serial returns the serial of the document held (0 when none).
func (r *Resolver) Serial() int64 {
	if s := r.cur.Load(); s != nil {
		return s.serial
	}
	return 0
}

// KVMount returns the KV v2 mount of the document held.
func (r *Resolver) KVMount() string {
	if s := r.cur.Load(); s != nil {
		return s.kvMount
	}
	return ""
}

// Counts implements egress.ResolverStats.
func (r *Resolver) Counts() (agents, targets int) {
	if s := r.cur.Load(); s != nil {
		return s.agents, s.targets
	}
	return 0, 0
}

// Run polls until ctx is done: immediately, then every interval; after a failure it retries
// sooner (1s doubling up to the interval).
func (r *Resolver) Run(ctx context.Context) {
	backoff := time.Second
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		next := r.interval
		if _, err := r.Refresh(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[EGRESS] control plane config: %v (serial in force: %d)", err, r.Serial())
			next = min(backoff, r.interval)
			backoff = min(backoff*2, r.interval)
		} else {
			backoff = time.Second
		}
		timer.Reset(next)
	}
}

// Refresh fetches the document once. It reports whether a new document was accepted. On a
// 401 or 403 the document in force is withdrawn; on any other error it is kept (until stale).
func (r *Resolver) Refresh(ctx context.Context) (bool, error) {
	cur := r.cur.Load()
	since := int64(0)
	if cur != nil {
		since = cur.serial
	}
	status, body, err := r.client.do(ctx, http.MethodGet, ConfigPath, url.Values{"since_serial": {strconv.FormatInt(since, 10)}}, nil)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusNotModified:
		if cur == nil {
			return false, errors.New("control plane answered 304 before any document was received")
		}
		r.lastOK.Store(r.now().UnixNano())
		return false, nil
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		if cur != nil {
			log.Printf("[EGRESS] control plane refused this node (HTTP %d): configuration serial %d withdrawn, requests answer 503", status, cur.serial)
		}
		r.cur.Store(nil)
		r.lastOK.Store(0)
		return false, errors.New(errorMessage(status, body))
	default:
		return false, errors.New(errorMessage(status, body))
	}
	var doc Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return false, fmt.Errorf("decoding document: %w", err)
	}
	snap, err := r.index(&doc)
	if err != nil {
		return false, err
	}
	if cur != nil && snap.serial < cur.serial {
		return false, fmt.Errorf("document serial %d is older than serial %d in force; kept", snap.serial, cur.serial)
	}
	r.cur.Store(snap)
	r.lastOK.Store(r.now().UnixNano())
	if cur == nil || cur.serial != snap.serial {
		log.Printf("[EGRESS] control plane config serial %d: %d agents, %d targets", snap.serial, snap.agents, snap.targets)
	}
	return true, nil
}

// index validates doc and builds its lookup tables. Top-level problems reject the document;
// an invalid tenant, target or agent is skipped with a log line.
func (r *Resolver) index(doc *Document) (*snapshot, error) {
	if doc.Version != DocumentVersion {
		return nil, fmt.Errorf("unsupported document version %d", doc.Version)
	}
	if doc.NodeID != r.client.NodeID() {
		return nil, fmt.Errorf("document is for node %q, not %q", doc.NodeID, r.client.NodeID())
	}
	if !reKVMount.MatchString(doc.KVMount) {
		return nil, fmt.Errorf("invalid kv_mount %q", doc.KVMount)
	}
	snap := &snapshot{serial: doc.Serial, kvMount: doc.KVMount, byToken: map[[sha256.Size]byte]*agentEntry{}}
	seenOrg := map[string]bool{}
	dupTokens := map[[sha256.Size]byte]bool{}
	for _, t := range doc.Tenants {
		if !reUUID.MatchString(t.OrgID) || seenOrg[strings.ToLower(t.OrgID)] {
			log.Printf("[EGRESS] control plane config: skipping tenant with invalid or repeated org_id %q", t.OrgID)
			continue
		}
		seenOrg[strings.ToLower(t.OrgID)] = true
		te := &tenantEntry{orgID: t.OrgID, targets: map[string]egress.TargetConfig{}, creds: map[string]bool{}}
		for id, tg := range t.Targets {
			tc, err := targetConfig(id, tg)
			if err != nil {
				log.Printf("[EGRESS] control plane config: tenant %s: skipping target %q: %v", t.OrgID, id, err)
				continue
			}
			te.targets[id] = tc
			te.creds[id] = tg.Credential
		}
		snap.targets += len(te.targets)
		for _, a := range t.Agents {
			if !reUUID.MatchString(a.ID) || !reAgentName.MatchString(a.Name) || !reTokenHash.MatchString(a.TokenSHA256) {
				log.Printf("[EGRESS] control plane config: tenant %s: skipping invalid agent %q", t.OrgID, a.ID)
				continue
			}
			var h [sha256.Size]byte
			hex.Decode(h[:], []byte(a.TokenSHA256))
			if _, dup := snap.byToken[h]; dup || dupTokens[h] {
				// Two agents with one token cannot be told apart: neither is served.
				log.Printf("[EGRESS] control plane config: tenant %s: agent %s shares its token hash with another agent; both disabled", t.OrgID, a.ID)
				delete(snap.byToken, h)
				dupTokens[h] = true
				continue
			}
			allowed := make([]string, 0, len(a.AllowedTargets))
			for _, id := range a.AllowedTargets {
				if reTargetID.MatchString(id) {
					allowed = append(allowed, id)
				}
			}
			a.AllowedTargets = allowed
			snap.byToken[h] = &agentEntry{tenant: te, agent: a, hash: h}
		}
	}
	snap.agents = len(snap.byToken)
	return snap, nil
}

// targetConfig validates a document target: an https URL on a DNS name (no IP literal,
// userinfo, query or fragment) whose host matches the declared host.
func targetConfig(id string, t Target) (egress.TargetConfig, error) {
	if !reTargetID.MatchString(id) {
		return egress.TargetConfig{}, errors.New("invalid target id")
	}
	u, err := url.Parse(t.BaseURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return egress.TargetConfig{}, fmt.Errorf("invalid base_url %q", t.BaseURL)
	}
	if net.ParseIP(u.Hostname()) != nil {
		return egress.TargetConfig{}, fmt.Errorf("base_url %q uses an IP literal", t.BaseURL)
	}
	declared := t.Host
	if h, _, err := net.SplitHostPort(declared); err == nil {
		declared = h
	}
	if declared != "" && !strings.EqualFold(declared, u.Hostname()) {
		return egress.TargetConfig{}, fmt.Errorf("host %q does not match base_url %q", t.Host, t.BaseURL)
	}
	header := t.AuthHeader
	if header == "" {
		header = "Authorization"
	}
	if strings.ContainsAny(header, " \t\r\n:") || strings.ContainsAny(t.AuthPrefix, "\r\n") {
		return egress.TargetConfig{}, errors.New("invalid auth_header or auth_prefix")
	}
	// The SSRF check and the upstream Host header both use the URL's own authority.
	return egress.TargetConfig{BaseURL: t.BaseURL, Host: u.Host, AuthHeader: header, AuthPrefix: t.AuthPrefix}, nil
}

// CredentialPath returns the KV v2 path of a tenant's target credential. It is always derived
// here, never taken from the document.
func CredentialPath(orgID, target string) string {
	return "tenants/" + orgID + "/egress/" + target
}

// Resolve implements egress.Resolver: the bearer token is looked up by SHA-256, and the agent
// name in /v1/agent/<name>/ must be that agent's name. X-OpenWAF-Agent is ignored.
func (r *Resolver) Resolve(_ context.Context, req egress.ResolveRequest) (*egress.Resolution, error) {
	snap, err := r.current()
	if err != nil {
		return nil, err
	}
	if req.Authorization == "" {
		return nil, &egress.ResolveError{Status: http.StatusUnauthorized, Code: "token_required", Message: "Agent token required: Authorization: Bearer <token>"}
	}
	h := sha256.Sum256([]byte(strings.TrimPrefix(req.Authorization, "Bearer ")))
	e := snap.byToken[h]
	if e == nil || subtle.ConstantTimeCompare(e.hash[:], h[:]) != 1 {
		return nil, &egress.ResolveError{Status: http.StatusUnauthorized, Code: "invalid_token", Message: "Agent token is not valid"}
	}
	if req.RouteAgent != e.agent.Name {
		return nil, &egress.ResolveError{Status: http.StatusUnauthorized, Code: "unauthorized_agent",
			Message: "The route must name the token's agent: /v1/agent/<agent>/proxy/<target>/…"}
	}
	res := &egress.Resolution{
		TenantID:  e.tenant.orgID,
		AgentID:   e.agent.ID,
		AgentName: e.agent.Name,
		Policy: egress.AgentPolicy{
			AllowedTargets:   e.agent.AllowedTargets,
			EnforceInjection: e.agent.EnforceInjection,
			BlockDLP:         e.agent.BlockDLP,
		},
		CredentialRequired: true,
		DropAuthorization:  true,
	}
	if t, ok := e.tenant.targets[req.Target]; ok {
		res.Target = &t
		if e.tenant.creds[req.Target] {
			res.Credential = &egress.CredRef{Mount: snap.kvMount, Path: CredentialPath(e.tenant.orgID, req.Target), Key: CredentialKey}
		}
	}
	return res, nil
}
