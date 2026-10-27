package controlplane

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openwaf-dev/egress/pkg/egress"
)

const (
	testNode = "egress-1"
	orgA     = "11111111-2222-4333-8444-555555555555"
	orgB     = "99999999-8888-4777-8666-555555555555"
	agentA   = "aaaaaaaa-0000-4000-8000-000000000001"
	agentB   = "bbbbbbbb-0000-4000-8000-000000000002"
)

func tokenHash(tok string) string {
	s := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(s[:])
}

// fakeControlPlane emulates OpenWAF Cloud's egressnode v1 endpoints and verifies every
// request signature with its own implementation of openwaf-node-request/v1.
type fakeControlPlane struct {
	t   *testing.T
	pub ed25519.PublicKey

	mu         sync.Mutex
	nonces     map[string]bool
	sinces     []string
	doc        map[string]any
	failNext   int // answer failStatus (default 503) to this many requests
	failStatus int
	batches    [][]byte
}

var reNonce = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (f *fakeControlPlane) verify(r *http.Request, body []byte) int {
	sum := sha256.Sum256(f.pub)
	if r.Header.Get("X-OpenWAF-Node-ID") != testNode || r.Header.Get("X-OpenWAF-Node-Key-ID") != hex.EncodeToString(sum[:])[:16] {
		return http.StatusForbidden
	}
	ts, err := strconv.ParseInt(r.Header.Get("X-OpenWAF-Timestamp"), 10, 64)
	if err != nil || time.Since(time.Unix(ts, 0)).Abs() > 300*time.Second {
		return http.StatusUnauthorized
	}
	nonce := r.Header.Get("X-OpenWAF-Nonce")
	if !reNonce.MatchString(nonce) || f.nonces[nonce] {
		return http.StatusUnauthorized
	}
	f.nonces[nonce] = true
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	bodySum := sha256.Sum256(body)
	input := "openwaf-node-request/v1\n" + r.Method + "\n" + path + "\n" + r.URL.RawQuery + "\n" +
		r.Header.Get("X-OpenWAF-Timestamp") + "\n" + nonce + "\n" + testNode + "\n" +
		r.Header.Get("X-OpenWAF-Node-Key-ID") + "\n" + hex.EncodeToString(bodySum[:])
	sig, ok := strings.CutPrefix(r.Header.Get("X-OpenWAF-Signature"), "ed25519=")
	raw, err := base64.StdEncoding.DecodeString(sig)
	if !ok || err != nil || !ed25519.Verify(f.pub, []byte(input), raw) {
		return http.StatusUnauthorized
	}
	return 0
}

func (f *fakeControlPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if code := f.verify(r, body); code != 0 {
		f.t.Errorf("%s %s: signature check failed with %d", r.Method, r.URL, code)
		w.WriteHeader(code)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == ConfigPath:
		since := r.URL.Query().Get("since_serial")
		f.sinces = append(f.sinces, since)
		if f.failNext > 0 {
			f.failNext--
			w.WriteHeader(cmp.Or(f.failStatus, http.StatusServiceUnavailable))
			return
		}
		if since == fmt.Sprint(f.doc["serial"]) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		json.NewEncoder(w).Encode(f.doc)
	case r.Method == "POST" && r.URL.Path == EventsPath:
		f.batches = append(f.batches, body)
		if f.failNext > 0 {
			f.failNext--
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var b struct {
			BatchID string            `json:"batch_id"`
			Events  []json.RawMessage `json:"events"`
		}
		json.Unmarshal(body, &b)
		json.NewEncoder(w).Encode(map[string]any{"batch_id": b.BatchID, "accepted": len(b.Events), "dropped": 0, "duplicate": false})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func testDoc(serial int) map[string]any {
	return map[string]any{
		"version": 1, "node_id": testNode, "serial": serial, "generated_at": "2026-10-27T10:00:00Z", "kv_mount": "kv",
		"tenants": []any{
			map[string]any{"org_id": orgA,
				"targets": map[string]any{
					"openrouter": map[string]any{"base_url": "https://openrouter.ai/api/v1", "host": "openrouter.ai", "auth_header": "Authorization", "auth_prefix": "Bearer ", "credential": true},
					"anthropic":  map[string]any{"base_url": "https://api.anthropic.com/v1", "host": "api.anthropic.com", "auth_header": "x-api-key", "auth_prefix": "", "credential": false},
					"bad":        map[string]any{"base_url": "https://10.0.0.1/v1", "host": "10.0.0.1", "credential": true},
				},
				"agents": []any{map[string]any{"id": agentA, "name": "support-bot", "token_sha256": tokenHash("OWE_TOKEN_A"),
					"allowed_targets": []string{"openrouter", "anthropic", "*"}, "enforce_injection": true, "block_dlp": true}}},
			map[string]any{"org_id": orgB,
				"targets": map[string]any{
					"openai": map[string]any{"base_url": "https://api.openai.com/v1", "host": "api.openai.com", "auth_header": "Authorization", "auth_prefix": "Bearer ", "credential": true},
					"groq":   map[string]any{"base_url": "https://api.groq.com/openai/v1", "host": "api.groq.com", "auth_header": "Authorization", "auth_prefix": "Bearer ", "credential": true},
				},
				"agents": []any{map[string]any{"id": agentB, "name": "support-bot", "token_sha256": tokenHash("OWE_TOKEN_B"),
					"allowed_targets": []string{"openai"}, "enforce_injection": false, "block_dlp": false}}},
		},
	}
}

func setup(t *testing.T) (*fakeControlPlane, *Client) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	f := &fakeControlPlane{t: t, pub: pub, nonces: map[string]bool{}, doc: testDoc(42)}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	signer, err := NewSigner(testNode, priv)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(srv.URL, signer, nil)
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

func TestConfigPollingKeepsLastGoodDocument(t *testing.T) {
	f, c := setup(t)
	r := NewResolver(c, ResolverOptions{Interval: time.Hour})
	ctx := context.Background()

	if _, err := r.Resolve(ctx, egress.ResolveRequest{RouteAgent: "support-bot", Authorization: "Bearer OWE_TOKEN_A", Target: "openrouter"}); err == nil {
		t.Fatal("resolved before any document")
	}
	if changed, err := r.Refresh(ctx); err != nil || !changed || r.Serial() != 42 || r.KVMount() != "kv" {
		t.Fatalf("first refresh: changed %v err %v serial %d", changed, err, r.Serial())
	}
	if changed, err := r.Refresh(ctx); err != nil || changed {
		t.Fatalf("304 refresh: changed %v err %v", changed, err)
	}
	f.failNext = 1
	if _, err := r.Refresh(ctx); err == nil || r.Serial() != 42 {
		t.Fatalf("a failed refresh must keep serial 42: err %v serial %d", err, r.Serial())
	}
	f.doc = map[string]any{"version": 1, "node_id": "egress-other", "serial": 43, "kv_mount": "kv"}
	if _, err := r.Refresh(ctx); err == nil || r.Serial() != 42 {
		t.Fatalf("another node's document must be refused: err %v serial %d", err, r.Serial())
	}
	f.doc = testDoc(44)
	if changed, err := r.Refresh(ctx); err != nil || !changed || r.Serial() != 44 {
		t.Fatalf("new document: changed %v err %v serial %d", changed, err, r.Serial())
	}
	if want := []string{"0", "42", "42", "42", "42"}; strings.Join(f.sinces, ",") != strings.Join(want, ",") {
		t.Errorf("since_serial sequence %v, want %v", f.sinces, want)
	}
	if agents, targets := r.Counts(); agents != 2 || targets != 4 {
		t.Errorf("counts: %d agents %d targets (the IP-literal target is skipped)", agents, targets)
	}
}

// A document the control plane stops confirming stops being used after MaxStale; a 200 or 304
// confirms it again.
func TestConfigGoesStale(t *testing.T) {
	f, c := setup(t)
	r := NewResolver(c, ResolverOptions{Interval: time.Hour, MaxStale: 10 * time.Minute})
	now := time.Now()
	r.now = func() time.Time { return now }
	ctx := context.Background()
	req := egress.ResolveRequest{RouteAgent: "support-bot", Authorization: "Bearer OWE_TOKEN_A", Target: "openrouter"}
	if _, err := r.Refresh(ctx); err != nil {
		t.Fatal(err)
	}

	now = now.Add(9 * time.Minute)
	f.failNext = 1
	if _, err := r.Refresh(ctx); err == nil {
		t.Fatal("503 not reported")
	}
	if _, err := r.Resolve(ctx, req); err != nil || !r.Ready() {
		t.Fatalf("within max stale: %v", err)
	}
	now = now.Add(2 * time.Minute) // 11 min since the last 200
	_, err := r.Resolve(ctx, req)
	if _, refusal := err.(*egress.ResolveError); err == nil || refusal || r.Ready() {
		t.Fatalf("stale document: err %v ready %v; want a non-refusal error (503)", err, r.Ready())
	}
	if changed, err := r.Refresh(ctx); err != nil || changed {
		t.Fatalf("304: changed %v err %v", changed, err)
	}
	if _, err := r.Resolve(ctx, req); err != nil || !r.Ready() {
		t.Fatalf("a 304 must confirm the document again: %v", err)
	}
}

// 401 or 403 from the control plane withdraws the document at once.
func TestConfigWithdrawnOnAuthFailure(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		f, c := setup(t)
		r := NewResolver(c, ResolverOptions{Interval: time.Hour})
		ctx := context.Background()
		if _, err := r.Refresh(ctx); err != nil {
			t.Fatal(err)
		}
		f.failNext, f.failStatus = 1, status
		if _, err := r.Refresh(ctx); err == nil {
			t.Fatalf("%d not reported", status)
		}
		_, err := r.Resolve(ctx, egress.ResolveRequest{RouteAgent: "support-bot", Authorization: "Bearer OWE_TOKEN_A", Target: "openrouter"})
		if _, refusal := err.(*egress.ResolveError); err == nil || refusal || r.Ready() || r.Serial() != 0 {
			t.Fatalf("%d: err %v ready %v serial %d; want the document withdrawn", status, err, r.Ready(), r.Serial())
		}
		// The next good answer restores service; since_serial starts over from 0.
		if changed, err := r.Refresh(ctx); err != nil || !changed || !r.Ready() || f.sinces[len(f.sinces)-1] != "0" {
			t.Fatalf("%d: recovery: changed %v err %v sinces %v", status, changed, err, f.sinces)
		}
	}
}

// A document older than the one in force is refused.
func TestConfigSerialNeverGoesBack(t *testing.T) {
	f, c := setup(t)
	r := NewResolver(c, ResolverOptions{Interval: time.Hour})
	ctx := context.Background()
	if _, err := r.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	f.doc = testDoc(41)
	f.doc["tenants"] = []any{}
	if changed, err := r.Refresh(ctx); err == nil || changed || r.Serial() != 42 {
		t.Fatalf("older serial: changed %v err %v serial %d", changed, err, r.Serial())
	}
	if agents, _ := r.Counts(); agents != 2 {
		t.Errorf("the document in force was replaced: %d agents", agents)
	}
}

func TestResolveByToken(t *testing.T) {
	_, c := setup(t)
	r := NewResolver(c, ResolverOptions{Interval: time.Hour})
	ctx := context.Background()
	if _, err := r.Refresh(ctx); err != nil {
		t.Fatal(err)
	}

	res, err := r.Resolve(ctx, egress.ResolveRequest{RouteAgent: "support-bot", HeaderAgent: "someone-else", Authorization: "Bearer OWE_TOKEN_A", Target: "openrouter"})
	if err != nil {
		t.Fatal(err)
	}
	if res.TenantID != orgA || res.AgentID != agentA || res.AgentName != "support-bot" || !res.Policy.EnforceInjection || !res.Policy.BlockDLP ||
		!res.CredentialRequired || !res.DropAuthorization || res.Target == nil || res.Target.Host != "openrouter.ai" {
		t.Fatalf("resolution %+v", res)
	}
	if want := (egress.CredRef{Mount: "kv", Path: "tenants/" + orgA + "/egress/openrouter", Key: "api_key"}); res.Credential == nil || *res.Credential != want {
		t.Errorf("credential %+v, want %+v", res.Credential, want)
	}
	if strings.Join(res.Policy.AllowedTargets, ",") != "openrouter,anthropic" {
		t.Errorf("allowed targets %v (\"*\" must be dropped)", res.Policy.AllowedTargets)
	}

	// The same agent name in another tenant is told apart by its token.
	res, err = r.Resolve(ctx, egress.ResolveRequest{RouteAgent: "support-bot", Authorization: "Bearer OWE_TOKEN_B", Target: "openai"})
	if err != nil || res.TenantID != orgB || res.AgentID != agentB || res.Credential.Path != "tenants/"+orgB+"/egress/openai" {
		t.Fatalf("tenant B: %+v %v", res, err)
	}
	// Tenant A's targets are not tenant B's.
	if res, _ := r.Resolve(ctx, egress.ResolveRequest{RouteAgent: "support-bot", Authorization: "Bearer OWE_TOKEN_B", Target: "openrouter"}); res.Target != nil || res.Credential != nil {
		t.Errorf("tenant B resolved tenant A's target: %+v", res)
	}
	// No stored credential: nothing to read, the request will be refused.
	if res, _ := r.Resolve(ctx, egress.ResolveRequest{RouteAgent: "support-bot", Authorization: "Bearer OWE_TOKEN_A", Target: "anthropic"}); res.Credential != nil || !res.CredentialRequired {
		t.Errorf("anthropic: %+v", res)
	}

	for name, req := range map[string]egress.ResolveRequest{
		"wrong route name": {RouteAgent: "billing-bot", Authorization: "Bearer OWE_TOKEN_A", Target: "openrouter"},
		"no route name":    {HeaderAgent: "support-bot", Authorization: "Bearer OWE_TOKEN_A", Target: "openrouter"},
		"unknown token":    {RouteAgent: "support-bot", Authorization: "Bearer OWE_TOKEN_C", Target: "openrouter"},
		"token hash":       {RouteAgent: "support-bot", Authorization: "Bearer " + tokenHash("OWE_TOKEN_A"), Target: "openrouter"},
		"no token":         {RouteAgent: "support-bot", Target: "openrouter"},
	} {
		_, err := r.Resolve(ctx, req)
		re, ok := err.(*egress.ResolveError)
		if !ok || re.Status != http.StatusUnauthorized {
			t.Errorf("%s: got %v, want 401", name, err)
		}
	}
}

// End to end through the gateway: a refused request of a tenant agent is reported, and a
// wrong route name answers 401 without an event.
func TestGatewayReportsTenantBlocks(t *testing.T) {
	f, c := setup(t)
	r := NewResolver(c, ResolverOptions{Interval: time.Hour})
	if _, err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	sink := NewEventSink(c, EventSinkOptions{})
	gw := egress.NewServerWithResolver(r, nil, egress.WithEventSink(sink))

	send := func(path, token string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", path, strings.NewReader(`{"messages":[]}`))
		req.RemoteAddr = "203.0.113.7:4444"
		req.Header.Set("Authorization", "Bearer "+token)
		gw.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := send("/v1/agent/billing-bot/proxy/openrouter/chat/completions", "OWE_TOKEN_A"); code != http.StatusUnauthorized {
		t.Fatalf("wrong route name: %d", code)
	}
	if code := send("/v1/agent/support-bot/proxy/anthropic/messages?beta=1", "OWE_TOKEN_B"); code != http.StatusNotFound {
		t.Fatalf("tenant B, target of tenant A: %d", code)
	}
	if code := send("/v1/agent/support-bot/proxy/bad/x", "OWE_TOKEN_A"); code != http.StatusNotFound {
		t.Fatalf("skipped target: %d", code)
	}
	if code := send("/v1/agent/support-bot/proxy/groq/chat/completions?x=1", "OWE_TOKEN_B"); code != http.StatusForbidden {
		t.Fatalf("not allowed: %d", code)
	}
	if err := sink.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.batches) != 1 {
		t.Fatalf("got %d batches", len(f.batches))
	}
	var b struct {
		Version int     `json:"version"`
		NodeID  string  `json:"node_id"`
		BatchID string  `json:"batch_id"`
		Events  []Event `json:"events"`
	}
	if err := json.Unmarshal(f.batches[0], &b); err != nil {
		t.Fatal(err)
	}
	if b.Version != 1 || b.NodeID != testNode || !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(b.BatchID) || len(b.Events) != 1 {
		t.Fatalf("batch %s", f.batches[0])
	}
	ev := b.Events[0]
	if _, err := time.Parse(time.RFC3339, ev.TS); err != nil || ev.OrgID != orgB || ev.AgentID != agentB || ev.Target != "groq" ||
		ev.Code != "egress_blocked" || ev.Status != 403 || ev.Method != "POST" || ev.Path != "/chat/completions" || ev.IP != "203.0.113.7" || ev.Detections == nil || len(ev.Detections) != 0 {
		t.Errorf("event %+v", ev)
	}
	if !strings.Contains(string(f.batches[0]), `"detections":[]`) {
		t.Errorf("detections must be an empty array: %s", f.batches[0])
	}
}

func TestEventBatchesRetryAndOverflow(t *testing.T) {
	f, c := setup(t)
	sink := NewEventSink(c, EventSinkOptions{QueueSize: 2500, MinBackoff: time.Millisecond, MaxBackoff: 2 * time.Millisecond, FlushInterval: time.Hour})
	ev := egress.BlockEvent{Time: time.Now(), TenantID: orgA, AgentID: agentA, AgentName: "support-bot", Target: "openrouter",
		Code: egress.CodeInjectionDetected, Status: 403, Method: "POST", Path: "/chat/completions", IP: "203.0.113.7",
		Detections: []string{"pi.override.en", "pi.override.en", "hidden.zero_width", "Not Valid!"}}
	for range 2600 {
		sink.Block(ev)
	}
	sink.Block(egress.BlockEvent{AgentID: "static-agent", Code: egress.CodeEgressBlocked}) // no tenant: ignored
	if sink.Dropped() != 100 || sink.Queued() != 2500 {
		t.Fatalf("dropped %d queued %d, want 100 and 2500", sink.Dropped(), sink.Queued())
	}

	f.failNext = 2
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { sink.Run(ctx); close(done) }()
	sink.wake <- struct{}{}
	deadline := time.Now().Add(5 * time.Second)
	idle := func() bool {
		sink.sendMu.Lock()
		defer sink.sendMu.Unlock()
		return sink.pending == nil && sink.Queued() == 0
	}
	for !idle() || len(batchesOf(f)) < 5 {
		if time.Now().After(deadline) {
			t.Fatalf("not delivered: queued %d, %d posts", sink.Queued(), len(batchesOf(f)))
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	type batch struct {
		BatchID string  `json:"batch_id"`
		Events  []Event `json:"events"`
	}
	var got []batch
	for _, raw := range batchesOf(f) {
		var b batch
		json.Unmarshal(raw, &b)
		got = append(got, b)
	}
	// Two 503s: the first batch is posted three times under one batch_id.
	if len(got) != 5 || got[0].BatchID != got[1].BatchID || got[1].BatchID != got[2].BatchID || got[2].BatchID == got[3].BatchID || got[3].BatchID == got[4].BatchID {
		var ids []string
		for _, b := range got {
			ids = append(ids, fmt.Sprintf("%s/%d", b.BatchID, len(b.Events)))
		}
		t.Fatalf("batch ids %v", ids)
	}
	if string(batchesOf(f)[0]) != string(batchesOf(f)[2]) {
		t.Error("a retried batch must resend the same body")
	}
	sizes := []int{len(got[2].Events), len(got[3].Events), len(got[4].Events)}
	if sizes[0] != 1000 || sizes[1] != 1000 || sizes[2] != 500 {
		t.Errorf("batch sizes %v", sizes)
	}
	if d := got[4].Events[0].Detections; strings.Join(d, ",") != "pi.override.en,hidden.zero_width" {
		t.Errorf("detections %v", d)
	}
}

func batchesOf(f *fakeControlPlane) [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.batches...)
}

func TestGenerateKeyFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "node.key")
	pub, err := GenerateKeyFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %v", st.Mode().Perm())
	}
	priv, err := LoadPrivateKey(p)
	if err != nil || !priv.Public().(ed25519.PublicKey).Equal(pub) {
		t.Fatalf("reloaded key does not match: %v", err)
	}
	if raw, _ := base64.StdEncoding.DecodeString(PublicKeyBase64(pub)); len(raw) != ed25519.PublicKeySize {
		t.Errorf("public key encoding %q", PublicKeyBase64(pub))
	}
	if _, err := GenerateKeyFile(p); err == nil {
		t.Error("an existing key file must not be overwritten")
	}
}

func TestClientRequiresHTTPS(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	s, _ := NewSigner(testNode, priv)
	for u, ok := range map[string]bool{
		"https://app.openwaf.dev": true, "http://127.0.0.1:8080": true, "http://localhost:8080": true,
		"http://app.openwaf.dev": false, "ftp://x": false, "https://u:p@app.openwaf.dev": false,
	} {
		if _, err := NewClient(u, s, nil); (err == nil) != ok {
			t.Errorf("%s: err %v", u, err)
		}
	}
	if _, err := NewSigner("Bad_Node", priv); err == nil {
		t.Error("invalid node id accepted")
	}
}
