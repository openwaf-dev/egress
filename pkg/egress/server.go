package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/openwaf-dev/egress/pkg/aiagents"
)

// maxBodyBytes is the largest request body the gateway forwards (agents without inspection).
const maxBodyBytes = 8 << 20

// reMediaDataURI: base64 inline images, audio and video, e.g. an OpenAI-style image_url
// "data:image/jpeg;base64,…" (backslashes allow JSON-escaped slashes). Text media types
// (data:text/plain;base64,…) are not matched: they stay inspected.
var reMediaDataURI = regexp.MustCompile(`data:(?:image|audio|video)/[A-Za-z0-9.+-]{1,40};base64,[A-Za-z0-9+/=\\]+`)

// minBinaryDataLen: a JSON "data" member holding at least this much bare base64 is a binary
// payload (OpenAI input_audio, Gemini inlineData / inline_data, Anthropic base64 image or
// document sources), not inspected text. Chat text travels in "content" / "text" members.
const minBinaryDataLen = 1024

// stripBinaryDataFields replaces the value of every "data" member of at least minBinaryDataLen
// base64 characters (JSON-escaped slashes allowed) with "omitted", in one linear pass.
func stripBinaryDataFields(s string) string {
	const key = `"data"`
	var b strings.Builder
	last := 0 // s[last:] is not yet copied to b
	for i := 0; ; {
		k := strings.Index(s[i:], key)
		if k < 0 {
			break
		}
		j := skipJSONSpace(s, i+k+len(key))
		if j >= len(s) || s[j] != ':' {
			i = j
			continue
		}
		j = skipJSONSpace(s, j+1)
		if j >= len(s) || s[j] != '"' {
			i = j
			continue
		}
		start := j + 1
		end := start
		for end < len(s) && isBase64JSONByte(s[end]) {
			end++
		}
		if end < len(s) && s[end] == '"' && end-start >= minBinaryDataLen {
			b.WriteString(s[last:start])
			b.WriteString("omitted")
			last = end
		}
		i = end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func skipJSONSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	return i
}

func isBase64JSONByte(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '+' || c == '/' || c == '=' || c == '\\'
}

// withoutMediaData replaces inline media payloads with a short marker.
func withoutMediaData(s string) string {
	if strings.Contains(s, ";base64,") {
		s = reMediaDataURI.ReplaceAllString(s, "data:media;base64,omitted")
	}
	if strings.Contains(s, `"data"`) {
		s = stripBinaryDataFields(s)
	}
	return s
}

// Server is the OpenWAF Egress Gateway HTTP handler.
type Server struct {
	resolver Resolver
	vault    SecretProvider
	events   EventSink
	// trustedProxies give the caller address of block events in X-Real-IP (WithTrustedProxies).
	trustedProxies []netip.Prefix
	client         *http.Client
	logOutput      io.Writer
}

// upstreamHeaderTimeout bounds the wait for the provider's response headers; UpstreamTimeout
// bounds a whole exchange, a streamed response included (cmd/egress uses it as the server
// write timeout too). The agent disconnecting cancels the upstream request before either.
const (
	upstreamHeaderTimeout = 5 * time.Minute
	UpstreamTimeout       = 15 * time.Minute
)

// Option configures a Server.
type Option func(*Server)

// NewServer initializes a new Egress Gateway server for a static config file.
func NewServer(cfg *Config, vault SecretProvider, opts ...Option) *Server {
	return NewServerWithResolver(cfg, vault, opts...)
}

// NewServerWithResolver initializes a gateway whose agent policies, targets and credential
// references come from resolver (e.g. a control-plane document) instead of a Config.
func NewServerWithResolver(resolver Resolver, vault SecretProvider, opts ...Option) *Server {
	transport := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// Non-streaming reasoning, image and video generations answer after minutes.
		ResponseHeaderTimeout: upstreamHeaderTimeout,
	}

	s := &Server{
		resolver: resolver,
		vault:    vault,
		events:   LogSink{},
		client: &http.Client{
			Transport: transport,
			Timeout:   UpstreamTimeout, // whole exchange, streamed body included
			// Never follow a redirect: the 3xx goes back to the agent as is. Following it
			// would resend the injected credential (Go only strips Authorization and Cookie
			// across hosts, never a custom header such as x-api-key) to a destination that
			// skipped the target allowlist and the SSRF check.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" || r.URL.Path == "/v1/health" {
		s.handleHealth(w, r)
		return
	}

	// Match proxy routes
	// 1) /v1/proxy/{target}/{path...}
	// 2) /v1/agent/{agent}/proxy/{target}/{path...}
	agentName, targetAlias, subPath, ok := s.parseProxyRoute(r.URL.Path)
	if !ok {
		http.Error(w, `{"error":"invalid_route","message":"expected /v1/proxy/{target}/* or /v1/agent/{agent}/proxy/{target}/*"}`, http.StatusNotFound)
		return
	}

	s.handleProxy(w, r, agentName, targetAlias, subPath)
}

func (s *Server) parseProxyRoute(p string) (agentName, targetAlias, subPath string, ok bool) {
	p = strings.TrimPrefix(p, "/")
	parts := strings.Split(p, "/")
	if len(parts) < 3 {
		return "", "", "", false
	}

	if parts[0] == "v1" && parts[1] == "proxy" {
		targetAlias = parts[2]
		subPath = "/" + strings.Join(parts[3:], "/")
		return "", targetAlias, subPath, true
	}

	if len(parts) >= 5 && parts[0] == "v1" && parts[1] == "agent" && parts[3] == "proxy" {
		agentName = parts[2]
		targetAlias = parts[4]
		subPath = "/" + strings.Join(parts[5:], "/")
		return agentName, targetAlias, subPath, true
	}

	return "", "", "", false
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	vaultOK := false
	if s.vault != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := s.vault.Health(ctx); err == nil {
			vaultOK = true
		}
	}

	agents, targets := 0, 0
	if st, ok := s.resolver.(ResolverStats); ok {
		agents, targets = st.Counts()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"service": "openwaf-egress",
		"version": "0.1.0",
		"openbao": vaultOK,
		"targets": targets,
		"agents":  agents,
	})
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request, agentName, targetAlias, subPath string) {
	ctx := r.Context()

	// 1. Resolve agent, policy, target and credential reference
	authHeader := r.Header.Get("Authorization")
	res, err := s.resolver.Resolve(ctx, ResolveRequest{
		RouteAgent:    agentName,
		HeaderAgent:   r.Header.Get("X-OpenWAF-Agent"),
		Authorization: authHeader,
		Target:        targetAlias,
	})
	if err != nil {
		var re *ResolveError
		if errors.As(err, &re) {
			log.Printf("[EGRESS %d] %s: Agent=%q Target=%q Path=%q AuthPresent=%t",
				re.Status, re.Code, agentName, targetAlias, r.URL.Path, authHeader != "")
			s.respondError(w, re.Status, re.Code, re.Message)
			return
		}
		log.Printf("[EGRESS 503] Policy resolution failed: Agent=%q Target=%q: %v", agentName, targetAlias, err)
		s.respondError(w, http.StatusServiceUnavailable, "policy_unavailable", "Agent policy is not available yet")
		return
	}
	resolvedAgent := res.AgentName
	policy := res.Policy

	// 2. Validate target alias
	if res.Target == nil {
		s.respondError(w, http.StatusNotFound, "unknown_target", fmt.Sprintf("Target alias %q is not defined", targetAlias))
		return
	}
	targetCfg := *res.Target

	// Check if target is allowed for this agent
	allowed := false
	for _, a := range policy.AllowedTargets {
		if a == targetAlias || a == "*" {
			allowed = true
			break
		}
	}
	if !allowed {
		s.emitBlock(r, res, targetAlias, subPath, http.StatusForbidden, CodeEgressBlocked, nil)
		s.respondError(w, http.StatusForbidden, CodeEgressBlocked, fmt.Sprintf("Agent %q is not permitted to access target %q", resolvedAgent, targetAlias))
		return
	}

	// 3. SSRF Protection: target host must not resolve to private addresses
	if err := ValidatePublicDestination(targetCfg.Host); err != nil {
		s.emitBlock(r, res, targetAlias, subPath, http.StatusForbidden, CodeSSRFBlocked, nil)
		s.respondError(w, http.StatusForbidden, CodeSSRFBlocked, fmt.Sprintf("Egress to destination blocked: %v", err))
		return
	}

	// 4. Request Body Inspection (Prompt Injection & DLP). A body is never cut: anything over
	// maxBodyBytes is refused, and with inspection on so is anything the detectors would not
	// see in full (aiagents.MaxInspectBytes), so no part of a body leaves uninspected.
	var bodyBytes []byte
	if r.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
		r.Body.Close()
		if err != nil {
			s.respondError(w, http.StatusBadRequest, "body_read_error", "Failed to read request body")
			return
		}
	}
	// Inline images, audio and video (data:image/…;base64,…) are binary the detectors cannot
	// read; they are left out of the inspected text, so a chat request with a photo is not
	// refused for its size. The rest of the body must fit the inspection window.
	inspect := policy.EnforceInjection || policy.BlockDLP
	bodyStr := string(bodyBytes)
	inspected := bodyStr
	if inspect {
		inspected = withoutMediaData(bodyStr)
	}
	if len(bodyBytes) > maxBodyBytes || inspect && len(inspected) > aiagents.MaxInspectBytes {
		limit := maxBodyBytes
		if inspect && len(bodyBytes) <= maxBodyBytes {
			limit = aiagents.MaxInspectBytes
		}
		s.emitBlock(r, res, targetAlias, subPath, http.StatusRequestEntityTooLarge, CodeBodyTooLarge, nil)
		s.respondError(w, http.StatusRequestEntityTooLarge, CodeBodyTooLarge,
			fmt.Sprintf("Request body exceeds %d bytes (text outside inline media counts against the inspection window when injection or DLP checks are on)", limit))
		return
	}

	if len(bodyBytes) > 0 {
		// Prompt Injection check using OpenWAF's internal/aiagents.Detect
		if policy.EnforceInjection {
			detections := aiagents.Detect(inspected)
			var injectionFindings []aiagents.Detection
			for _, d := range detections {
				if !aiagents.IsCostDetection(d) {
					injectionFindings = append(injectionFindings, d)
				}
			}
			if len(injectionFindings) > 0 {
				ids := make([]string, 0, len(injectionFindings))
				for _, d := range injectionFindings {
					ids = append(ids, d.ID)
				}
				s.emitBlock(r, res, targetAlias, subPath, http.StatusForbidden, CodeInjectionDetected, ids)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":      "injection_detected",
					"message":    "Request body contains prompt injection or adversarial pattern",
					"agent":      resolvedAgent,
					"target":     targetAlias,
					"detections": injectionFindings,
				})
				return
			}
		}

		// DLP check
		if policy.BlockDLP {
			dlpMatches := ScanDLP(inspected)
			if len(dlpMatches) > 0 {
				var types []string
				for _, m := range dlpMatches {
					if !slices.Contains(types, m.Type) {
						types = append(types, m.Type)
					}
				}
				s.emitBlock(r, res, targetAlias, subPath, http.StatusForbidden, CodeDataLeakBlocked, types)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"error":       "data_leak_blocked",
					"message":     "Request body contains high-entropy secrets or sensitive card data",
					"agent":       resolvedAgent,
					"target":      targetAlias,
					"dlp_matches": dlpMatches,
				})
				return
			}
		}
	}

	// 5. Credential Resolution from OpenBao
	var realCredential string
	if credRef := res.Credential; credRef != nil && s.vault != nil {
		var err error
		realCredential, err = s.getSecret(ctx, *credRef)
		if err != nil {
			log.Printf("[EGRESS] Failed resolving secret %s:%s for agent %s: %v", credRef.Path, credRef.Key, resolvedAgent, err)
			s.respondError(w, http.StatusBadGateway, "credential_resolution_failed", "Unable to obtain upstream credential from OpenBao")
			return
		}
	}
	if realCredential == "" && res.CredentialRequired {
		log.Printf("[EGRESS] No credential available for agent %s target %s", resolvedAgent, targetAlias)
		s.respondError(w, http.StatusBadGateway, "credential_resolution_failed", fmt.Sprintf("No upstream credential is available for target %q", targetAlias))
		return
	}

	// 6. Build outgoing request
	upstreamURL, err := url.Parse(targetCfg.BaseURL)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "invalid_upstream_url", "Malformed upstream target URL")
		return
	}

	finalPath := strings.TrimRight(upstreamURL.Path, "/") + subPath
	outURL := *upstreamURL
	outURL.Path = finalPath
	outURL.RawQuery = r.URL.RawQuery

	var reqBody io.Reader
	if len(bodyBytes) > 0 {
		reqBody = bytes.NewReader(bodyBytes)
	}

	outReq, err := http.NewRequestWithContext(ctx, r.Method, outURL.String(), reqBody)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "request_creation_failed", err.Error())
		return
	}

	// Copy original headers
	for k, vv := range r.Header {
		for _, v := range vv {
			outReq.Header.Add(k, v)
		}
	}

	// Strip gateway-specific headers. The agent's placeholder token never leaves the gateway,
	// also when the target takes its key in another header (x-api-key, x-goog-api-key).
	outReq.Header.Del("X-OpenWAF-Agent")
	if res.DropAuthorization {
		outReq.Header.Del("Authorization")
	}

	// Inject real credential
	if realCredential != "" {
		headerName := targetCfg.AuthHeader
		if headerName == "" {
			headerName = "Authorization"
		}
		prefix := targetCfg.AuthPrefix
		outReq.Header.Set(headerName, prefix+realCredential)
	}

	outReq.Host = targetCfg.Host

	// 7. Dispatch to upstream
	t0 := time.Now()
	resp, err := s.client.Do(outReq)
	duration := time.Since(t0)

	if err != nil {
		s.respondError(w, http.StatusBadGateway, "upstream_error", fmt.Sprintf("Error dialing upstream %s: %v", targetCfg.Host, err))
		return
	}
	defer resp.Body.Close()
	log.Printf("[EGRESS] Agent=%s Target=%s Method=%s Path=%s Status=%d Latency=%s",
		resolvedAgent, targetAlias, r.Method, subPath, resp.StatusCode, duration)

	// 8. Stream response headers and body
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	if flusher, ok := w.(http.Flusher); ok {
		buf := make([]byte, 4096)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
				flusher.Flush()
			}
			if err != nil {
				break
			}
		}
	} else {
		io.Copy(w, resp.Body)
	}
}

func (s *Server) respondError(w http.ResponseWriter, code int, errCode, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{
		"error":   errCode,
		"message": msg,
	})
}

// getSecret reads ref from the secret store, from its own KV mount when it names one.
func (s *Server) getSecret(ctx context.Context, ref CredRef) (string, error) {
	if ref.Mount == "" {
		return s.vault.GetSecret(ctx, ref.Path, ref.Key)
	}
	mp, ok := s.vault.(MountSecretProvider)
	if !ok {
		return "", errors.New("secret provider cannot read from an explicit kv mount")
	}
	return mp.GetSecretAt(ctx, ref.Mount, ref.Path, ref.Key)
}
