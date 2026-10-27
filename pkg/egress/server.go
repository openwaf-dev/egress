package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openwaf-dev/egress/pkg/aiagents"
)

// maxBodyBytes is the largest request body the gateway forwards (agents without inspection).
const maxBodyBytes = 8 << 20

// Server is the OpenWAF Egress Gateway HTTP handler.
type Server struct {
	cfg       *Config
	vault     SecretProvider
	client    *http.Client
	logOutput io.Writer
}

// NewServer initializes a new Egress Gateway server.
func NewServer(cfg *Config, vault SecretProvider) *Server {
	transport := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}

	return &Server{
		cfg:   cfg,
		vault: vault,
		client: &http.Client{
			Transport: transport,
			Timeout:   300 * time.Second, // Long timeout for LLM generation
		},
	}
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"service": "openwaf-egress",
		"version": "0.1.0",
		"openbao": vaultOK,
		"targets": len(s.cfg.Targets),
		"agents":  len(s.cfg.Agents),
	})
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request, agentName, targetAlias, subPath string) {
	ctx := r.Context()

	// 1. Resolve agent
	var agentCfg *AgentConfig
	resolvedAgent := agentName

	authHeader := r.Header.Get("Authorization")
	customAgentHeader := r.Header.Get("X-OpenWAF-Agent")

	if customAgentHeader != "" {
		resolvedAgent = customAgentHeader
	}

	if resolvedAgent != "" {
		if a, exists := s.cfg.Agents[resolvedAgent]; exists {
			agentCfg = &a
		}
	} else if authHeader != "" {
		// Identify by token if agentName not in route
		tokenVal := strings.TrimPrefix(authHeader, "Bearer ")
		for name, a := range s.cfg.Agents {
			if a.Token == tokenVal {
				agentCfg = &a
				resolvedAgent = name
				break
			}
		}
	}

	if agentCfg == nil {
		log.Printf("[EGRESS 401] Unauthorized: Agent=%q Target=%q Path=%q AuthPresent=%t",
			resolvedAgent, targetAlias, r.URL.Path, authHeader != "")
		s.respondError(w, http.StatusUnauthorized, "unauthorized_agent", "Agent not identified or token mismatch")
		return
	}

	// Require the agent's placeholder token whenever one is configured, regardless of how
	// the agent was identified (route, X-OpenWAF-Agent header, or token lookup). A caller
	// who knows only the agent name must not be able to use the gateway: doing so would
	// also hand them the real upstream credential injected below.
	if agentCfg.Token != "" {
		if authHeader == "" {
			log.Printf("[EGRESS 401] Missing token for agent %q: Path=%q", resolvedAgent, r.URL.Path)
			s.respondError(w, http.StatusUnauthorized, "token_required", "Agent placeholder token required: Authorization: Bearer <token>")
			return
		}
		tokenVal := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenVal != agentCfg.Token {
			log.Printf("[EGRESS 401] Token mismatch for agent %q: Path=%q", resolvedAgent, r.URL.Path)
			s.respondError(w, http.StatusUnauthorized, "invalid_token", "Agent placeholder token did not match policy")
			return
		}
	}

	// 2. Validate target alias
	targetCfg, targetExists := s.cfg.Targets[targetAlias]
	if !targetExists {
		s.respondError(w, http.StatusNotFound, "unknown_target", fmt.Sprintf("Target alias %q is not defined", targetAlias))
		return
	}

	// Check if target is allowed for this agent
	allowed := false
	for _, a := range agentCfg.AllowedTargets {
		if a == targetAlias || a == "*" {
			allowed = true
			break
		}
	}
	if !allowed {
		s.respondError(w, http.StatusForbidden, "egress_blocked", fmt.Sprintf("Agent %q is not permitted to access target %q", resolvedAgent, targetAlias))
		return
	}

	// 3. SSRF Protection: target host must not resolve to private addresses
	if err := ValidatePublicDestination(targetCfg.Host); err != nil {
		s.respondError(w, http.StatusForbidden, "ssrf_blocked", fmt.Sprintf("Egress to destination blocked: %v", err))
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
	inspect := agentCfg.EnforceInjection || agentCfg.BlockDLP
	if len(bodyBytes) > maxBodyBytes || inspect && len(bodyBytes) > aiagents.MaxInspectBytes {
		limit := maxBodyBytes
		if inspect {
			limit = aiagents.MaxInspectBytes
		}
		s.respondError(w, http.StatusRequestEntityTooLarge, "body_too_large",
			fmt.Sprintf("Request body exceeds %d bytes (the inspection window when injection or DLP checks are on)", limit))
		return
	}

	if len(bodyBytes) > 0 {
		bodyStr := string(bodyBytes)

		// Prompt Injection check using OpenWAF's internal/aiagents.Detect
		if agentCfg.EnforceInjection {
			detections := aiagents.Detect(bodyStr)
			var injectionFindings []aiagents.Detection
			for _, d := range detections {
				if !aiagents.IsCostDetection(d) {
					injectionFindings = append(injectionFindings, d)
				}
			}
			if len(injectionFindings) > 0 {
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
		if agentCfg.BlockDLP {
			dlpMatches := ScanDLP(bodyStr)
			if len(dlpMatches) > 0 {
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
	if credRef, hasCred := agentCfg.CredentialMapping[targetAlias]; hasCred && s.vault != nil {
		var err error
		realCredential, err = s.vault.GetSecret(ctx, credRef.Path, credRef.Key)
		if err != nil {
			log.Printf("[EGRESS] Failed resolving secret %s:%s for agent %s: %v", credRef.Path, credRef.Key, resolvedAgent, err)
			s.respondError(w, http.StatusBadGateway, "credential_resolution_failed", "Unable to obtain upstream credential from OpenBao")
			return
		}
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

	// Strip gateway-specific headers
	outReq.Header.Del("X-OpenWAF-Agent")

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
