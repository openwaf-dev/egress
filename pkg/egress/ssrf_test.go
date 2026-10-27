package egress

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// allowLoopbackUpstream lets a test server forward to an httptest upstream on 127.0.0.1.
func allowLoopbackUpstream(s *Server) { s.allowPrivateUpstream = true }

func TestCheckDialAddress(t *testing.T) {
	for addr, ok := range map[string]bool{
		"8.8.8.8:443":            true,
		"[2606:4700::1111]:443":  true,
		"127.0.0.1:443":          false,
		"10.1.2.3:80":            false,
		"169.254.169.254:80":     false,
		"0.0.0.0:443":            false,
		"[::]:443":               false,
		"[::1]:443":              false,
		"[::ffff:10.0.0.1]:443":  false,
		"[::ffff:127.0.0.1]:443": false,
		"[fe80::1%en0]:443":      false,
		"224.0.0.1:443":          false,
		"255.255.255.255:443":    false,
		"not-an-address":         false,
	} {
		if err := checkDialAddress(addr); (err == nil) != ok {
			t.Errorf("%s: err %v, want allowed=%v", addr, err, ok)
		}
	}
}

// A target whose host passes the pre-check but whose connection lands on a private address
// (DNS rebinding) is refused at dial time as ssrf_blocked; nothing reaches the upstream and
// the caller learns no address.
func TestDialTimeSSRFBlocked(t *testing.T) {
	called := false
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer upstream.Close()

	sink := &recordingSink{}
	res := &Resolution{
		AgentID: "a", AgentName: "a",
		Policy: AgentPolicy{AllowedTargets: []string{"openrouter"}},
		Target: &TargetConfig{BaseURL: upstream.URL, Host: "8.8.8.8", AuthHeader: "Authorization"},
	}
	srv := NewServerWithResolver(staticResolution{res}, nil, WithEventSink(sink))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/agent/a/proxy/openrouter/models", nil))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), CodeSSRFBlocked) || called {
		t.Fatalf("got %d %s, upstream called %v", rec.Code, rec.Body.String(), called)
	}
	if strings.Contains(rec.Body.String(), "127.0.0.1") {
		t.Errorf("the answer reveals the dialed address: %s", rec.Body.String())
	}
	if len(sink.events) != 1 || sink.events[0].Code != CodeSSRFBlocked {
		t.Errorf("events %+v", sink.events)
	}
}

// Upstream failures answer a generic 502; the error detail stays in the log.
func TestUpstreamErrorIsGeneric(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := upstream.URL
	upstream.Close() // connection refused

	res := &Resolution{
		AgentID: "a", AgentName: "a",
		Policy: AgentPolicy{AllowedTargets: []string{"openrouter"}},
		Target: &TargetConfig{BaseURL: url, Host: "8.8.8.8", AuthHeader: "Authorization"},
	}
	srv := NewServerWithResolver(staticResolution{res}, nil, allowLoopbackUpstream)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/agent/a/proxy/openrouter/models", nil))
	if rec.Code != http.StatusBadGateway || strings.TrimSpace(rec.Body.String()) != `{"error":"upstream_error","message":"Upstream request failed"}` {
		t.Errorf("got %d %s", rec.Code, rec.Body.String())
	}
}

// The pre-check answer names no resolved address either.
func TestSSRFMessageHasNoAddress(t *testing.T) {
	res := &Resolution{
		AgentID: "a", AgentName: "a",
		Policy: AgentPolicy{AllowedTargets: []string{"meta"}},
		Target: &TargetConfig{BaseURL: "http://169.254.169.254", Host: "169.254.169.254"},
	}
	srv := NewServerWithResolver(staticResolution{res}, nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/agent/a/proxy/meta/latest", nil))
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "169.254") {
		t.Errorf("got %d %s", rec.Code, rec.Body.String())
	}
}
