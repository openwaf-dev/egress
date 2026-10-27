package controlplane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Data-plane endpoints (egressnode v1).
const (
	ConfigPath = "/v1/egress/node/config"
	EventsPath = "/v1/egress/node/events"
)

// maxResponseBytes bounds a control-plane response read into memory.
const maxResponseBytes = 64 << 20

// Client sends signed requests to the OpenWAF Cloud control plane.
type Client struct {
	base   *url.URL
	signer *Signer
	http   *http.Client
}

// NewClient returns a Client for the control plane at baseURL (https, or http on a loopback
// host for local testing). httpClient may be nil: the default never follows a redirect (a 3xx
// is an error), so signed requests only ever reach baseURL.
func NewClient(baseURL string, signer *Signer, httpClient *http.Client) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid control plane URL %q", baseURL)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if ip := net.ParseIP(u.Hostname()); u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, fmt.Errorf("control plane URL %q must use https", baseURL)
		}
	default:
		return nil, fmt.Errorf("control plane URL %q must use https", baseURL)
	}
	if signer == nil {
		return nil, errors.New("a signer is required")
	}
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	return &Client{base: u, signer: signer, http: httpClient}, nil
}

// NodeID returns the node id the client signs for.
func (c *Client) NodeID() string { return c.signer.NodeID() }

// do sends one signed request and returns the status and the (bounded) response body.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body []byte) (int, []byte, error) {
	u := *c.base
	u.Path = c.base.Path + path
	u.RawPath = ""
	u.RawQuery = query.Encode()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "openwaf-egress")
	if err := c.signer.Sign(req, body); err != nil {
		return 0, nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if len(data) > maxResponseBytes {
		return resp.StatusCode, nil, fmt.Errorf("%s %s: response larger than %d bytes", method, path, maxResponseBytes)
	}
	return resp.StatusCode, data, nil
}

// errorMessage extracts a short reason from an error response body.
func errorMessage(status int, body []byte) string {
	msg := strings.TrimSpace(string(body))
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return fmt.Sprintf("HTTP %d %s", status, msg)
}
