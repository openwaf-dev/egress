package egress

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Block event codes (BlockEvent.Code).
const (
	CodeInjectionDetected = "injection_detected"
	CodeDataLeakBlocked   = "data_leak_blocked"
	CodeSSRFBlocked       = "ssrf_blocked"
	CodeEgressBlocked     = "egress_blocked"
	CodeBodyTooLarge      = "body_too_large"
)

// BlockEvent describes one request of an identified agent that the gateway refused. It never
// carries the request body or any part of it.
type BlockEvent struct {
	Time       time.Time
	TenantID   string // empty in static config mode
	AgentID    string
	AgentName  string
	Target     string   // target alias from the route
	Code       string   // one of the Code* constants
	Status     int      // HTTP status returned to the caller
	Method     string   // request method
	Path       string   // sub-path after /proxy/<target>, without the query
	IP         string   // caller address (connection peer)
	Detections []string // injection detection IDs or DLP match types; empty for other codes
}

// EventSink receives block events. Block is called on the request goroutine and must not
// block it for long (queue the event instead).
type EventSink interface {
	Block(ev BlockEvent)
}

// WithEventSink sends block events to sink instead of the log.
func WithEventSink(sink EventSink) Option {
	return func(s *Server) {
		if sink != nil {
			s.events = sink
		}
	}
}

// LogSink writes block events to the standard logger. It is the default EventSink.
type LogSink struct{}

// Block implements EventSink.
func (LogSink) Block(ev BlockEvent) {
	tenant := ""
	if ev.TenantID != "" {
		tenant = " Tenant=" + ev.TenantID
	}
	log.Printf("[EGRESS %d] %s:%s Agent=%s Target=%s Method=%s Path=%q IP=%s Detections=%s",
		ev.Status, ev.Code, tenant, ev.AgentName, ev.Target, ev.Method, ev.Path, ev.IP, strings.Join(ev.Detections, ","))
}

// WithTrustedProxies makes the gateway take the caller address of block events from X-Real-IP (one address) when
// the connection comes from one of proxies, e.g. a reverse proxy on loopback in front of the gateway. Any other peer,
// or an X-Real-IP that is not a single IP address, gives the connection address.
func WithTrustedProxies(proxies []netip.Prefix) Option {
	return func(s *Server) { s.trustedProxies = proxies }
}

// ParsePrefixes reads a comma-separated list of CIDR prefixes or single addresses.
func ParsePrefixes(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(list, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if a, err := netip.ParseAddr(f); err == nil {
			out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q is not an IP address or CIDR prefix", f)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// clientIP returns the caller address of r: the connection peer, or X-Real-IP from a trusted proxy.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	for _, p := range s.trustedProxies {
		if p.Contains(peer.Unmap()) {
			if real, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
				return real.Unmap().String()
			}
			break
		}
	}
	return host
}

// emitBlock reports a refused request of the agent identified by res.
func (s *Server) emitBlock(r *http.Request, res *Resolution, target, subPath string, status int, code string, detections []string) {
	if detections == nil {
		detections = []string{}
	}
	s.events.Block(BlockEvent{
		Time:       time.Now().UTC(),
		TenantID:   res.TenantID,
		AgentID:    res.AgentID,
		AgentName:  res.AgentName,
		Target:     target,
		Code:       code,
		Status:     status,
		Method:     r.Method,
		Path:       subPath,
		IP:         s.clientIP(r),
		Detections: detections,
	})
}
