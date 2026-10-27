package egress

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// ssrfBlockedMessage is what a caller is told; resolved addresses are logged, not returned.
const ssrfBlockedMessage = "Egress to destination blocked: the target must resolve only to public addresses"

// errDestinationBlocked: the upstream connection was refused for a non-public address.
var errDestinationBlocked = errors.New("destination address is not public")

// privateCIDRs covers IPv4 and IPv6 non-public ranges (loopback, private, link-local, multicast, etc.).
var privatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("224.0.0.0/4"), // Multicast
	netip.MustParsePrefix("240.0.0.0/4"), // Reserved
	netip.MustParsePrefix("::1/128"),     // IPv6 loopback
	netip.MustParsePrefix("::/128"),      // IPv6 unspecified
	netip.MustParsePrefix("fc00::/7"),    // IPv6 ULA
	netip.MustParsePrefix("fe80::/10"),   // IPv6 link-local
	netip.MustParsePrefix("ff00::/8"),    // IPv6 multicast
}

// IsPrivateIP reports whether an IP address belongs to a private, loopback, or reserved range.
func IsPrivateIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	// Unmap IPv4-mapped IPv6 addresses so ::ffff:127.0.0.1 is checked as IPv4
	ip = ip.Unmap()
	for _, p := range privatePrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidatePublicDestination checks that the hostname or IP does not resolve to an internal/private address.
func ValidatePublicDestination(host string) error {
	// Strip port if present
	h, _, err := net.SplitHostPort(host)
	if err == nil {
		host = h
	}

	// Direct IP check
	if ip, err := netip.ParseAddr(host); err == nil {
		if IsPrivateIP(ip) {
			return fmt.Errorf("destination IP %s is private or reserved", ip)
		}
		return nil
	}

	// Resolve hostname
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("resolving destination %s: %w", host, err)
	}

	if len(ips) == 0 {
		return fmt.Errorf("destination %s resolved to no addresses", host)
	}

	for _, rawIP := range ips {
		ip, ok := netip.AddrFromSlice(rawIP)
		if !ok || IsPrivateIP(ip) {
			return fmt.Errorf("destination %s resolves to private address %s", host, rawIP)
		}
	}

	return nil
}

// checkDialAddress refuses a connection to address ("ip:port", as resolved by the dialer)
// unless the IP is a public unicast address.
func checkDialAddress(address string) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return errDestinationBlocked
	}
	ip := ap.Addr().Unmap()
	if IsPrivateIP(ip) || ip.IsUnspecified() || !ip.IsGlobalUnicast() {
		return errDestinationBlocked
	}
	return nil
}
