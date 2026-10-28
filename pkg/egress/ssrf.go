package egress

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
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

// suspiciousIPLiteral matches host spellings Go's netip does not accept but resolvers may
// interpret as IPv4: all-decimal ("2130706433"), hex ("0x7f000001") and dotted-quad forms
// with out-of-range or zero-padded components ("127.1", "0177.0.0.1", "127.0.0.01"). They are
// refused before any DNS lookup, so a resolver quirk cannot turn them into a private address.
var (
	reDecimalIP = regexp.MustCompile(`^\d{1,10}$`)
	reHexIP     = regexp.MustCompile(`(?i)^0[xX][0-9a-f]{1,8}$`)
	// reDottedNum: an all-numeric dotted host (any label length). All-numeric names are IP
	// literals, never domains, so anything netip did not accept (leading zeros, out-of-range
	// or too-short forms) is refused instead of reaching a resolver that may read the bytes
	// either way.
	reDottedNum = regexp.MustCompile(`^\d+(\.\d+){0,3}$`)
	// reLeadingZeroNum: a numeric dotted component starting with 0 ("0177.0.0.1"). netip
	// rejects those literals outright, classic inet_addr reads them as octal (127.0.0.1) and
	// other readers as decimal (177.0.0.1): the ambiguity itself is refused.
	reLeadingZeroNum = regexp.MustCompile(`(?:^|\.)0\d`)
)

func suspiciousIPLiteral(host string) bool {
	return reDecimalIP.MatchString(host) || reHexIP.MatchString(host) || reDottedNum.MatchString(host)
}

// ambiguousDottedLiteral reports a dotted numeric host with a zero-padded component, for
// which netip and inet_addr disagree about the value.
func ambiguousDottedLiteral(host string) bool {
	return reDottedNum.MatchString(host) && reLeadingZeroNum.MatchString(host)
}

// ValidatePublicDestination checks that the hostname or IP does not resolve to an internal/private address.
func ValidatePublicDestination(host string) error {
	// Strip port if present
	h, _, err := net.SplitHostPort(host)
	if err == nil {
		host = h
	}
	// A trailing dot is the same name; make sure ParseAddr sees "8.8.8.8." as an IP.
	host = strings.TrimSuffix(host, ".")

	// Direct IP check
	if ip, err := netip.ParseAddr(host); err == nil {
		if IsPrivateIP(ip) {
			return fmt.Errorf("destination IP %s is private or reserved", ip)
		}
		if ambiguousDottedLiteral(host) {
			return fmt.Errorf("destination %s is an ambiguous numeric IP literal", host)
		}
		return nil
	}

	// Numeric spellings netip rejected (decimal, hex, zero-padded) are never hostnames worth
	// shipping to a resolver: refuse them here, deterministically.
	if suspiciousIPLiteral(host) {
		return fmt.Errorf("destination %s is a numeric IP literal in an unsupported form", host)
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
