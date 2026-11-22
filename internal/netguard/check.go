package netguard

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Prefixes and addresses that are never dialed. Fixed and read only.
//
//nolint:gochecknoglobals // constant address lists, never written
var (
	teredo       = netip.MustParsePrefix("2001::/32")      // IPv4 inside is obfuscated
	nat64Local   = netip.MustParsePrefix("64:ff9b:1::/48") // IPv4 position depends on prefix length
	nat64        = netip.MustParsePrefix("64:ff9b::/96")   // IPv4 in the last 32 bits
	sixToFour    = netip.MustParsePrefix("2002::/16")      // IPv4 in bits 16 to 47
	v4Compatible = netip.MustParsePrefix("::/96")          // deprecated ::a.b.c.d
	thisNetwork  = netip.MustParsePrefix("0.0.0.0/8")      // 0.x.x.x, connects to localhost on Linux

	// Cloud metadata addresses outside the link-local ranges.
	metadataAddrs = []netip.Addr{
		netip.MustParseAddr("100.100.100.200"), // Alibaba
		netip.MustParseAddr("fd00:ec2::254"),   // AWS IMDS over IPv6
		netip.MustParseAddr("fd00:ec2::23"),    // AWS EKS pod identity over IPv6
	}

	// Metadata hostnames, refused before any DNS lookup. The IP check
	// catches them anyway; this is defense in depth.
	metadataNames = []string{
		"metadata", "metadata.google.internal", "metadata.goog",
		"instance-data", "instance-data.ec2.internal", "metadata.tencentyun.com",
	}
)

// checkAddr is the address policy for every connection: it refuses link-local
// addresses, cloud metadata, the unspecified address and every IPv6 form that
// can wrap one of those. Loopback, private and public addresses are allowed.
func checkAddr(ip netip.Addr) error {
	ip = ip.WithZone("").Unmap()
	if ip.Is6() {
		switch {
		case teredo.Contains(ip):
			return blocked(ip, "Teredo address")
		case nat64Local.Contains(ip):
			return blocked(ip, "local-use NAT64 address")
		}
		if v4, ok := embeddedV4(ip); ok {
			if err := checkAddr(v4); err != nil {
				return blocked(ip, "wraps "+v4.String())
			}
		}
	}
	switch {
	case ip.IsUnspecified() || thisNetwork.Contains(ip):
		return blocked(ip, "unspecified address")
	case ip.IsLinkLocalUnicast():
		return blocked(ip, "link-local address")
	case slices.Contains(metadataAddrs, ip):
		return blocked(ip, "cloud metadata address")
	}
	return nil
}

// checkPlain is the policy for plaintext http: everything checkAddr refuses,
// plus anything that isn't loopback.
func checkPlain(ip netip.Addr) error {
	if err := checkAddr(ip); err != nil {
		return err
	}
	if !ip.WithZone("").Unmap().IsLoopback() {
		return fmt.Errorf("%w: plain http to %s, which isn't loopback", ErrInsecure, ip)
	}
	return nil
}

// embeddedV4 returns the IPv4 address inside an IPv4-compatible, NAT64 or
// 6to4 address.
func embeddedV4(ip netip.Addr) (netip.Addr, bool) {
	b := ip.As16()
	switch {
	case v4Compatible.Contains(ip):
		if ip == netip.IPv6Unspecified() || ip == netip.IPv6Loopback() {
			return netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(b[12:16])), true
	case nat64.Contains(ip):
		return netip.AddrFrom4([4]byte(b[12:16])), true
	case sixToFour.Contains(ip):
		return netip.AddrFrom4([4]byte(b[2:6])), true
	default:
		return netip.Addr{}, false
	}
}

// blockedName reports metadata hostnames, ignoring case and a trailing dot.
func blockedName(host string) bool {
	return slices.Contains(metadataNames, strings.TrimSuffix(strings.ToLower(host), "."))
}

func blocked(ip netip.Addr, why string) error {
	return fmt.Errorf("%w: %s (%s)", ErrBlocked, ip, why)
}
