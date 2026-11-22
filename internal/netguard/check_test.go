package netguard

import (
	"errors"
	"net/netip"
	"testing"
)

func TestCheckAddrBlocksMetadataAndLinkLocalInEveryForm(t *testing.T) {
	for _, addr := range []string{
		// link-local IPv4, which covers most cloud metadata
		"169.254.169.254", // AWS, GCP, Azure, Oracle, DigitalOcean
		"169.254.170.2",   // AWS ECS task metadata
		"169.254.170.23",  // AWS EKS pod identity
		"169.254.0.23",    // Tencent
		"169.254.0.1",
		// metadata outside link-local
		"100.100.100.200", // Alibaba, in CGNAT space
		"fd00:ec2::254",   // AWS IMDS over IPv6, inside private fc00::/7
		"fd00:ec2::23",    // AWS EKS pod identity over IPv6
		// IPv6 link-local, with and without a zone
		"fe80::1",
		"fe80::a9fe:a9fe%eth0",
		// IPv4 wrapped in IPv6
		"::ffff:169.254.169.254", // IPv4-mapped
		"::ffff:a9fe:a9fe",       // IPv4-mapped, hex
		"::ffff:100.100.100.200", // IPv4-mapped Alibaba: the exact-address list needs Unmap
		"::ffff:0.0.0.0",         // IPv4-mapped unspecified
		"::ffff:0.1.2.3",         // IPv4-mapped this-network
		"::169.254.169.254",      // IPv4-compatible
		"64:ff9b::a9fe:a9fe",     // NAT64 well-known prefix
		"64:ff9b::100.100.100.200",
		"64:ff9b:1::a9fe:a9fe",                 // NAT64 local-use prefix, blocked outright
		"2002:a9fe:a9fe::1",                    // 6to4
		"2001:0:4136:e378:8000:63bf:3fff:fdd2", // Teredo, blocked outright
		// unspecified
		"0.0.0.0",
		"0.1.2.3",
		"::",
	} {
		ip := netip.MustParseAddr(addr)
		if err := checkAddr(ip); !errors.Is(err, ErrBlocked) {
			t.Errorf("checkAddr(%s) = %v, want ErrBlocked", addr, err)
		}
	}
}

func TestCheckAddrAllowsLoopbackPrivateAndPublic(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1", "127.5.5.5", "::1", "::ffff:127.0.0.1",
		"10.0.0.5", "172.16.1.1", "192.168.1.10", "fd12:3456::1",
		"100.64.0.1", // CGNAT, but not the Alibaba metadata address
		"93.184.216.34", "2606:4700::1111",
		"64:ff9b::5db8:d822", // NAT64 of a public IPv4
		"2002:5db8:d822::1",  // 6to4 of a public IPv4
	} {
		if err := checkAddr(netip.MustParseAddr(addr)); err != nil {
			t.Errorf("checkAddr(%s) = %v, want allowed", addr, err)
		}
	}
}

func TestCheckPlainAllowsOnlyLoopback(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "127.9.9.9", "::1", "::ffff:127.0.0.1"} {
		if err := checkPlain(netip.MustParseAddr(addr)); err != nil {
			t.Errorf("checkPlain(%s) = %v, want allowed", addr, err)
		}
	}
	for _, addr := range []string{"10.0.0.5", "192.168.1.10", "93.184.216.34", "fd12::1", "2606:4700::1111"} {
		if err := checkPlain(netip.MustParseAddr(addr)); !errors.Is(err, ErrInsecure) {
			t.Errorf("checkPlain(%s) = %v, want ErrInsecure", addr, err)
		}
	}
	// The metadata block still comes first.
	if err := checkPlain(netip.MustParseAddr("169.254.169.254")); !errors.Is(err, ErrBlocked) {
		t.Errorf("checkPlain(169.254.169.254) = %v, want ErrBlocked", err)
	}
}

func TestBlockedNames(t *testing.T) {
	for name, want := range map[string]bool{
		"metadata.google.internal":   true,
		"metadata.google.internal.":  true,
		"METADATA.Google.Internal":   true,
		"metadata.goog":              true,
		"metadata":                   true,
		"instance-data":              true,
		"instance-data.ec2.internal": true,
		"metadata.tencentyun.com":    true,
		"example.com":                false,
		"mcp.metadata.example.com":   false,
		"localhost":                  false,
	} {
		if got := blockedName(name); got != want {
			t.Errorf("blockedName(%q) = %v, want %v", name, got, want)
		}
	}
}
