package cimd

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"syscall"
)

// errBlocked is returned when a fetch would connect to an address that isn't public
var errBlocked = errors.New("not a public address")

// dialControl refuses connections to addresses refuse reports, and to anything that isn't an IP address since the dialer only passes resolved ones
// Running on every connection, it covers redirects and defeats DNS rebinding, where a check before the fetch would not
func dialControl(refuse func(netip.AddrPort) bool) func(string, string, syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		addrPort, err := netip.ParseAddrPort(address)
		if err != nil || refuse(addrPort) {
			return fmt.Errorf("connect to %s: %w", address, errBlocked)
		}
		return nil
	}
}

// refusePrivate refuses every address but public ones
func refusePrivate(addrPort netip.AddrPort) bool {
	return blocked(addrPort.Addr())
}

var (
	// sharedAddressSpace is 100.64.0.0/10, where some clouds serve instance metadata, e.g. Alibaba Cloud at 100.100.100.200
	sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")
	// nat64 addresses reach the IPv4 address in their last 32 bits through a NAT64 gateway
	nat64 = netip.MustParsePrefix("64:ff9b::/96")
	// metadataAddrs are cloud metadata services outside the link-local range: Alibaba Cloud's and the IPv6 one of AWS
	metadataAddrs = []netip.Addr{netip.MustParseAddr("100.100.100.200"), netip.MustParseAddr("fd00:ec2::254")}
	// specialRanges are IPv4 ranges that are neither private nor public, where local services live too, such as the benchmarking range some VPNs hand out
	specialRanges = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("240.0.0.0/4")}
)

// blocked reports whether a connection to addr could reach the host itself, cloud metadata or a private network
func blocked(addr netip.Addr) bool {
	addr = reached(addr)
	return addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsPrivate() ||
		sharedAddressSpace.Contains(addr) || slices.Contains(metadataAddrs, addr) || slices.ContainsFunc(specialRanges, func(p netip.Prefix) bool { return p.Contains(addr) })
}

// reached is the address a connection to addr really reaches, since IPv4-mapped and NAT64 addresses lead to the IPv4 address they embed
// An IPv6 zone only picks the interface to leave through, so it is dropped, which also keeps range checks working since a prefix never contains a zoned address
func reached(addr netip.Addr) netip.Addr {
	addr = addr.WithZone("").Unmap()
	if nat64.Contains(addr) {
		b := addr.As16()
		addr = netip.AddrFrom4([4]byte(b[12:]))
	}
	return addr
}
