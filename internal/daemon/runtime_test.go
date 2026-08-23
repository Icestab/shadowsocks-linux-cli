package daemon

import (
	"net"
	"net/netip"
	"slices"
	"testing"
)

func TestPrioritizeIPs(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("2001:db8::1"),
		net.ParseIP("18.139.140.0"),
		net.ParseIP("18.139.140.0"), // duplicate from the resolver
		net.ParseIP("18.139.141.7"),
		net.ParseIP("2001:db8::2"),
	}
	got, err := prioritizeIPs(ips)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{
		netip.MustParseAddr("18.139.140.0"),
		netip.MustParseAddr("18.139.141.7"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("2001:db8::2"),
	}
	if !slices.Equal(got, want) {
		t.Errorf("prioritizeIPs = %v, want %v (v4 first, deduped)", got, want)
	}

	if _, err := prioritizeIPs(nil); err == nil {
		t.Error("empty input should error")
	}
}

func TestResolveServerIPsAcceptsLiteral(t *testing.T) {
	// Literal addresses need no DNS (this is the no-network path).
	got, err := resolveServerIPs("18.139.140.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != netip.MustParseAddr("18.139.140.0") {
		t.Errorf("resolveServerIPs(literal) = %v, want [18.139.140.0]", got)
	}
}