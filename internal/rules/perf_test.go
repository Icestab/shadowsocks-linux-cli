package rules

import (
	"fmt"
	"net/netip"
	"testing"
)

// TestPerfSanity validates that matching stays fast with realistic list
// sizes (~70k China domains + ~15k CIDRs + ~10k GFW domains).
func TestPerfSanity(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	e := NewEngine(ModeBypass)
	for i := 0; i < 70000; i++ {
		e.ChinaDomains().AddSuffix(fmt.Sprintf("site%05d.example.cn", i))
	}
	for i := 0; i < 15000; i++ {
		mustInsert(t, e.ChinaIP(), netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(i>>16&0xff) | 0x22, byte(i >> 8), byte(i), 0}), 24).String())
	}
	for i := 0; i < 10000; i++ {
		e.GFWList().AddSuffix(fmt.Sprintf("blocked%05d.io", i))
	}

	// Miss path (worst case): must not scan lists.
	dMiss := netip.MustParseAddr("203.0.113.77")
	n := 200000
	// Domain lookups.
	for i := 0; i < n; i++ {
		e.Decide(fmt.Sprintf("no-hit-%d.random.org", i%997), netip.Addr{})
	}
	// IP lookups.
	for i := 0; i < n; i++ {
		e.Decide("", dMiss)
	}
}
