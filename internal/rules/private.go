package rules

import (
	"net/netip"
	"sync"
)

// PrivateCIDRs are the system-reserved ranges that must always be DIRECT,
// per the requirements (plus 0.0.0.0/8, multicast/reserved, and the
// benchmark range 198.18.0.0/15 that sscli's own TUN address lives in —
// without it packets to/from the TUN interface itself could be proxied).
var PrivateCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"255.255.255.255/32",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
}

// PrivateSets builds separate v4/v6 CIDR sets for the private ranges.
func PrivateSets() (*CIDRSet, *CIDRSet) {
	v4 := NewCIDRSet()
	v6 := NewCIDRSet()
	for _, c := range PrivateCIDRs {
		p := netip.MustParsePrefix(c)
		if p.Addr().Is4() || p.Addr().Is4In6() {
			_ = v4.Insert(p)
		} else {
			_ = v6.Insert(p)
		}
	}
	return v4, v6
}

// IsPrivate reports whether ip falls in any private/LAN range.
func IsPrivate(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	v4, v6 := privateOnce()
	if ip.Is4() || ip.Is4In6() {
		return v4.Contains(ip.Unmap())
	}
	return v6.Contains(ip)
}

var (
	privOnce       sync.Once
	privV4, privV6 *CIDRSet
)

func privateOnce() (*CIDRSet, *CIDRSet) {
	privOnce.Do(func() { privV4, privV6 = PrivateSets() })
	return privV4, privV6
}
