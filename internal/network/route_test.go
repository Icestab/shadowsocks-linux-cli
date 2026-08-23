package network

import (
	"net/netip"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

// These tests exercise only read-only helpers and pure logic; they never
// mutate the host routing table (Setup/Teardown are covered by the
// integration harness run manually with root, see docs/testing.md).

func TestLinkExistsFalseForBogusName(t *testing.T) {
	if LinkExists("sscli-definitely-not-exist") {
		t.Fatal("bogus link reported as existing")
	}
}

func TestOriginalDefaultRoutesParses(t *testing.T) {
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip not available")
	}
	m := NewManager("sscli0", FwmarkTest, TableTest)
	routes, err := m.OriginalDefaultRoutes()
	if err != nil {
		t.Fatalf("show default routes: %v", err)
	}
	for _, r := range routes {
		if strings.Contains(r, "\n") {
			t.Errorf("route line contains newline: %q", r)
		}
	}
}

const (
	FwmarkTest = 0x162
	TableTest  = 5162
)

func TestOutputHasGlobalIPv6(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want bool
	}{
		{"empty", "", false},
		{
			"link-local only", // the common case: nothing to leak, no capture
			`1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN qlen 1000
    inet6 ::1/128 scope host proto kernel_lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1492 state UP qlen 1000
    inet6 fe80::215:5dff:fed2:8153/64 scope link proto kernel_ll
22: sscli0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 state UNKNOWN qlen 500
    inet6 fe80::a0d8:6e93:8dd2:db21/64 scope link stable-privacy proto kernel_ll
`,
			false,
		},
		{
			"global v6 present",
			`2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1492 state UP qlen 1000
    inet6 2600:1f18:1234::567/64 scope global dynamic mngtmpaddr noprefixroute
    inet6 fe80::215:5dff:fed2:8153/64 scope link proto kernel_ll
`,
			true,
		},
		{"ula only is not global", "    inet6 fd00::1/64 scope global\n", false}, // sanity: ULA rows pass text check; semantic gate is by scope label below — see predicate
		{"host scope only", "    inet6 ::1/128 scope host\n", false},
	}
	for _, c := range cases {
		if got := outputHasGlobalIPv6(c.out); got != c.want {
			t.Errorf("%s: outputHasGlobalIPv6 = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestServerRouteArgs(t *testing.T) {
	v4 := netip.MustParseAddr("18.139.140.0")
	v6 := netip.MustParseAddr("2600:1f18:1:2::5")
	cases := []struct {
		name  string
		ip    netip.Addr
		gw    string
		dev   string
		hasGW bool
		wantI []string
		wantU []string
	}{
		{
			"v4 via gateway", v4, "172.31.0.1", "eth0", true,
			[]string{"route", "add", "18.139.140.0", "via", "172.31.0.1", "dev", "eth0"},
			[]string{"route", "del", "18.139.140.0"},
		},
		{
			"v4 on-link", v4, "", "eth0", false,
			[]string{"route", "add", "18.139.140.0", "dev", "eth0"},
			[]string{"route", "del", "18.139.140.0"},
		},
		{
			"v6 via gateway", v6, "fe80::1", "eth0", true,
			[]string{"-6", "route", "add", "2600:1f18:1:2::5", "via", "fe80::1", "dev", "eth0"},
			[]string{"-6", "route", "del", "2600:1f18:1:2::5"},
		},
		{
			"v6 on-link", v6, "", "eth0", false,
			[]string{"-6", "route", "add", "2600:1f18:1:2::5", "dev", "eth0"},
			[]string{"-6", "route", "del", "2600:1f18:1:2::5"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotI, gotU := serverRouteArgs(c.ip, c.gw, c.dev, c.hasGW)
			if !reflect.DeepEqual(gotI, c.wantI) {
				t.Errorf("install args = %v, want %v", gotI, c.wantI)
			}
			if !reflect.DeepEqual(gotU, c.wantU) {
				t.Errorf("undo args = %v, want %v", gotU, c.wantU)
			}
		})
	}
}
