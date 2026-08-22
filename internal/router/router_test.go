package router

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/Icestab/shadowsocks-linux-cli/internal/dns"
	"github.com/Icestab/shadowsocks-linux-cli/internal/rules"
)

// countingDialer never touches the network; it only records calls.
type countingDialer struct{ hits *int }

func (l countingDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	*l.hits++
	return nil, context.Canceled // sentinel: path selection already verified
}

func TestDecisionForIPWithMapping(t *testing.T) {
	mapping := dns.NewMapping(0, 0)
	engine := rules.NewEngine(rules.ModeGFW)
	engine.GFWList().AddSuffix("github.com")

	ip := netip.MustParseAddr("140.82.112.3")
	mapping.Record("github.com", ip, 300) // as if DNS answered earlier

	r := New(engine, mapping, countingDialer{}, countingDialer{}, netip.Addr{})
	dec, domain, level := r.DecisionFor("140.82.112.3:443")
	if dec != rules.Proxy {
		t.Errorf("decision = %v, want PROXY via mapping", dec)
	}
	if domain != "github.com" {
		t.Errorf("domain = %q", domain)
	}
	if level != "gfw-list" {
		t.Errorf("level = %q", level)
	}
}

func TestDecisionUnknownIPFallsToModeDefault(t *testing.T) {
	mapping := dns.NewMapping(0, 0)
	e := rules.NewEngine(rules.ModeGFW)
	r := New(e, mapping, countingDialer{}, countingDialer{}, netip.Addr{})
	dec, _, _ := r.DecisionFor("203.0.113.9:443")
	if dec != rules.Direct {
		t.Errorf("gfw mode unknown IP = %v, want DIRECT", dec)
	}
}

func TestServerIPAlwaysDirect(t *testing.T) {
	// Even in bypass mode the VPS address itself must never be PROXY:
	// sslocal's unmarked connection to it re-enters the TUN, and a PROXY
	// decision would loop it back into sslocal forever.
	mapping := dns.NewMapping(0, 0)
	e := rules.NewEngine(rules.ModeBypass)
	srv := netip.MustParseAddr("18.139.140.0")
	r := New(e, mapping, countingDialer{}, countingDialer{}, srv)
	dec, _, level := r.DecisionFor("18.139.140.0:27314")
	if dec != rules.Direct {
		t.Errorf("server IP = %v, want DIRECT (loop prevention)", dec)
	}
	if level != "server-bypass" {
		t.Errorf("level = %q, want server-bypass", level)
	}
	// A mapping entry for the server's domain must not flip it either.
	mapping.Record("lightsail4.122113.xyz", srv, 300)
	dec, _, _ = r.DecisionFor("18.139.140.0:27314")
	if dec != rules.Direct {
		t.Errorf("server IP with mapping = %v, want DIRECT", dec)
	}
}

func TestDialUsesSelectedPath(t *testing.T) {
	mapping := dns.NewMapping(0, 0)
	e := rules.NewEngine(rules.ModeBypass)
	e.ChinaDomains().AddSuffix("baidu.cn")
	proxyHits, directHits := 0, 0
	r := New(e, mapping, countingDialer{hits: &proxyHits}, countingDialer{hits: &directHits}, netip.Addr{})

	ctx := context.Background()
	// Foreign IP in bypass mode -> PROXY path.
	if _, _, err := r.Dial(ctx, "tcp", "203.0.113.5:443"); err == nil {
		t.Errorf("expected sentinel error from counting dialer")
	}
	if proxyHits != 1 {
		t.Errorf("proxy hits = %d, want 1", proxyHits)
	}
	// Private IP -> DIRECT path even in bypass mode.
	if _, _, err := r.Dial(ctx, "tcp", "192.168.1.1:80"); err == nil {
		t.Errorf("expected sentinel error")
	}
	if directHits != 1 {
		t.Errorf("direct hits = %d, want 1", directHits)
	}
}
