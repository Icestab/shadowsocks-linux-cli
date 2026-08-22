package dns

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/Icestab/shadowsocks-linux-cli/internal/rules"
)

func TestMappingRecordAndLookup(t *testing.T) {
	m := NewMapping(2*time.Second, time.Minute)
	ip := netip.MustParseAddr("140.82.112.3")
	m.Record("github.com", ip, 300)

	if got := m.DomainForIP(ip); got != "github.com" {
		t.Errorf("DomainForIP = %q, want github.com", got)
	}
	// CDN case: several domains share one IP; most recent wins.
	ip2 := netip.MustParseAddr("104.16.0.1")
	m.Record("a.example.com", ip2, 300)
	time.Sleep(5 * time.Millisecond)
	m.Record("b.example.com", ip2, 300)
	if got := m.DomainForIP(ip2); got != "b.example.com" {
		t.Errorf("most-recent domain = %q, want b.example.com", got)
	}
	// Case and trailing dot normalisation.
	m.Record("WWW.Example.COM.", ip2, 60)
	if got := m.Len(); got != 2 {
		t.Errorf("Len = %d, want 2 (no duplicate for case variants)", got)
	}
}

func TestMappingExpiry(t *testing.T) {
	m := NewMapping(time.Millisecond, 10*time.Millisecond)
	now := time.Now()
	m.nowFunc = func() time.Time { return now }
	ip := netip.MustParseAddr("1.2.3.4")
	m.Record("gone.example", ip, 1) // clamped to minTTL=1ms
	now = now.Add(50 * time.Millisecond)
	if got := m.DomainForIP(ip); got != "" {
		t.Errorf("expired entry returned %q", got)
	}
}

func TestServerHandlesAQuery(t *testing.T) {
	// Use a fake upstream served by our own test DNS server so the test
	// never touches the network.
	upstream := mdns.NewServeMux()
	upstream.HandleFunc("origin.test.", func(w mdns.ResponseWriter, r *mdns.Msg) {
		resp := new(mdns.Msg)
		resp.SetReply(r)
		resp.Answer = append(resp.Answer, &mdns.A{
			Hdr: mdns.RR_Header{Name: r.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 120},
			A:   net.IP{93, 184, 216, 34},
		})
		_ = w.WriteMsg(resp)
	})
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upSrv := &mdns.Server{PacketConn: pc, Handler: upstream}
	defer upSrv.Shutdown()
	go func() { _ = upSrv.ActivateAndServe() }()
	upAddr := pc.LocalAddr().String()

	china := rules.NewDomainSet()
	resolver := NewResolver([]string{upAddr}, []string{upAddr}, china, nil)
	srv := NewServer(resolver, nil)

	req := new(mdns.Msg)
	req.SetQuestion("www.origin.test.", mdns.TypeA)
	resp := srv.HandleMsg(context.Background(), req)
	if resp.Rcode != mdns.RcodeSuccess {
		t.Fatalf("rcode = %d", resp.Rcode)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(resp.Answer))
	}
	a, ok := resp.Answer[0].(*mdns.A)
	if !ok {
		t.Fatalf("answer type %T, want A", resp.Answer[0])
	}
	if a.A.String() != "93.184.216.34" {
		t.Errorf("answer A = %s", a.A.String())
	}
	// The mapping must now know the domain for that IP.
	ip := netip.MustParseAddr("93.184.216.34")
	if got := resolver.Mapping().DomainForIP(ip); got != "www.origin.test" {
		t.Errorf("mapping domain = %q", got)
	}
}

func TestResolverSplitRouting(t *testing.T) {
	china := rules.NewDomainSet()
	china.AddSuffix("baidu.cn")
	r := NewResolver(nil, nil, china, nil)
	ctx := context.Background()
	// Just verify Resolve returns quickly with unreachable upstreams
	// rather than hanging (timeout bound).
	start := time.Now()
	_, _ = r.Resolve(ctx, "whatever.io", mdns.TypeA)
	if elapsed := time.Since(start); elapsed > 8*time.Second {
		t.Errorf("Resolve took %v with dead upstreams; timeout not bounded", elapsed)
	}
}

// TestForeignQueriesViaProxyDial verifies that when a proxy dialer is
// installed, foreign upstream queries are exchanged over TCP through that
// dialer instead of plaintext UDP from the local machine.
func TestForeignQueriesViaProxyDial(t *testing.T) {
	// Fake "proxied" upstream: a plain TCP DNS server.
	mux := mdns.NewServeMux()
	mux.HandleFunc("foreign.test.", func(w mdns.ResponseWriter, r *mdns.Msg) {
		resp := new(mdns.Msg)
		resp.SetReply(r)
		resp.Answer = append(resp.Answer, &mdns.A{
			Hdr: mdns.RR_Header{Name: r.Question[0].Name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
			A:   net.IP{1, 2, 3, 4},
		})
		_ = w.WriteMsg(resp)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &mdns.Server{Listener: ln, Handler: mux}
	defer srv.Shutdown()
	go func() { _ = srv.ActivateAndServe() }()

	china := rules.NewDomainSet() // nothing is domestic -> everything foreign
	resolver := NewResolver(nil, []string{ln.Addr().String()}, china, nil)

	var dialed int
	resolver.SetProxyDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" {
			t.Errorf("proxy dial network = %q, want tcp", network)
		}
		dialed++
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	})

	addrs, ttl, ok := func() ([]netip.Addr, uint32, bool) {
		a, ttl := resolver.Resolve(context.Background(), "host.foreign.test", mdns.TypeA)
		return a, ttl, len(a) > 0
	}()
	if !ok || dialed == 0 {
		t.Fatalf("foreign resolve did not go through the proxy dialer (addrs=%v dialed=%d)", addrs, dialed)
	}
	if got := resolver.Mapping().DomainForIP(netip.MustParseAddr("1.2.3.4")); got != "host.foreign.test" {
		t.Errorf("mapping domain = %q", got)
	}
	_ = ttl
}
