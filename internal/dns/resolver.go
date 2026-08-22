package dns

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/Icestab/shadowsocks-linux-cli/internal/rules"
)

// Fwmark mirrors proxy.Fwmark (kept separate to avoid an import cycle):
// sockets carrying this mark escape the TUN policy routing.
const Fwmark = 0x162

// Resolver performs split-horizon resolution:
//   - domains matching the China list are resolved via domestic upstreams
//     (fast, correct CDN results, no pollution for those domains)
//   - everything else goes through the foreign upstreams; in gfw/bypass
//     mode those queries are sent through the PROXY path by pointing the
//     "foreign" upstream at sscli's own proxied resolver transport.
//
// Every answer is recorded in the Mapping so the router can later map an
// IP connection back to its domain (requirement 十六).
type Resolver struct {
	domestic []string // host:port of domestic upstreams
	foreign  []string // host:port of foreign upstreams
	china    *rules.DomainSet
	mapping  *Mapping
	timeout  time.Duration
	client   *mdns.Client

	// proxyDial, when set, routes foreign upstream queries through the
	// proxy (TCP DNS over the SOCKS5 endpoint) so plaintext queries never
	// leave the machine directly. Domestic queries stay local but are sent
	// with an fwmark so they escape the TUN instead of looping into it.
	proxyDial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewResolver builds a resolver. Upstreams must be "host:port" strings.
func NewResolver(domestic, foreign []string, china *rules.DomainSet, mapping *Mapping) *Resolver {
	if len(domestic) == 0 {
		domestic = []string{"223.5.5.5:53", "119.29.29.29:53"}
	}
	if len(foreign) == 0 {
		foreign = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}
	if mapping == nil {
		mapping = NewMapping(0, 0)
	}
	// Domestic UDP sockets carry the fwmark escape (tolerated as a no-op
	// without CAP_NET_ADMIN, e.g. in tests).
	c := &mdns.Client{Net: "udp", Timeout: 3 * time.Second}
	c.Dialer = &net.Dialer{
		Timeout: 3 * time.Second,
		Control: func(network, address string, conn syscall.RawConn) error {
			var ctlErr error
			err := conn.Control(func(fd uintptr) {
				ctlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, Fwmark)
			})
			if err != nil || ctlErr != nil {
				return nil //nolint:nilerr // best effort; only needed while TUN hijack is active
			}
			return nil
		},
	}
	return &Resolver{
		domestic: domestic,
		foreign:  foreign,
		china:    china,
		mapping:  mapping,
		timeout:  3 * time.Second,
		client:   c,
	}
}

// SetProxyDial installs a dialer used for foreign upstream queries. When
// set, foreign lookups are exchanged over TCP through this dialer (the
// SOCKS5 endpoint), keeping domain names off the local link in cleartext.
func (r *Resolver) SetProxyDial(fn func(ctx context.Context, network, addr string) (net.Conn, error)) {
	r.proxyDial = fn
}

// Mapping exposes the recorded domain->IP table.
func (r *Resolver) Mapping() *Mapping { return r.mapping }

// Resolve answers A/AAAA queries for domain, choosing upstreams per split
// rules and recording results. Returns IPs and TTL.
func (r *Resolver) Resolve(ctx context.Context, domain string, qtype uint16) ([]netip.Addr, uint32) {
	upstreams := r.foreign
	viaProxy := r.proxyDial != nil
	if r.china != nil && r.china.Contains(domain) {
		upstreams = r.domestic
		viaProxy = false // domestic upstreams stay direct (fwmark escape)
	}
	var lastErr error
	for _, up := range upstreams {
		addrs, ttl, err := r.queryUpstream(ctx, up, domain, qtype, viaProxy)
		if err != nil {
			lastErr = err
			continue
		}
		for _, a := range addrs {
			r.mapping.Record(domain, a, ttl)
		}
		return addrs, ttl
	}
	if lastErr != nil {
		return nil, 0
	}
	return nil, 0
}

func (r *Resolver) queryUpstream(ctx context.Context, upstream, domain string, qtype uint16, viaProxy bool) ([]netip.Addr, uint32, error) {
	q := new(mdns.Msg)
	q.SetQuestion(mdns.Fqdn(domain), qtype)
	q.RecursionDesired = true

	if viaProxy {
		return r.exchangeViaProxy(ctx, q, upstream, domain)
	}

	// miekg/dns Exchange does not take ctx; bound it via deadline client copy.
	c := *r.client
	c.Timeout = r.timeout
	done := make(chan result, 1)
	go func() {
		resp, _, err := c.Exchange(q, upstream)
		done <- result{resp, err}
	}()
	select {
	case res := <-done:
		if res.err != nil {
			return nil, 0, fmt.Errorf("query %s via %s: %w", domain, upstream, res.err)
		}
		return extractAddrs(res.resp, qtype)
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}
}

// exchangeViaProxy performs the DNS exchange over TCP through the proxy
// dialer. UDP is not an option here: the local SOCKS5 endpoint only
// supports TCP CONNECT.
func (r *Resolver) exchangeViaProxy(ctx context.Context, q *mdns.Msg, upstream, domain string) ([]netip.Addr, uint32, error) {
	raw, err := r.proxyDial(ctx, "tcp", upstream)
	if err != nil {
		return nil, 0, fmt.Errorf("proxy dial %s for %s: %w", upstream, domain, err)
	}
	conn := &mdns.Conn{Conn: raw}
	defer conn.Close() //nolint:errcheck

	c := mdns.Client{Net: "tcp", Timeout: r.timeout}
	done := make(chan result, 1)
	go func() {
		resp, _, err := c.ExchangeWithConn(q, conn)
		done <- result{resp, err}
	}()
	select {
	case res := <-done:
		if res.err != nil {
			return nil, 0, fmt.Errorf("query %s via %s (proxied): %w", domain, upstream, res.err)
		}
		return extractAddrs(res.resp, q.Question[0].Qtype)
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}
}

type result struct {
	resp *mdns.Msg
	err  error
}

func extractAddrs(resp *mdns.Msg, qtype uint16) ([]netip.Addr, uint32, error) {
	if resp == nil || resp.Rcode != mdns.RcodeSuccess {
		return nil, 0, fmt.Errorf("upstream returned rcode %v", respRcode(resp))
	}
	var (
		out []netip.Addr
		ttl uint32 = 300
	)
	for _, rr := range resp.Answer {
		var ip netip.Addr
		switch rec := rr.(type) {
		case *mdns.A:
			a4, ok := netip.AddrFromSlice(rec.A)
			if !ok {
				continue
			}
			ip = a4.Unmap()
		case *mdns.AAAA:
			a6, ok := netip.AddrFromSlice(rec.AAAA)
			if !ok {
				continue
			}
			ip = a6.Unmap()
		default:
			continue
		}
		out = append(out, ip)
		if h := rr.Header(); h != nil && h.Ttl > 0 && h.Ttl < ttl {
			ttl = h.Ttl
		}
	}
	return out, ttl, nil
}

func respRcode(resp *mdns.Msg) int {
	if resp == nil {
		return -1
	}
	return resp.Rcode
}

// LookupHost resolves domain to its first IPv4 address (helper for tests
// and `sscli dns`).
func (r *Resolver) LookupHost(ctx context.Context, domain string) (netip.Addr, error) {
	addrs, _ := r.Resolve(ctx, domain, mdns.TypeA)
	for _, a := range addrs {
		if a.Is4() || a.Is4In6() {
			return a.Unmap(), nil
		}
	}
	if len(addrs) == 0 {
		return netip.Addr{}, fmt.Errorf("no A record for %s", domain)
	}
	return addrs[0].Unmap(), nil
}
