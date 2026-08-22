// Package router binds the rule engine to outbound dialers: every flow is
// decided DIRECT or PROXY here, decoupled from any concrete proxy
// implementation (requirement 三十: Outbound abstraction).
package router

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/Icestab/shadowsocks-linux-cli/internal/dns"
	"github.com/Icestab/shadowsocks-linux-cli/internal/proxy"
	"github.com/Icestab/shadowsocks-linux-cli/internal/rules"
)

// Router decides and establishes outbound connections.
type Router struct {
	engine  *rules.Engine
	mapping *dns.Mapping

	proxyDialer  proxy.Dialer
	directDialer proxy.Dialer

	// serverIP is the resolved Shadowsocks server address. Traffic to it is
	// always DIRECT: the un-marked sslocal subprocess is captured by the
	// TUN policy routing ("everything else -> TUN"), and if its own
	// connection to the VPS were re-decided PROXY (e.g. the bypass/global
	// mode default, or a mapping entry carrying the server's domain), it
	// would loop back into sslocal forever.
	serverIP netip.Addr
}

// New wires a router from an engine and the two outbound paths. serverIP is
// the SS server address resolved before routing changes; pass an invalid
// Addr to disable the VPS loop-prevention pin.
func New(engine *rules.Engine, mapping *dns.Mapping, proxyDialer, directDialer proxy.Dialer, serverIP netip.Addr) *Router {
	if directDialer == nil {
		directDialer = &proxy.DirectDialer{}
	}
	return &Router{
		engine:       engine,
		mapping:      mapping,
		proxyDialer:  proxyDialer,
		directDialer: directDialer,
		serverIP:     serverIP,
	}
}

// Engine exposes the rule engine (mode switches, stats).
func (r *Router) Engine() *rules.Engine { return r.engine }

// DecisionFor resolves the routing decision for an address ("host:port").
// When the host is not an IP literal, the DNS mapping table is consulted to
// recover the domain an earlier query recorded for it; domain rules then
// apply as usual.
func (r *Router) DecisionFor(addr string) (rules.Decision, string, string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := parseHostIP(host)
	// The SS server address is pinned DIRECT before any rule evaluation
	// (loop prevention; see New). This also covers the case where the DNS
	// mapping recorded the server's domain for its IP.
	if ip.IsValid() && r.serverIP.IsValid() && ip == r.serverIP {
		return rules.Direct, "", "server-bypass"
	}
	domain := ""
	if !ip.IsValid() || ip.IsUnspecified() {
		domain = host
	}
	if r.mapping != nil && ip.IsValid() {
		if d := r.mapping.DomainForIP(ip); d != "" {
			domain = d
		}
	}
	dec := r.engine.Decide(domain, ip)
	return dec, domain, explain(r.engine, domain, ip)
}

// Dial connects to addr through the path selected by the rules.
func (r *Router) Dial(ctx context.Context, network, addr string) (net.Conn, rules.Decision, error) {
	dec, _, _ := r.DecisionFor(addr)
	var d proxy.Dialer
	switch dec {
	case rules.Proxy:
		d = r.proxyDialer
	default:
		d = r.directDialer
	}
	if d == nil {
		return nil, dec, fmt.Errorf("no outbound configured for %s", dec)
	}
	conn, err := d.DialContext(ctx, network, addr)
	return conn, dec, err
}

func parseHostIP(host string) netip.Addr {
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}
	}
	return ip
}

func explain(e *rules.Engine, domain string, ip netip.Addr) string {
	dec, level := e.Explain(domain, ip)
	_ = dec
	return level
}
