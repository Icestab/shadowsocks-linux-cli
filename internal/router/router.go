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

	"github.com/Icestab/sscli/internal/dns"
	"github.com/Icestab/sscli/internal/proxy"
	"github.com/Icestab/sscli/internal/rules"
)

// Router decides and establishes outbound connections.
type Router struct {
	engine  *rules.Engine
	mapping *dns.Mapping

	proxyDialer  proxy.Dialer
	directDialer proxy.Dialer
}

// New wires a router from an engine and the two outbound paths.
func New(engine *rules.Engine, mapping *dns.Mapping, proxyDialer, directDialer proxy.Dialer) *Router {
	if directDialer == nil {
		directDialer = &proxy.DirectDialer{}
	}
	return &Router{
		engine:       engine,
		mapping:      mapping,
		proxyDialer:  proxyDialer,
		directDialer: directDialer,
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
