package cli

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/dy/sscli/internal/config"
	"github.com/dy/sscli/internal/dns"
	"github.com/dy/sscli/internal/proxy"
	"github.com/dy/sscli/internal/router"
	"github.com/dy/sscli/internal/rules"
)

// buildEngine loads config custom rules plus downloaded rule files.
func buildEngine(cfg *config.Config) (*rules.Engine, error) {
	return router.LoadEngine(cfg)
}

// showRoute implements `sscli route [target...]`: prints the routing
// decision for each target (domain or IP).
func showRoute(w io.Writer, cfg *config.Config, targets []string) error {
	engine, err := buildEngine(cfg)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Fprintf(w, "Mode: %s — pass domains or IPs to evaluate, e.g.\n", cfg.Mode)
		fmt.Fprintln(w, "  sscli route github.com baidu.com 192.168.1.1")
		return nil
	}
	for _, t := range targets {
		dec, level := decideTarget(engine, t)
		fmt.Fprintf(w, "%-32s %-6s (%s)\n", t, dec, level)
	}
	return nil
}

func decideTarget(engine *rules.Engine, target string) (rules.Decision, string) {
	if strings.Contains(target, "/") { // CIDR
		p, err := netip.ParsePrefix(target)
		if err == nil {
			return engine.Decide("", p.Addr()), engineLevel(engine, "", p.Addr())
		}
	}
	if ip, err := netip.ParseAddr(strings.Trim(target, "[]")); err == nil {
		return engine.Decide("", ip), engineLevel(engine, "", ip)
	}
	host := target
	if ap, err := netip.ParseAddrPort(target); err == nil {
		host = ap.Addr().String()
	} else if i := strings.LastIndex(target, ":"); i > 0 && !strings.Contains(target[i:], "]") {
		host = target[:i]
	}
	return engine.Decide(host, netip.Addr{}), engineLevel(engine, host, netip.Addr{})
}

func engineLevel(e *rules.Engine, d string, ip netip.Addr) string {
	_, lvl := e.Explain(d, ip)
	return lvl
}

// dnsQuery implements `sscli dns <domain>` (requirement 十五): resolves via
// the split resolver and shows which path the connection would take.
func dnsQuery(w io.Writer, cfg *config.Config, domain string) error {
	engine, err := buildEngine(cfg)
	if err != nil {
		return err
	}
	mapping := dns.NewMapping(0, 0)
	resolver := dns.NewResolver(cfg.DNS.HijackAddrs(), nil, engine.ChinaDomains(), mapping)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	ip, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", domain, err)
	}
	fmt.Fprintf(w, "Domain:     %s\n", domain)
	fmt.Fprintf(w, "Resolved:   %s (%d ms)\n", ip, time.Since(start).Milliseconds())
	dec, level := engine.Explain(domain, ip)
	fmt.Fprintf(w, "Rule:       %s\n", level)
	fmt.Fprintf(w, "Outbound:   %s\n", dec)
	if dec == rules.Proxy && cfg.Sslocal.SocksAddr != "" {
		fmt.Fprintf(w, "Via:        SOCKS5 %s -> sslocal -> server\n", cfg.Sslocal.SocksAddr)
	} else if dec == rules.Direct {
		fmt.Fprintf(w, "Via:        DIRECT (fwmark %#x escape)\n", proxy.Fwmark)
	}
	return nil
}
