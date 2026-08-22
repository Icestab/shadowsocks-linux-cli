package rules

import (
	"net/netip"
	"strings"
)

// Mode mirrors config.Mode to avoid an import cycle; values are identical.
type Mode string

const (
	ModeGFW    Mode = "gfw"
	ModeBypass Mode = "bypass"
	ModeGlobal Mode = "global"
)

// CustomRule is one user-defined rule from config.yaml or custom.list.
type CustomRule struct {
	Domain       string
	DomainSuffix string
	IP           netip.Addr
	CIDR         netip.Prefix
	Action       Decision
}

// Engine evaluates routing decisions with the documented priority order:
//
//  1. Private / LAN          -> DIRECT (reserved, always first)
//  2. User-defined rules     -> action
//  3. China domains          -> DIRECT (gfw/bypass only)
//  4. China IPs              -> DIRECT (gfw/bypass only)
//  5. GFW List               -> PROXY
//  6. Mode default           -> DIRECT (gfw) | PROXY (bypass/global)
//
// In global mode levels 3 and 4 are skipped so Chinese sites go through the
// proxy; only Private/LAN stays DIRECT.
type Engine struct {
	privateV4   *CIDRSet // LAN/private ranges incl. the TUN's own 198.18.0.0/15
	privateV6   *CIDRSet
	custom      []CustomRule
	chinaDomain *DomainSet
	chinaIP     *CIDRSet
	gfw         *DomainSet
	mode        Mode
}

// NewEngine builds an engine. Nil sets are treated as empty.
func NewEngine(mode Mode) *Engine {
	if mode == "" {
		mode = ModeGFW
	}
	pv4, pv6 := PrivateSets()
	return &Engine{
		privateV4:   pv4,
		privateV6:   pv6,
		chinaDomain: NewDomainSet(),
		chinaIP:     NewCIDRSet(),
		gfw:         NewDomainSet(),
		mode:        mode,
	}
}

// SetMode changes the active mode at runtime.
func (e *Engine) SetMode(m Mode) { e.mode = m }

// Mode returns the active mode.
func (e *Engine) Mode() Mode { return e.mode }

// SetCustom changes the user-defined rules (evaluated in order at priority 2).
func (e *Engine) SetCustom(rules []CustomRule) { e.custom = rules }

// Custom returns the current user-defined rules.
func (e *Engine) Custom() []CustomRule { return e.custom }

// Sets exposes the list-backed sets for loading rule files.
func (e *Engine) ChinaDomains() *DomainSet { return e.chinaDomain }
func (e *Engine) GFWList() *DomainSet      { return e.gfw }
func (e *Engine) ChinaIP() *CIDRSet        { return e.chinaIP }

// Decide returns the routing decision for a connection identified by an
// optional domain and/or destination IP. At least one should be valid;
// with neither, only the mode default applies.
func (e *Engine) Decide(domain string, ip netip.Addr) Decision {
	// 1. Private / LAN (system-reserved, applies in every mode).
	if ip.IsValid() {
		if ip.Is4() || ip.Is4In6() {
			if e.privateV4.Contains(ip.Unmap()) {
				return Direct
			}
		} else if e.privateV6.Contains(ip) {
			return Direct
		}
	}

	d := normalizeDomain(domain)

	// 2. User-defined rules, first match wins.
	for _, r := range e.custom {
		switch {
		case r.Domain != "":
			if d != "" && d == normalizeDomain(r.Domain) {
				return r.Action
			}
		case r.DomainSuffix != "":
			if d != "" && suffixMatch(d, normalizeDomain(r.DomainSuffix)) {
				return r.Action
			}
		case r.IP.IsValid():
			if ip.IsValid() && ip == r.IP {
				return r.Action
			}
		case r.CIDR.IsValid():
			if ip.IsValid() && r.CIDR.Contains(ip.Unmap()) {
				return r.Action
			}
		}
	}

	// 3+4. China lists do not apply in global mode.
	if e.mode != ModeGlobal {
		// 3. China domains.
		if d != "" && e.chinaDomain.Contains(d) {
			return Direct
		}
		// 4. China IPs.
		if ip.IsValid() && e.chinaIP.Contains(ip.Unmap()) {
			return Direct
		}
	}

	// 5. GFW List.
	if d != "" && e.gfw.Contains(d) {
		return Proxy
	}

	// 6. Mode default.
	switch e.mode {
	case ModeGFW:
		return Direct
	default: // bypass, global
		return Proxy
	}
}

// Explain returns the decision plus the rule level that produced it,
// useful for `sscli route` and debug logs.
func (e *Engine) Explain(domain string, ip netip.Addr) (Decision, string) {
	dec := e.Decide(domain, ip)
	level := e.explainLevel(domain, ip)
	return dec, level
}

func (e *Engine) explainLevel(domain string, ip netip.Addr) string {
	d := normalizeDomain(domain)
	if ip.IsValid() && (e.privateV4.Contains(ip.Unmap()) || e.privateV6.Contains(ip)) {
		return "private-lan"
	}
	for _, r := range e.custom {
		switch {
		case r.Domain != "":
			if d == normalizeDomain(r.Domain) {
				return "custom"
			}
		case r.DomainSuffix != "":
			if suffixMatch(d, normalizeDomain(r.DomainSuffix)) {
				return "custom"
			}
		case r.IP.IsValid():
			if ip.IsValid() && ip == r.IP {
				return "custom"
			}
		case r.CIDR.IsValid():
			if ip.IsValid() && r.CIDR.Contains(ip.Unmap()) {
				return "custom"
			}
		}
	}
	if e.mode != ModeGlobal {
		if d != "" && e.chinaDomain.Contains(d) {
			return "china-domain"
		}
		if ip.IsValid() && e.chinaIP.Contains(ip.Unmap()) {
			return "china-ip"
		}
	}
	if d != "" && e.gfw.Contains(d) {
		return "gfw-list"
	}
	return "mode-default:" + string(e.mode)
}

func suffixMatch(domain, suffix string) bool {
	return domain == suffix || strings.HasSuffix(domain, "."+suffix)
}
