// Package network manages Linux routing state: TUN address, policy rules,
// per-table routes, and cleanup on exit.
//
// Safety contract (requirement 三十三): every mutation is recorded so Stop
// can undo it, and Stop must be idempotent — safe even after a crash of
// the forwarding loop, and safe to call twice.
package network

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"

	"github.com/Icestab/shadowsocks-linux-cli/internal/rules"
)

// Manager mutates routing state through the `ip` command (the approach
// used by leaf/tun2proxy: simple, debuggable, matches iproute2 docs).
type Manager struct {
	TUNName string
	Fwmark  int
	Table   int

	// originalDefault records the pre-existing default route(s) so we can
	// verify restoration after teardown.
	originalDefault []string

	// applied tracks successful operations for reverse-order rollback.
	applied []op
}

type op struct {
	undo []string // args for `ip` that revert this operation
	desc string
}

// NewManager builds a manager for the given TUN device.
func NewManager(tunName string, fwmark, table int) *Manager {
	return &Manager{TUNName: tunName, Fwmark: fwmark, Table: table}
}

func run(args ...string) error {
	cmd := exec.Command("ip", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runOK(args ...string) error { // runs command tolerating "already exists"
	err := run(args...)
	if err != nil && (strings.Contains(err.Error(), "File exists") || strings.Contains(err.Error(), "already exists")) {
		return nil
	}
	return err
}

// OriginalDefaultRoutes snapshots the current main-table default routes.
func (m *Manager) OriginalDefaultRoutes() ([]string, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	m.originalDefault = lines
	return lines, nil
}

// Setup performs the full policy-routing installation:
//
//  1. fwmark rule      : sscli's own marked sockets use MAIN (escape TUN)
//  2. private/LAN rules: every private range keeps using MAIN (LAN 直连)
//  3. server host-routes: EVERY resolved VPS address /32|/128 goes via the
//     original gateway so the un-marked sslocal subprocess cannot loop —
//     pinning only the first address would let a DNS round-robin server
//     re-enter the TUN and loop in bypass/global mode
//  4. lookup rule      : everything else consults TABLE -> TUN
//
// It assumes the caller already assigned an address to the TUN and brought
// it up (ConfigureTUN).
func (m *Manager) Setup(serverIPs []netip.Addr) error {
	if len(m.originalDefault) == 0 {
		if _, err := m.OriginalDefaultRoutes(); err != nil {
			return fmt.Errorf("snapshot original routes: %w", err)
		}
	}
	m.applied = m.applied[:0]

	install := func(args, undo []string, desc string) error {
		if err := runOK(args...); err != nil {
			return fmt.Errorf("setup %s: %w", desc, err)
		}
		m.applied = append(m.applied, op{undo: undo, desc: desc})
		return nil
	}

	// 1. sscli's own marked sockets escape the TUN. Policy rules are
	// per-address-family, so install for both v4 and v6.
	for _, fam := range [][]string{{}, {"-6"}} {
		args := append(append([]string{}, fam...),
			"rule", "add", "fwmark", fmt.Sprintf("%#x", m.Fwmark), "lookup", "main", "priority", "100")
		undo := append(append([]string{}, fam...),
			"rule", "del", "fwmark", fmt.Sprintf("%#x", m.Fwmark), "lookup", "main", "priority", "100")
		if err := install(args, undo, "fwmark bypass rule"); err != nil {
			m.Rollback()
			return err
		}
	}
	// 2. Private/LAN ranges always use MAIN (requirement: LAN 直连).
	// ip rule is family-scoped: IPv6 CIDRs must go through `ip -6 rule`.
	for _, cidr := range rules.PrivateCIDRs {
		fam := []string{"-6"}
		if !strings.Contains(cidr, ":") {
			fam = nil
		}
		prio := privateRulePriority(cidr)
		args := append(append([]string{}, fam...), "rule", "add", "to", cidr, "lookup", "main", "priority", prio)
		undo := append(append([]string{}, fam...), "rule", "del", "to", cidr, "lookup", "main", "priority", prio)
		if err := install(args, undo, "private bypass "+cidr); err != nil {
			m.Rollback()
			return err
		}
	}
	// 3. Server host-routes through the original gateway so the unmarked
	// sslocal subprocess cannot loop back into the TUN. One route per
	// resolved address (IPv6 uses the IPv6 default gateway when present;
	// with neither family default the /128 is skipped — the router pin
	// still prevents loops).
	gw4, dev4, hasGW4 := parseDefaultRoute(m.originalDefault)
	gw6, dev6, hasGW6 := parseDefaultRoute(m.originalDefault6())
	for _, ip := range serverIPs {
		if !ip.IsValid() {
			continue
		}
		var args, undo []string
		if ip.Is4() {
			if dev4 == "" {
				continue
			}
			args, undo = serverRouteArgs(ip, gw4, dev4, hasGW4)
		} else {
			if dev6 == "" {
				continue
			}
			args, undo = serverRouteArgs(ip, gw6, dev6, hasGW6)
		}
		if err := install(args, undo, "sslocal server bypass "+ip.String()); err != nil {
			m.Rollback()
			return err
		}
	}
	// 4. Everything else consults our table whose default is the TUN.
	for _, fam := range [][]string{{}, {"-6"}} {
		args := append(append([]string{}, fam...),
			"rule", "add", "lookup", fmt.Sprint(m.Table), "priority", "10000")
		undo := append(append([]string{}, fam...),
			"rule", "del", "lookup", fmt.Sprint(m.Table))
		if err := install(args, undo, "tun lookup rule"); err != nil {
			m.Rollback()
			return err
		}
	}
	if err := runOK("route", "add", "default", "dev", m.TUNName, "table", fmt.Sprint(m.Table)); err != nil {
		m.Rollback()
		return fmt.Errorf("add tun default route: %w", err)
	}
	m.applied = append(m.applied, op{
		undo: []string{"route", "del", "default", "dev", m.TUNName, "table", fmt.Sprint(m.Table)},
		desc: "tun default route",
	})
	// 4b. IPv6 default into the TUN — but ONLY when the host actually has a
	// global IPv6 address. The lookup rules are installed for both families,
	// and without a v6 default in our table a v6 lookup falls back to MAIN;
	// on hosts WITH global IPv6 that would let foreign v6 egress directly
	// (leak). On hosts with only link-local v6 (the common case), installing
	// the route is actively harmful: AAAA-driven v6 attempts would reach the
	// stack (the spoofed handshake succeeds), the app commits to IPv6, and
	// the v6 relay then often fails (e.g. the VPS has no IPv6), killing
	// connections mid-TLS that would otherwise have fallen back to IPv4
	// instantly at connect().
	if hostHasGlobalIPv6() {
		args := []string{"-6", "route", "add", "default", "dev", m.TUNName, "table", fmt.Sprint(m.Table)}
		undo := []string{"-6", "route", "del", "default", "dev", m.TUNName, "table", fmt.Sprint(m.Table)}
		if err := runOK(args...); err != nil {
			m.Rollback()
			return fmt.Errorf("add tun default route (v6): %w", err)
		}
		m.applied = append(m.applied, op{undo: undo, desc: "tun default route (v6)"})
	}
	return nil
}

// hostHasGlobalIPv6 reports whether any interface carries a global IPv6
// address; only then can v6 traffic exist that could leak past the TUN.
func hostHasGlobalIPv6() bool {
	out, err := exec.Command("ip", "-6", "addr", "show").Output()
	if err != nil {
		return false
	}
	return outputHasGlobalIPv6(string(out))
}

// outputHasGlobalIPv6 is the pure predicate behind hostHasGlobalIPv6,
// parseable in unit tests. ULA (fd00::/8) is excluded: it has local
// semantics and is already covered by the fc00::/7 -> main private rule,
// so it neither leaks nor needs TUN capture.
func outputHasGlobalIPv6(out string) bool {
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || f[0] != "inet6" || !strings.Contains(l, "scope global") {
			continue
		}
		addr := strings.SplitN(f[1], "/", 2)[0]
		if strings.HasPrefix(addr, "fd") { // ULA
			continue
		}
		return true
	}
	return false
}

func privateRulePriority(cidr string) string {
	// Stable distinct priorities inside [300, 399].
	sum := 0
	for _, b := range []byte(cidr) {
		sum += int(b)
	}
	return fmt.Sprint(300 + sum%100)
}

// originalDefault6 snapshots the IPv6 default route(s), best-effort:
// hosts without IPv6 yield nothing (and the caller then skips v6 pins).
func (m *Manager) originalDefault6() []string {
	out, err := exec.Command("ip", "-6", "route", "show", "default").Output()
	if err != nil {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// serverRouteArgs builds the `ip` command (and its undo) that pins one SS
// server address to the original default path. IPv4 addresses use the main
// table via the IPv4 gateway; IPv6 addresses go through `ip -6` via the
// IPv6 gateway (on-link when the default route has no gateway).
func serverRouteArgs(ip netip.Addr, gw, dev string, hasGW bool) (install, undo []string) {
	install = []string{"route", "add", ip.String()}
	undo = []string{"route", "del", ip.String()}
	if !ip.Is4() {
		install = append([]string{"-6"}, install...)
		undo = append([]string{"-6"}, undo...)
	}
	if hasGW {
		install = append(install, "via", gw)
	}
	return append(install, "dev", dev), undo
}

// parseDefaultRoute extracts "via GW dev DEV" from `ip route show default`.
func parseDefaultRoute(lines []string) (gw, dev string, ok bool) {
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) == 0 || f[0] != "default" {
			continue
		}
		for i := 1; i < len(f)-1; i++ {
			switch f[i] {
			case "via":
				gw = f[i+1]
				ok = true
			case "dev":
				dev = f[i+1]
			}
		}
		return gw, dev, dev != ""
	}
	return "", "", false
}

// Rollback undoes applied operations in reverse order, ignoring errors so
// best-effort cleanup always proceeds as far as possible.
func (m *Manager) Rollback() {
	for i := len(m.applied) - 1; i >= 0; i-- {
		o := m.applied[i]
		_ = runOK(o.undo...) //nolint:staticcheck // best-effort by design
	}
	m.applied = nil
}

// Teardown is Rollback plus a sweep for leftovers from a crashed previous
// instance (idempotent, safe at any time).
func (m *Manager) Teardown() error {
	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	m.Rollback()
	// Sweep leftovers regardless of m.applied state (crash recovery).
	for _, fam := range [][]string{{"-6"}, {}} {
		record(run(append(append([]string{}, fam...),
			"rule", "del", "fwmark", fmt.Sprintf("%#x", m.Fwmark))...))
		record(run(append(append([]string{}, fam...),
			"rule", "del", "lookup", fmt.Sprint(m.Table))...))
	}
	// 私有网段豁免也按族清扫。
	for _, cidr := range rules.PrivateCIDRs {
		fam := []string{"-6"}
		if !strings.Contains(cidr, ":") {
			fam = nil
		}
		record(run(append(fam, "rule", "del", "to", cidr, "lookup", "main",
			"priority", privateRulePriority(cidr))...))
	}
	// v4/v6 默认路由清扫（无条件尝试 v6：主机可能在本次会话中失去 v6，
// 已装的 v6 路由必须能删掉；无 v6 内核时 ip -6 报错属正常，best-effort）。
	record(run("route", "del", "default", "dev", m.TUNName, "table", fmt.Sprint(m.Table)))
	record(run("-6", "route", "del", "default", "dev", m.TUNName, "table", fmt.Sprint(m.Table)))
	return firstErr
}

// ConfigureTUN assigns addr/prefix to the TUN device and brings it up.
func ConfigureTUN(name, cidr string) error {
	ipAddr, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid tun address %q: %w", cidr, err)
	}
	prefixLen, _ := ipNet.Mask.Size()
	if err := runOK("addr", "add", ipAddr.String()+"/"+fmt.Sprint(prefixLen), "dev", name); err != nil {
		return fmt.Errorf("assign tun address: %w", err)
	}
	if err := run("link", "set", "dev", name, "up"); err != nil {
		return fmt.Errorf("bring tun up: %w", err)
	}
	return nil
}

// LinkExists reports whether the named link exists.
func LinkExists(name string) bool {
	return exec.Command("ip", "link", "show", "dev", name).Run() == nil
}

// DeleteLink removes the TUN interface (used on stop).
func DeleteLink(name string) error {
	return run("link", "del", "dev", name)
}
