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

	"github.com/dy/sscli/internal/rules"
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
//  3. server host-route: VPS /32 goes via the original gateway so the
//     un-marked sslocal subprocess cannot loop
//  4. lookup rule      : everything else consults TABLE -> TUN
//
// It assumes the caller already assigned an address to the TUN and brought
// it up (ConfigureTUN).
func (m *Manager) Setup(serverIP netip.Addr) error {
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

	// 1. sscli's own marked sockets escape the TUN.
	if err := install(
		[]string{"rule", "add", "fwmark", fmt.Sprintf("%#x", m.Fwmark), "lookup", "main", "priority", "100"},
		[]string{"rule", "del", "fwmark", fmt.Sprintf("%#x", m.Fwmark), "lookup", "main", "priority", "100"},
		"fwmark bypass rule"); err != nil {
		m.Rollback()
		return err
	}
	// 2. Private/LAN ranges always use MAIN (requirement: LAN 直连).
	for _, cidr := range rules.PrivateCIDRs {
		prio := privateRulePriority(cidr)
		if err := install(
			[]string{"rule", "add", "to", cidr, "lookup", "main", "priority", prio},
			[]string{"rule", "del", "to", cidr, "lookup", "main", "priority", prio},
			"private bypass "+cidr); err != nil {
			m.Rollback()
			return err
		}
	}
	// 3. Server host-route through the original gateway so the unmarked
	// sslocal subprocess cannot loop back into the TUN.
	gw, devName, hasGW := parseDefaultRoute(m.originalDefault)
	if serverIP.IsValid() && devName != "" {
		var args []string
		if hasGW {
			args = []string{"route", "add", serverIP.String(), "via", gw, "dev", devName}
		} else {
			args = []string{"route", "add", serverIP.String(), "dev", devName}
		}
		if err := install(args,
			[]string{"route", "del", serverIP.String()},
			"sslocal server bypass"); err != nil {
			m.Rollback()
			return err
		}
	}
	// 4. Everything else consults our table whose default is the TUN.
	if err := install(
		[]string{"rule", "add", "lookup", fmt.Sprint(m.Table), "priority", "10000"},
		[]string{"rule", "del", "lookup", fmt.Sprint(m.Table)},
		"tun lookup rule"); err != nil {
		m.Rollback()
		return err
	}
	if err := runOK("route", "add", "default", "dev", m.TUNName, "table", fmt.Sprint(m.Table)); err != nil {
		m.Rollback()
		return fmt.Errorf("add tun default route: %w", err)
	}
	m.applied = append(m.applied, op{
		undo: []string{"route", "del", "default", "dev", m.TUNName, "table", fmt.Sprint(m.Table)},
		desc: "tun default route",
	})
	return nil
}

func privateRulePriority(cidr string) string {
	// Stable distinct priorities inside [300, 399].
	sum := 0
	for _, b := range []byte(cidr) {
		sum += int(b)
	}
	return fmt.Sprint(300 + sum%100)
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
	record(run("rule", "del", "fwmark", fmt.Sprintf("%#x", m.Fwmark)))
	record(run("rule", "del", "lookup", fmt.Sprint(m.Table)))
	record(run("route", "del", "default", "dev", m.TUNName, "table", fmt.Sprint(m.Table)))
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
