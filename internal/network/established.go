package network

import (
	"fmt"
	"os"
	"strings"
)

// EstablishedStateFileName is appended to the state directory; it records
// the exact established-exemption rule this process inserted so teardown
// can remove precisely that rule.
var EstablishedStateFileName = "established-mark.rules"

// establishedExemptSpec is the single mangle OUTPUT rule we manage:
// packets of ALREADY-ESTABLISHED TCP connections (and ICMP errors related
// to them) get the fwmark, which the policy routing (priority 100) sends
// straight to the main table.
//
// Why: without this, the TUN lookup rule (priority 10000) captures EVERY
// non-private destination — including reply packets of connections that
// existed before sscli started (an SSH session into this very machine).
// The gvisor forwarder only accepts SYNs, so those established TCP data
// segments are swallowed in userspace and the remote session dies; new
// inbound connections die too, because their SYN-ACKs are equally
// non-SYN segments. Exempting ESTABLISHED/RELATED TCP keeps existing
// sessions and inbound-connection replies on the original path, while
// NEW outbound connections (SYN, no conntrack state yet) still enter the
// TUN and get split-routed as before.
//
// TCP-only on purpose: a UDP "flow" with an established conntrack entry
// (e.g. a long-lived resolver socket) must NOT be exempted — it would
// skip the DNS hijack and starve the domain→IP mapping. Pre-existing UDP
// flows don't need the exemption either: the gvisor UDP forwarder accepts
// any datagram, so they survive via the relay path.
func establishedExemptSpec() []string {
	return []string{"-p", "tcp", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "MARK", "--set-mark", FwmarkString}
}

// SetupEstablishedExempt inserts the exemption into the mangle OUTPUT
// chain (before any routing decision) and records the delta. Best-effort:
// without an iptables-compatible backend it is a no-op (existing
// connections will then be disrupted — degrade matches the DNS hijack).
func SetupEstablishedExempt(statePath string) error {
	bin, ok := firewallBackend()
	if !ok {
		return nil
	}
	pre, err := snapshotRules(bin, "mangle", "OUTPUT")
	if err != nil {
		return fmt.Errorf("snapshot pre-state: %w", err)
	}
	args := append([]string{"-t", "mangle", "-I", "OUTPUT", "1"}, establishedExemptSpec()...)
	if out, err := iptablesRun(bin, args...); err != nil {
		return fmt.Errorf("insert established-exempt rule: %w: %s", err, strings.TrimSpace(out))
	}
	post, err := snapshotRules(bin, "mangle", "OUTPUT")
	if err != nil {
		return fmt.Errorf("snapshot post-state: %w", err)
	}
	delta := computeDelta(pre, post)
	if len(delta) != 1 {
		// 插入数量与预期不符：回滚本次新增，避免留下半条规则。
		for _, d := range delta {
			spec := strings.Fields(strings.TrimPrefix(d, "-A OUTPUT "))
			del := append([]string{"-t", "mangle", "-D", "OUTPUT"}, spec...)
			_, _ = iptablesRun(bin, del...) //nolint:errcheck // best-effort rollback
		}
		return fmt.Errorf("established exempt: inserted %d rules, expected 1; rolled back", len(delta))
	}
	if err := saveRuleState(statePath, delta); err != nil {
		return fmt.Errorf("persist established state: %w", err)
	}
	return nil
}

// TeardownEstablishedExempt removes exactly the rule recorded in
// statePath (idempotent: missing state or missing rule are both fine).
// Falls back to the well-known spec when no state exists (upgrade path).
func TeardownEstablishedExempt(statePath string) error {
	bin, ok := firewallBackend()
	if !ok {
		return nil
	}
	delta := loadRuleState(statePath)
	if len(delta) == 0 {
		delta = []string{"-A OUTPUT " + strings.Join(establishedExemptSpec(), " ")}
	} else {
		os.Remove(statePath) //nolint:errcheck // consumed
	}
	var firstErr error
	for _, line := range delta {
		spec := strings.Fields(strings.TrimPrefix(line, "-A OUTPUT "))
		args := append([]string{"-t", "mangle", "-D", "OUTPUT"}, spec...)
		if out, err := iptablesRun(bin, args...); err != nil &&
			!strings.Contains(out, "does not exist") {
			if firstErr == nil {
				firstErr = fmt.Errorf("delete %q: %w: %s", line, err, strings.TrimSpace(out))
			}
		}
	}
	return firstErr
}