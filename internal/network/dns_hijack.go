package network

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DNSHijackPort is the local port of sscli's internal DNS server
// (daemon.dnsListener). Locally generated DNS queries are REDIRECTed here
// so every lookup flows through sscli's resolver — this fills the
// domain→IP mapping the router needs for domain-based decisions
// (requirement 十六).
const DNSHijackPort = 53090

// FwmarkString mirrors proxy.Fwmark as an iptables literal.
const FwmarkString = "0x162"

// HijackStateFileName is appended to the state directory; it records the exact
// rules this process inserted so teardown can remove precisely those —
// never a user's pre-existing rules.
var HijackStateFileName = "dns-hijack.rules"

// firewallBackend resolves once per call site: only the iptables-compatible
// interface is used (plain iptables or iptables-nft). Native `nft` is
// deliberately NOT mixed in — touching both backends independently risks
// corrupting the shared nftables view. Environments with neither get no
// DNS hijack at all (domain rules degrade to IP-only matching).
func firewallBackend() (string, bool) {
	for _, c := range []string{"iptables", "iptables-nft"} {
		if p, err := exec.LookPath(c); err == nil {
			return p, true
		}
	}
	return "", false
}

// dnsHijackSpecs returns the rulespec bodies (without chain/action prefix)
// of the three rules we manage, in insertion order. Order matters: exempt
// marked sockets first, then redirect port 53.
func dnsHijackSpecs() [][]string {
	return [][]string{
		{"-m", "mark", "--mark", FwmarkString, "-j", "RETURN"},
		{"-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", fmt.Sprint(DNSHijackPort)},
		{"-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", fmt.Sprint(DNSHijackPort)},
	}
}

func iptablesRun(bin string, args ...string) (string, error) {
	full := append([]string{bin}, args...)
	cmd := exec.Command(full[0], full[1:]...) //nolint:gosec // fixed args we built
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// snapshotOutputRules lists current nat OUTPUT rules as rulespec lines,
// e.g. "-A OUTPUT -m mark --mark 0x162 -j RETURN".
func snapshotOutputRules(bin string) ([]string, error) {
	out, err := iptablesRun(bin, "-t", "nat", "-S", "OUTPUT")
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "-A OUTPUT ") {
			lines = append(lines, l)
		}
	}
	return lines, nil
}

// specKey normalizes a snapshot line into a comparable key.
func specKey(line string) string {
	return strings.Join(strings.Fields(line), " ")
}

// computeDelta returns the multiset difference post - pre: exactly the
// rules WE added.
func computeDelta(pre, post []string) []string {
	counts := map[string]int{}
	for _, l := range pre {
		counts[specKey(l)]++
	}
	var delta []string
	for _, l := range post {
		k := specKey(l)
		if counts[k] > 0 {
			counts[k]--
			continue
		}
		delta = append(delta, l)
	}
	return delta
}

func saveHijackState(statePath string, delta []string) error {
	if err := os.MkdirAll(filepath.Dir(statePath), 0o750); err != nil {
		return err
	}
	return os.WriteFile(statePath, []byte(strings.Join(delta, "\n")), 0o600)
}

func loadHijackState(statePath string) []string {
	data, err := os.ReadFile(statePath)
	if err != nil {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "-A OUTPUT ") {
			lines = append(lines, l)
		}
	}
	return lines
}

// SetupDNSHijack inserts the redirects and records the exact delta to
// statePath. Best-effort: without an iptables-compatible backend it is a
// no-op (domain rules degrade to IP-only matching).
func SetupDNSHijack(statePath string) error {
	bin, ok := firewallBackend()
	if !ok {
		return nil
	}
	pre, err := snapshotOutputRules(bin)
	if err != nil {
		return fmt.Errorf("snapshot pre-state: %w", err)
	}
	pos := 1
	for _, spec := range dnsHijackSpecs() {
		args := append([]string{"-t", "nat", "-I", "OUTPUT", fmt.Sprint(pos)}, spec...)
		if out, err := iptablesRun(bin, args...); err != nil {
			return fmt.Errorf("insert dns hijack rule: %w: %s", err, strings.TrimSpace(out))
		}
		pos++
	}
	post, err := snapshotOutputRules(bin)
	if err != nil {
		return fmt.Errorf("snapshot post-state: %w", err)
	}
	delta := computeDelta(pre, post)
	if len(delta) != len(dnsHijackSpecs()) {
		// 插入数量与预期不符：回滚本次全部新增，避免留下半套规则。
		for _, d := range delta {
			spec := strings.Fields(strings.TrimPrefix(d, "-A OUTPUT "))
			del := append([]string{"-t", "nat", "-D", "OUTPUT"}, spec...)
			_, _ = iptablesRun(bin, del...) //nolint:errcheck // best-effort rollback
		}
		return fmt.Errorf("dns hijack: inserted %d rules, expected %d; rolled back",
			len(delta), len(dnsHijackSpecs()))
	}
	if err := saveHijackState(statePath, delta); err != nil {
		return fmt.Errorf("persist hijack state: %w", err)
	}
	return nil
}

// TeardownDNSHijack removes exactly the rules recorded in statePath
// (idempotent: missing state or missing rules are both fine). Falls back
// to the well-known specs when no state exists (upgrade path).
func TeardownDNSHijack(statePath string) error {
	bin, ok := firewallBackend()
	if !ok {
		return nil
	}
	delta := loadHijackState(statePath)
	if len(delta) == 0 {
		for _, spec := range dnsHijackSpecs() {
			delta = append(delta, "-A OUTPUT "+strings.Join(spec, " "))
		}
	} else {
		os.Remove(statePath) //nolint:errcheck // consumed
	}
	var firstErr error
	for _, line := range delta {
		spec := strings.Fields(strings.TrimPrefix(line, "-A OUTPUT "))
		args := append([]string{"-t", "nat", "-D", "OUTPUT"}, spec...)
		if out, err := iptablesRun(bin, args...); err != nil &&
			!strings.Contains(out, "does not exist") {
			if firstErr == nil {
				firstErr = fmt.Errorf("delete %q: %w: %s", line, err, strings.TrimSpace(out))
			}
		}
	}
	return firstErr
}
