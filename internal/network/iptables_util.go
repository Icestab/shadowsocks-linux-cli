package network

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// firewallBackend resolves once per call site: only the iptables-compatible
// interface is used (plain iptables or iptables-nft). Native `nft` is
// deliberately NOT mixed in — touching both backends independently risks
// corrupting the shared nftables view. Environments with neither get no
// firewall rules at all (callers degrade gracefully).
func firewallBackend() (string, bool) {
	for _, c := range []string{"iptables", "iptables-nft"} {
		if p, err := exec.LookPath(c); err == nil {
			return p, true
		}
	}
	return "", false
}

func iptablesRun(bin string, args ...string) (string, error) {
	full := append([]string{bin}, args...)
	cmd := exec.Command(full[0], full[1:]...) //nolint:gosec // fixed args we built
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// snapshotRules lists the current rules of (table, chain) as rulespec
// lines, e.g. "-A OUTPUT -m mark --mark 0x162 -j RETURN".
func snapshotRules(bin, table, chain string) ([]string, error) {
	out, err := iptablesRun(bin, "-t", table, "-S", chain)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "-A "+chain+" ") {
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

// saveRuleState persists the rule delta this process inserted so teardown
// can remove precisely those — never a user's pre-existing rules.
func saveRuleState(statePath string, delta []string) error {
	if err := os.MkdirAll(filepath.Dir(statePath), 0o750); err != nil {
		return err
	}
	return os.WriteFile(statePath, []byte(strings.Join(delta, "\n")), 0o600)
}

// loadRuleState reads back the rules previously saved by saveRuleState.
func loadRuleState(statePath string) []string {
	data, err := os.ReadFile(statePath)
	if err != nil {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "-A ") {
			lines = append(lines, l)
		}
	}
	return lines
}