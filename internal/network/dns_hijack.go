package network

import (
	"fmt"
	"os/exec"
	"strings"
)

// DNSHijackPort is the local port of sscli's internal DNS server
// (daemon.dnsListener). Locally generated DNS queries are REDIRECTed here
// so every lookup flows through sscli's resolver — this fills the
// domain→IP mapping the router needs for domain-based decisions
// (requirement 十六). Without it, system resolvers on private addresses
// bypass the TUN entirely and the mapping stays empty.
const DNSHijackPort = 53090

// fwmarkValue mirrors proxy.Fwmark (kept separate to avoid an import
// cycle): our own resolver's upstream sockets carry this mark and must be
// exempted from the redirect to prevent a self-loop.
const fwmarkValue = 0x162

// dnsHijackRules returns the iptables invocations in insertion order.
// Order matters: exempt marked sockets first, then redirect port 53.
func dnsHijackRules() [][]string {
	return [][]string{
		{"-t", "nat", "-I", "OUTPUT", "1", "-m", "mark", "--mark", fmt.Sprint(fwmarkValue), "-j", "RETURN"},
		{"-t", "nat", "-I", "OUTPUT", "2", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", fmt.Sprint(DNSHijackPort)},
		{"-t", "nat", "-I", "OUTPUT", "3", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", fmt.Sprint(DNSHijackPort)},
	}
}

// dnsHijackDelete converts an insert invocation into its delete form:
// "-I CHAIN POS ..." becomes "-D CHAIN ...".
func dnsHijackDelete(insert []string) []string {
	out := make([]string, 0, len(insert))
	for i, a := range insert {
		if i == 4 { // the position argument of -I
			continue
		}
		if i == 3 {
			out = append(out, "-D")
			continue
		}
		out = append(out, a)
	}
	return out
}

func haveIPTables() bool {
	for _, c := range []string{"iptables", "iptables-nft"} {
		if _, err := exec.LookPath(c); err == nil {
			return true
		}
	}
	return false
}

// SetupDNSHijack installs the OUTPUT-chain redirects. Best-effort:
// environments without iptables keep working (domain rules degrade to
// IP-only matching).
func SetupDNSHijack() error {
	if !haveIPTables() {
		return nil
	}
	for _, r := range dnsHijackRules() {
		full := append([]string{"iptables"}, r...)
		cmd := exec.Command(full[0], full[1:]...) //nolint:gosec // fixed args we built
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("dns hijack: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// TeardownDNSHijack removes the redirects in reverse order. Idempotent and
// best-effort: deleting a non-existent rule is treated as success so crash
// recovery always proceeds.
func TeardownDNSHijack() error {
	if !haveIPTables() {
		return nil
	}
	rules := dnsHijackRules()
	var firstErr error
	for i := len(rules) - 1; i >= 0; i-- {
		del := append([]string{"iptables"}, dnsHijackDelete(rules[i])...)
		cmd := exec.Command(del[0], del[1:]...) //nolint:gosec // fixed args we built
		if out, err := cmd.CombinedOutput(); err != nil &&
			!strings.Contains(string(out), "No such file or directory") &&
			!strings.Contains(string(out), "does not exist") {
			if firstErr == nil {
				firstErr = fmt.Errorf("dns hijack teardown: %w: %s", err, strings.TrimSpace(string(out)))
			}
		}
	}
	return firstErr
}
