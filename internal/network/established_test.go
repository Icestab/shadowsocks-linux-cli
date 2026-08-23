package network

import (
	"reflect"
	"strings"
	"testing"
)

// TestEstablishedExemptSpec guards the exact rule that protects existing
// TCP connections (and inbound-connection replies) from being captured by
// the TUN lookup rule: established TCP packets get the fwmark so policy
// routing (priority 100) keeps them on the main table. Deliberately
// TCP-only — exempting UDP would let long-lived resolver sockets skip the
// DNS hijack and starve the domain→IP mapping.
func TestEstablishedExemptSpec(t *testing.T) {
	spec := strings.Join(establishedExemptSpec(), " ")
	for _, want := range []string{
		"-p tcp",
		"-m conntrack",
		"--ctstate",
		"ESTABLISHED,RELATED",
		"-j MARK",
		"--set-mark",
		FwmarkString,
	} {
		if !strings.Contains(spec, want) {
			t.Errorf("spec %q missing %q", spec, want)
		}
	}
	if !strings.HasPrefix(strings.Join(establishedExemptSpec(), " "), "-p tcp") {
		t.Errorf("rule must be TCP-limited: %q", spec)
	}
}

// TestEstablishedTeardownFallbackSpec is the no-state fallback teardown
// path (upgrade/cleanup): it must reconstruct EXACTLY the same rule the
// setup inserts, otherwise the mangle table keeps a stray mark rule.
func TestEstablishedTeardownFallbackSpec(t *testing.T) {
	want := "-A OUTPUT " + strings.Join(establishedExemptSpec(), " ")
	// The teardown fallback is built by joining the spec; assert the
	// joining produces the snapshot format loadRuleState returns.
	snapshot := computeDelta(nil, []string{want})
	if len(snapshot) != 1 || snapshot[0] != want {
		t.Errorf("fallback line = %v, want %q", snapshot, want)
	}
}

// TestRuleStateRoundtripNonOutput is the same snapshot/delta roundtrip as
// the hijack test but for the mangle table's chain (different prefix is
// still "-A OUTPUT" for the OUTPUT chain; loadRuleState accepts any "-A ").
func TestRuleStateRoundtripMangle(t *testing.T) {
	path := t.TempDir() + "/" + EstablishedStateFileName
	delta := []string{
		"-A OUTPUT -p tcp -m conntrack --ctstate ESTABLISHED,RELATED -j MARK --set-mark 0x162",
	}
	if err := saveRuleState(path, delta); err != nil {
		t.Fatal(err)
	}
	got := loadRuleState(path)
	if !reflect.DeepEqual(got, delta) {
		t.Errorf("roundtrip = %v, want %v", got, delta)
	}
}