package network

import (
	"os/exec"
	"strings"
	"testing"
)

// These tests exercise only read-only helpers and pure logic; they never
// mutate the host routing table (Setup/Teardown are covered by the
// integration harness run manually with root, see docs/testing.md).

func TestLinkExistsFalseForBogusName(t *testing.T) {
	if LinkExists("sscli-definitely-not-exist") {
		t.Fatal("bogus link reported as existing")
	}
}

func TestOriginalDefaultRoutesParses(t *testing.T) {
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip not available")
	}
	m := NewManager("sscli0", FwmarkTest, TableTest)
	routes, err := m.OriginalDefaultRoutes()
	if err != nil {
		t.Fatalf("show default routes: %v", err)
	}
	for _, r := range routes {
		if strings.Contains(r, "\n") {
			t.Errorf("route line contains newline: %q", r)
		}
	}
}

const (
	FwmarkTest = 0x162
	TableTest  = 5162
)
