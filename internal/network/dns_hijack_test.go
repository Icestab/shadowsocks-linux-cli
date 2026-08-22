package network

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestComputeDeltaReturnsOnlyOurRules(t *testing.T) {
	pre := []string{
		"-A OUTPUT -o lo -j RETURN",
		"-A OUTPUT -m mark --mark 0x162 -j RETURN", // 用户原有的同规格规则！
	}
	post := append(append([]string{}, pre...),
		"-A OUTPUT -p udp -m udp --dport 53 -j REDIRECT --to-ports 53090",
		"-A OUTPUT -m mark --mark 0x162 -j RETURN", // 我们又插了一份同规格
	)
	delta := computeDelta(pre, post)
	want := []string{
		"-A OUTPUT -p udp -m udp --dport 53 -j REDIRECT --to-ports 53090",
		"-A OUTPUT -m mark --mark 0x162 -j RETURN", // 我们插入的第二份同规格规则
	}
	if !reflect.DeepEqual(delta, want) {
		t.Errorf("delta = %v; want %v", delta, want)
	}
}

func TestComputeDeltaEmpty(t *testing.T) {
	if d := computeDelta([]string{"-A OUTPUT -j ACCEPT"}, []string{"-A OUTPUT -j ACCEPT"}); len(d) != 0 {
		t.Errorf("expected empty delta, got %v", d)
	}
}

func TestHijackStateRoundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), HijackStateFileName)
	delta := []string{
		"-A OUTPUT -m mark --mark 0x162 -j RETURN",
		"-A OUTPUT -p tcp -m tcp --dport 53 -j REDIRECT --to-ports 53090",
	}
	if err := saveHijackState(path, delta); err != nil {
		t.Fatal(err)
	}
	got := loadHijackState(path)
	if !reflect.DeepEqual(got, delta) {
		t.Errorf("roundtrip = %v, want %v", got, delta)
	}
}

func TestLoadHijackStateMissingFile(t *testing.T) {
	if got := loadHijackState(filepath.Join(t.TempDir(), "nope")); len(got) != 0 {
		t.Errorf("missing state should be empty, got %v", got)
	}
}
