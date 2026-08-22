package router

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindRuleFileUserDirWins(t *testing.T) {
	userRoot := t.TempDir()
	old := SystemRulesDir
	SystemRulesDir = filepath.Join(t.TempDir(), "etc-rules")
	defer func() { SystemRulesDir = old }()

	userFile := filepath.Join(userRoot, "rules", "gfw.list")
	os.MkdirAll(filepath.Dir(userFile), 0o755)
	os.WriteFile(userFile, []byte("user-copy"), 0o644)

	if got := findRuleFile("gfw.list"); got != userFile {
		t.Errorf("findRuleFile = %q, want user copy %q", got, userFile)
	}
}

func TestFindRuleFileFallsBackToSystem(t *testing.T) {
	sysDir := t.TempDir()
	old := SystemRulesDir
	SystemRulesDir = sysDir
	defer func() { SystemRulesDir = old }()

	sysFile := filepath.Join(sysDir, "china-domains.list")
	os.WriteFile(sysFile, []byte("server=/baidu.com/114.114.114.114\n"), 0o644)
	t.Setenv("HOME", t.TempDir()) // 用户目录为空

	if got := findRuleFile("china-domains.list"); got != sysFile {
		t.Errorf("findRuleFile = %q, want system copy %q", got, sysFile)
	}
	if got := findRuleFile("nonexistent.list"); got != "" {
		t.Errorf("missing file should resolve to \"\", got %q", got)
	}
}
