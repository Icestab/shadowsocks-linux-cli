package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindPrefersUserPath(t *testing.T) {
	dir := t.TempDir()
	userCfg := filepath.Join(dir, "user.yaml")
	os.WriteFile(userCfg, []byte("mode: gfw\nserver: {address: a, port: 1, method: m, password: p}\n"), 0o600)

	t.Setenv("SSCLI_CONFIG", userCfg)
	got, err := Find()
	if err != nil || got != userCfg {
		t.Errorf("Find = %q, %v; want %q", got, err, userCfg)
	}
}

func TestFindFallsBackToSystemPath(t *testing.T) {
	sysCfg := filepath.Join(t.TempDir(), "etc-sscli.yaml")
	os.WriteFile(sysCfg, []byte("mode: gfw\n"), 0o600)
	old := SystemConfigPath
	SystemConfigPath = sysCfg
	defer func() { SystemConfigPath = old }()

	t.Setenv("SSCLI_CONFIG", "")
	t.Setenv("HOME", t.TempDir())
	got, err := Find()
	if err != nil || got != sysCfg {
		t.Errorf("Find = %q, %v; want %q", got, err, sysCfg)
	}
}

func TestFindReturnsPrimaryWhenNothingExists(t *testing.T) {
	old := SystemConfigPath
	SystemConfigPath = filepath.Join(t.TempDir(), "missing.yaml")
	defer func() { SystemConfigPath = old }()
	t.Setenv("SSCLI_CONFIG", "")
	t.Setenv("HOME", t.TempDir())
	got, err := Find()
	want := filepath.Join(os.Getenv("HOME"), ".config", "sscli", "config.yaml")
	if err != nil || got != want {
		t.Errorf("Find = %q, %v; want %q", got, err, want)
	}
}
