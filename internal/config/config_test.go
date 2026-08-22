package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
mode: bypass
server:
  address: example.com
  port: 443
  method: aes-256-gcm
  password: "secret"
tun:
  name: sscli0
  mtu: 1500
dns:
  enabled: true
rules:
  - domain: github.com
    action: proxy
  - domain_suffix: example.cn
    action: direct
  - cidr: 192.168.100.0/24
    action: direct
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Mode != ModeBypass {
		t.Errorf("mode = %q, want bypass", cfg.Mode)
	}
	if cfg.TUN.MTU != 1500 {
		t.Errorf("mtu = %d", cfg.TUN.MTU)
	}
	// Defaults applied:
	if len(cfg.DNS.Hijack) == 0 {
		t.Error("DNS hijack defaults not applied")
	}
	if cfg.Sslocal.SocksAddr != "127.0.0.1:1080" {
		t.Errorf("socks addr default = %q", cfg.Sslocal.SocksAddr)
	}
	if len(cfg.Rules) != 3 {
		t.Errorf("rules = %d, want 3", len(cfg.Rules))
	}
}

func TestLoadRejectsBadMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
mode: turbo
server:
  address: example.com
  port: 443
  method: aes-256-gcm
  password: "x"
`
	os.WriteFile(path, []byte(yaml), 0o600)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestValidateRequiresServer(t *testing.T) {
	c := &Config{Mode: ModeGFW}
	c.Defaults()
	if err := c.Validate(); err == nil {
		t.Fatal("expected error when server is missing")
	}
}

func TestRuleValidation(t *testing.T) {
	c := &Config{
		Mode:   ModeGFW,
		Server: Server{Address: "a", Port: 1, Method: "aes-256-gcm", Password: "p"},
		Rules:  []Rule{{Domain: "a.com", DomainSuffix: "b.com", Action: ActionDirect}},
	}
	c.Defaults()
	if err := c.Validate(); err == nil {
		t.Fatal("expected error when rule sets multiple matchers")
	}
}

func TestModeSwitchPreservesOtherKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := `
mode: gfw
server:
  address: example.com
  port: 8388
  method: aes-256-gcm
  password: "keepme"
rules:
  - domain: github.com
    action: proxy
`
	os.WriteFile(path, []byte(yaml), 0o600)
	if err := SetMode(path, ModeGlobal); err != nil {
		t.Fatalf("setConfigMode: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if cfg.Mode != ModeGlobal {
		t.Errorf("mode = %q, want global", cfg.Mode)
	}
	if cfg.Server.Password != "keepme" || cfg.Server.Port != 8388 {
		t.Errorf("other keys not preserved: %+v", cfg.Server)
	}
	if len(cfg.Rules) != 1 {
		t.Errorf("rules lost after mode switch")
	}
}
