// Package config loads and validates the sscli YAML configuration.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Action is a routing decision for a matched rule.
type Action string

const (
	ActionDirect Action = "direct"
	ActionProxy  Action = "proxy"
)

// Mode selects the overall routing strategy.
type Mode string

const (
	ModeGFW    Mode = "gfw"
	ModeBypass Mode = "bypass"
	ModeGlobal Mode = "global"
)

func (m Mode) Validate() error {
	switch m {
	case ModeGFW, ModeBypass, ModeGlobal:
		return nil
	default:
		return fmt.Errorf("invalid mode %q (must be gfw, bypass or global)", m)
	}
}

// Server describes the Shadowsocks server and how sslocal reaches it.
type Server struct {
	Address  string `yaml:"address"`
	Port     int    `yaml:"port"`
	Method   string `yaml:"method"`
	Password string `yaml:"password"`
}

// TUN settings for the virtual network interface.
type TUN struct {
	Enabled bool   `yaml:"enabled"`
	Name    string `yaml:"name"`
	MTU     int    `yaml:"mtu"`
	Address string `yaml:"address"`
}

// DNS settings.
type DNS struct {
	Enabled  bool     `yaml:"enabled"`
	Hijack   []string `yaml:"hijack"`    // upstream resolvers used by sscli's internal resolver
	CacheTTL int      `yaml:"cache_ttl"` // seconds, minimum TTL kept in mapping table
}

// IPv6 leak protection switches.
type IPv6 struct {
	Enabled bool `yaml:"enabled"`
	Block   bool `yaml:"block"` // block IPv6 outbound when full v6 proxying is unsupported
}

// Rule is a user-defined routing rule from the config file.
type Rule struct {
	Domain       string `yaml:"domain,omitempty"`
	DomainSuffix string `yaml:"domain_suffix,omitempty"`
	IP           string `yaml:"ip,omitempty"`
	CIDR         string `yaml:"cidr,omitempty"`
	Action       Action `yaml:"action"`
}

// Log verbosity settings.
type Log struct {
	Level string `yaml:"level"` // debug|info|warn|error
	File  string `yaml:"file,omitempty"`
}

// Update settings for rule downloads.
type Update struct {
	GFWListURL      string `yaml:"gfwlist_url"`
	ChinaDomainsURL string `yaml:"china_domains_url"`
	ChinaIPv4URL    string `yaml:"china_ipv4_url"`
	ChinaIPv6URL    string `yaml:"china_ipv6_url,omitempty"`
	IntervalHours   int    `yaml:"interval_hours,omitempty"`
}

// Sslocal settings for the managed shadowsocks-rust subprocess.
type Sslocal struct {
	BinaryPath string `yaml:"binary_path"` // path to prebuilt sslocal binary
	SocksAddr  string `yaml:"socks_addr"`  // local SOCKS5 listen address
}

// Config is the root configuration document.
type Config struct {
	Mode    Mode    `yaml:"mode"`
	Server  Server  `yaml:"server"`
	TUN     TUN     `yaml:"tun"`
	DNS     DNS     `yaml:"dns"`
	IPv6    IPv6    `yaml:"ipv6"`
	Rules   []Rule  `yaml:"rules"`
	Log     Log     `yaml:"log"`
	Update  Update  `yaml:"update"`
	Sslocal Sslocal `yaml:"sslocal"`
}

// Defaults fills unset fields with sane values.
func (c *Config) Defaults() {
	if c.Mode == "" {
		c.Mode = ModeGFW
	}
	if c.TUN.Name == "" {
		c.TUN.Name = "sscli0"
	}
	if c.TUN.MTU == 0 {
		c.TUN.MTU = 1500
	}
	if c.TUN.Address == "" {
		c.TUN.Address = "198.18.0.1/15"
	}
	if len(c.DNS.Hijack) == 0 {
		c.DNS.Hijack = []string{"223.5.5.5", "119.29.29.29", "8.8.8.8"}
	}
	if c.DNS.CacheTTL == 0 {
		c.DNS.CacheTTL = 3600
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Sslocal.SocksAddr == "" {
		c.Sslocal.SocksAddr = "127.0.0.1:1080"
	}
	if c.Update.IntervalHours == 0 {
		c.Update.IntervalHours = 72
	}
}

// Validate checks semantic correctness of the config.
func (c *Config) Validate() error {
	if err := c.Mode.Validate(); err != nil {
		return err
	}
	if c.Server.Address == "" || c.Server.Port == 0 {
		return fmt.Errorf("server.address and server.port are required")
	}
	if c.Server.Method == "" || c.Server.Password == "" {
		return fmt.Errorf("server.method and server.password are required")
	}
	for i, r := range c.Rules {
		if r.Action != ActionDirect && r.Action != ActionProxy {
			return fmt.Errorf("rules[%d]: invalid action %q", i, r.Action)
		}
		n := 0
		for _, v := range []string{r.Domain, r.DomainSuffix, r.IP, r.CIDR} {
			if v != "" {
				n++
			}
		}
		if n != 1 {
			return fmt.Errorf("rules[%d]: exactly one of domain/domain_suffix/ip/cidr must be set", i)
		}
	}
	// The local SOCKS5 endpoint must stay loopback-only: binding it
	// anywhere else turns this box into an unauthenticated open proxy on
	// the LAN (any neighbour can relay through the VPS). Defaults() fills
	// 127.0.0.1:1080 when empty, so this catches explicit misconfig.
	if c.Sslocal.SocksAddr != "" {
		host, _, err := net.SplitHostPort(c.Sslocal.SocksAddr)
		if err != nil {
			return fmt.Errorf("sslocal.socks_addr %q: %w", c.Sslocal.SocksAddr, err)
		}
		switch host {
		case "localhost", "127.0.0.1", "::1":
		default:
			return fmt.Errorf("sslocal.socks_addr %q must be a loopback address; a non-loopback SOCKS5 listener is an unauthenticated open proxy", c.Sslocal.SocksAddr)
		}
	}
	return nil
}

// SystemConfigPath is the system-wide config location written by
// system-level installs. A variable so tests can point it elsewhere.
var SystemConfigPath = "/etc/sscli/config.yaml"

// DefaultDir returns ~/.config/sscli.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "sscli"), nil
}

// DefaultPath returns the primary config location
// (~/.config/sscli/config.yaml) — where `sscli config init` writes.
func DefaultPath() (string, error) {
	dir, err := DefaultDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

// Find returns the first existing config file among the supported
// locations: $SSCLI_CONFIG, ~/.config/sscli/config.yaml and the
// system-wide /etc/sscli/config.yaml (written by system-level installs).
// When nothing exists yet the primary user path is returned so callers
// can produce a useful "not found" message or create it there.
func Find() (string, error) {
	if p := os.Getenv("SSCLI_CONFIG"); p != "" {
		return p, nil
	}
	primary, err := DefaultPath()
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(primary); err == nil {
		return primary, nil
	}
	if _, err := os.Stat(SystemConfigPath); err == nil {
		return SystemConfigPath, nil
	}
	return primary, nil
}

// Load reads and parses the config file at path, applying defaults and validation.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	c := &Config{}
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	c.Defaults()
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return c, nil
}

// HijackAddrs returns the configured DNS hijack upstreams as host:port
// strings.
func (d DNS) HijackAddrs() []string {
	out := make([]string, 0, len(d.Hijack))
	for _, h := range d.Hijack {
		if net.ParseIP(h) != nil {
			out = append(out, h+":53")
		} else {
			out = append(out, h)
		}
	}
	return out
}

// SocksAddrSafe exposes the local SOCKS5 endpoint (not a secret).
func (s Sslocal) SocksAddrSafe() string { return s.SocksAddr }
