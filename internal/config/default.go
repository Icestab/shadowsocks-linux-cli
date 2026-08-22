package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// defaultConfigTemplate is written by `sscli config init`. Placeholders in
// <...> must be filled by the user.
const defaultConfigTemplate = `# sscli configuration
# Full reference: https://github.com/Icestab/sscli (docs/config.md)

# Routing mode: gfw | bypass | global
mode: gfw

# Shadowsocks server (handled by sslocal; sscli never logs the password)
server:
  address: <your.server.example.com>
  port: 443
  method: aes-256-gcm
  password: "<your-password>"

# TUN device
tun:
  enabled: true
  name: sscli0
  mtu: 1500
  address: 198.18.0.1/15

# DNS module intercepts queries to build the domain -> IP mapping used by
# the router.
dns:
  enabled: true
  hijack:
    - 223.5.5.5      # AliDNS (domestic)
    - 119.29.29.29   # DNSPod (domestic)
    - 8.8.8.8        # Google (for proxied domains)
  cache_ttl: 3600

# IPv6: full v6 proxying is planned but not implemented yet; keep block=true
# to avoid IPv6 leaking past the proxy.
ipv6:
  enabled: false
  block: true

# User-defined rules, evaluated after Private/LAN and before list rules.
rules:
  - domain: github.com
    action: proxy
  - domain_suffix: internal.corp
    action: direct

log:
  level: info

update:
  gfwlist_url: https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt
  china_domains_url: https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf
  china_ipv4_url: https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt
  interval_hours: 72

# Managed sslocal subprocess (prebuilt shadowsocks-rust binary).
sslocal:
  binary_path: /usr/local/bin/sslocal
  socks_addr: 127.0.0.1:1080
`

// InitDefault writes the commented default config to path if it does not
// already exist. The file is created with mode 0600 because it holds secrets.
func InitDefault(path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists (refusing to overwrite)", path)
	}
	dir := parentDir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(defaultConfigTemplate), 0o600); err != nil {
		return err
	}
	fmt.Printf("Wrote %s — edit server settings before running 'sudo sscli start'.\n", path)
	return nil
}

// SetMode atomically rewrites only the top-level "mode" key of the YAML
// file at path, preserving comments and key order as much as yaml.v3 Node
// allows.
func SetMode(path string, next Mode) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return fmt.Errorf("config is empty")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("config root must be a mapping")
	}
	found := false
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "mode" {
			root.Content[i+1].Value = string(next)
			root.Content[i+1].Tag = "!!str"
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("config has no top-level 'mode' key")
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil { // config may contain secrets: keep 0600
		return err
	}
	return os.Rename(tmp, path)
}

func parentDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
