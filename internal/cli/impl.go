package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/Icestab/sscli/internal/config"
	"github.com/Icestab/sscli/internal/update"
)

// updateRules implements `sscli update` (requirement 二十九).
func updateRules(w io.Writer, cfg *config.Config) error {
	fmt.Fprintln(w, "Updating rules...")
	c := update.NewClient()
	if c.TryProxy(cfg.Sslocal.SocksAddr) {
		fmt.Fprintln(w, "(downloading via proxy — list fetches stay hidden from the local ISP)")
	} else {
		fmt.Fprintln(w, "warning: proxy not running; downloading directly (fetch targets are visible to your ISP)")
	}
	if err := c.UpdateAll(context.Background(), cfg, w); err != nil {
		return err
	}
	fmt.Fprintln(w, "\nRules updated successfully.")
	return nil
}

// showRules implements `sscli rules` (Phase 5+).
func showRules(w io.Writer, cfg *config.Config) error {
	fmt.Fprintf(w, "Custom rules: %d\n", len(cfg.Rules))
	for i, r := range cfg.Rules {
		subject := r.Domain
		if r.DomainSuffix != "" {
			subject = "*." + r.DomainSuffix
		} else if r.IP != "" {
			subject = r.IP
		} else if r.CIDR != "" {
			subject = r.CIDR
		}
		fmt.Fprintf(w, "  [%d] %-28s -> %s\n", i, subject, r.Action)
	}
	rulesDir := ""
	if dir, err := config.DefaultDir(); err == nil {
		rulesDir = dir + "/rules"
	}
	fmt.Fprintf(w, "Rule files directory: %s (run 'sscli rules' after Phase 8 lists file stats)\n", rulesDir)
	return nil
}

// showConfig prints the effective configuration with secrets redacted.
func showConfig(w io.Writer, cfg *config.Config) {
	pw := "<set>"
	if cfg.Server.Password == "" {
		pw = "<empty>"
	}
	fmt.Fprintf(w, "mode:            %s\n", cfg.Mode)
	fmt.Fprintf(w, "server.address:  %s\n", cfg.Server.Address)
	fmt.Fprintf(w, "server.port:     %d\n", cfg.Server.Port)
	fmt.Fprintf(w, "server.method:   %s\n", cfg.Server.Method)
	fmt.Fprintf(w, "server.password: %s\n", pw)
	fmt.Fprintf(w, "tun.name:        %s\n", cfg.TUN.Name)
	fmt.Fprintf(w, "tun.mtu:         %d\n", cfg.TUN.MTU)
	fmt.Fprintf(w, "tun.address:     %s\n", cfg.TUN.Address)
	fmt.Fprintf(w, "dns.enabled:     %v\n", cfg.DNS.Enabled)
	fmt.Fprintf(w, "ipv6.enabled:    %v\n", cfg.IPv6.Enabled)
	fmt.Fprintf(w, "ipv6.block:      %v\n", cfg.IPv6.Block)
	fmt.Fprintf(w, "sslocal.socks:   %s\n", cfg.Sslocal.SocksAddr)
	fmt.Fprintf(w, "custom rules:    %d\n", len(cfg.Rules))
}
