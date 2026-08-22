package daemon

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/Icestab/shadowsocks-linux-cli/internal/config"
	"github.com/Icestab/shadowsocks-linux-cli/internal/network"
)

// Status reports current runtime state (requirement 二十一).
func Status(w io.Writer) error {
	cfgPath, err := config.DefaultPath()
	if err != nil {
		return err
	}
	var cfg *config.Config
	if _, err := os.Stat(cfgPath); err == nil {
		cfg, _ = config.Load(cfgPath)
	}

	fmt.Fprintln(w, "sscli status")
	running, pid := isRunning()
	if running {
		fmt.Fprintf(w, "\nStatus:       Running (pid %d)\n", pid)
	} else {
		fmt.Fprintln(w, "\nStatus:       Stopped")
	}
	if cfg != nil {
		mode := string(cfg.Mode)
		fmt.Fprintf(w, "Mode:         %s\n", strings.ToUpper(mode[:1])+mode[1:])
		fmt.Fprintf(w, "TUN:          %s\n", cfg.TUN.Name)
		fmt.Fprintf(w, "TUN address:  %s\n", cfg.TUN.Address)
		fmt.Fprintf(w, "Shadowsocks:  %s\n", ternary(running, "Connected via sslocal", "Stopped"))
		// The server endpoint identifies the user's VPS: mask it unless
		// explicitly requested (SSCLI_SHOW_SERVER=full), so pasted
		// diagnostics do not leak it.
		addr := MaskServer(cfg.Server.Address)
		if os.Getenv("SSCLI_SHOW_SERVER") == "full" {
			addr = cfg.Server.Address
		}
		fmt.Fprintf(w, "Server:       %s:%d (%s)\n", addr, cfg.Server.Port, cfg.Server.Method)
		fmt.Fprintf(w, "DNS:          %s\n", ternary(running && cfg.DNS.Enabled, "Running", "Stopped"))
	}

	rulesDir := ""
	if d, err := config.DefaultDir(); err == nil {
		rulesDir = d + "/rules"
	}
	fmt.Fprintf(w, "\nRules (%s):\n", rulesDir)
	for _, name := range []string{"gfw.list", "china-domains.list", "china-ipv4.list"} {
		p := rulesDir + "/" + name
		info, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(w, "  %-18s not downloaded\n", name)
			continue
		}
		fmt.Fprintf(w, "  %-18s updated %s\n", name, info.ModTime().Format("2006-01-02"))
	}

	if !running {
		return nil
	}
	fmt.Fprintf(w, "\nRouting:\n")
	tunName := defaultTunName()
	if cfg != nil {
		tunName = cfg.TUN.Name
	}
	fmt.Fprintf(w, "  TUN link:      %s\n", ternary(network.LinkExists(tunName), "UP", "DOWN"))
	nm := network.NewManager(tunName, 0, routingTable)
	defs, err := nm.OriginalDefaultRoutes()
	if err == nil && len(defs) > 0 {
		mainDefault := ""
		for _, d := range defs {
			mainDefault = d
		}
		fmt.Fprintf(w, "  main default:  %s\n", mainDefault)
	}
	out, err := ipRuleList()
	if err == nil && out != "" {
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, strconv.Itoa(routingTable)) || strings.Contains(l, fmt.Sprintf("%#x", 0x162)) {
				fmt.Fprintf(w, "  rule: %s\n", strings.TrimSpace(l))
			}
		}
	}
	return nil
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

// MaskServer hides most of the server endpoint for display. Literal IPs
// keep their first two octets ("203.0.x.x"); domains keep the first label
// character and the TLD ("e******.com").
func MaskServer(addr string) string {
	if ip := net.ParseIP(addr); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return fmt.Sprintf("%d.%d.x.x", v4[0], v4[1])
		}
		h := ip.String()
		return h[:4] + "::::"
	}
	labels := strings.Split(strings.TrimSuffix(addr, "."), ".")
	if len(labels) < 2 {
		return "***"
	}
	first, tld := labels[0], labels[len(labels)-1]
	if first == "" {
		first = "*"
	}
	keep := string(first[0])
	return keep + "***." + tld
}

func ipRuleList() (string, error) {
	out, err := exec.Command("ip", "rule", "show").Output()
	return string(out), err
}
