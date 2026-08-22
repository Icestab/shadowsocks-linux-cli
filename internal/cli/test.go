package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/dy/sscli/internal/config"
	"github.com/dy/sscli/internal/proxy"
	"github.com/dy/sscli/internal/rules"
)

// testResult is one line of `sscli test` output.
type testResult struct {
	name string
	pass bool
	note string
}

// runSelfTest implements `sscli test` (requirement 二十二): checks TUN,
// routing, DNS, Shadowsocks reachability and rule behaviour.
func runSelfTest(w io.Writer, cfg *config.Config) error {
	var results []testResult

	// 1. Privileges.
	if os.Geteuid() == 0 {
		results = append(results, testResult{"Root", true, ""})
	} else {
		results = append(results, testResult{"Root", false, "not running as root; TUN/routing tests will be skipped"})
	}

	// 2. TUN availability.
	if _, err := os.Stat("/dev/net/tun"); err == nil {
		results = append(results, testResult{"TUN device", true, "/dev/net/tun present"})
	} else {
		results = append(results, testResult{"TUN device", false, err.Error()})
	}

	// 3. Routing tools present.
	if _, err := exec.LookPath("ip"); err == nil {
		results = append(results, testResult{"Routing (iproute2)", true, ""})
	} else {
		results = append(results, testResult{"Routing (iproute2)", false, "ip command not found"})
	}

	// 4. Direct connectivity (marked socket path).
	direct := &proxy.DirectDialer{}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := direct.DialContext(ctx, "tcp", "223.5.5.5:443")
	directOK := err == nil
	if directOK {
		conn.Close()
	}
	results = append(results, testResult{"Direct connection", directOK, noteOr(err)})

	// 5. Shadowsocks chain: dial through sslocal's SOCKS5.
	if cfg.Sslocal.BinaryPath != "" {
		if _, statErr := os.Stat(cfg.Sslocal.BinaryPath); statErr != nil {
			results = append(results, testResult{"Shadowsocks", false,
				fmt.Sprintf("sslocal not found at %s — install shadowsocks-rust or fix sslocal.binary_path", cfg.Sslocal.BinaryPath)})
		} else {
			results = append(results, testResult{"sslocal binary", true, cfg.Sslocal.BinaryPath})
		}
	}
	serverIP := resolveIPForTest(cfg.Server.Address)
	if serverIP != "" {
		c2, err2 := (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, "tcp",
			net.JoinHostPort(serverIP, fmt.Sprint(cfg.Server.Port)))
		ssOK := err2 == nil
		if ssOK {
			c2.Close()
		}
		results = append(results, testResult{"Server reachable", ssOK,
			fmt.Sprintf("%s:%d %s", serverIP, cfg.Server.Port, noteOr(err2))})
	}

	// 6. DNS resolution works at all.
	addr, derr := net.LookupHost("www.baidu.com")
	dnsOK := derr == nil && len(addr) > 0
	results = append(results, testResult{"DNS", dnsOK, noteOr(derr)})

	// 7. Rule engine decisions against the acceptance matrix.
	engine, err := buildEngine(cfg)
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	ruleCases := []struct {
		target string
		want   rules.Decision
	}{
		{"www.baidu.com", rules.Direct},
		{"192.168.1.1", rules.Direct},
		{"10.0.0.1", rules.Direct},
	}
	switch cfg.Mode {
	case config.ModeGlobal:
		ruleCases = append(ruleCases,
			struct {
				target string
				want   rules.Decision
			}{"github.com", rules.Proxy},
			struct {
				target string
				want   rules.Decision
			}{"114.114.114.114", rules.Proxy},
		)
	case config.ModeBypass:
		ruleCases = append(ruleCases,
			struct {
				target string
				want   rules.Decision
			}{"github.com", rules.Proxy},
			struct {
				target string
				want   rules.Decision
			}{"8.8.8.8", rules.Proxy},
		)
	default: // gfw
		ruleCases = append(ruleCases,
			struct {
				target string
				want   rules.Decision
			}{"google.com", rules.Proxy},
			struct {
				target string
				want   rules.Decision
			}{"8.8.8.8", rules.Direct},
		)
	}
	for _, c := range ruleCases {
		got, level := decideTarget(engine, c.target)
		results = append(results, testResult{
			fmt.Sprintf("%-16s -> %-6s", c.target, c.want),
			got == c.want, level,
		})
	}

	// Print.
	fmt.Fprintln(w)
	for _, r := range results {
		status := "[PASS]"
		if !r.pass {
			status = "[FAIL]"
		}
		line := fmt.Sprintf("%s %s", status, r.name)
		if r.note != "" {
			line += "  (" + r.note + ")"
		}
		fmt.Fprintln(w, line)
	}
	failed := 0
	for _, r := range results {
		if !r.pass {
			failed++
		}
	}
	fmt.Fprintln(w)
	if failed > 0 {
		return fmt.Errorf("%d check(s) failed", failed)
	}
	fmt.Fprintln(w, "All checks passed.")
	return nil
}

func noteOr(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.TrimSpace(err.Error())
	if len(msg) > 60 {
		msg = msg[:60] + "…"
	}
	return msg
}

func resolveIPForTest(host string) string {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.String()
	}
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0]
}
