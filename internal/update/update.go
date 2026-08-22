// Package update implements `sscli update`: download, validate, and
// atomically replace rule files. Download or parse failures never destroy
// existing rules (requirement 二十九).
package update

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/net/proxy"

	"github.com/Icestab/sscli/internal/config"
	"github.com/Icestab/sscli/internal/router"
)

// Result reports one list update.
type Result struct {
	Name    string
	OK      bool
	Skipped bool // no URL configured
	Err     error
}

// Client downloads rules. Timeout is per-request.
type Client struct {
	HTTP *http.Client
}

func NewClient() *Client {
	return &Client{HTTP: &http.Client{Timeout: 60 * time.Second}}
}

// TryProxy routes subsequent downloads through the local SOCKS5 endpoint so
// rule fetches (e.g. the GFW List) are not visible to the local ISP as a
// usage fingerprint. Returns true when the endpoint answered and downloads
// will be proxied; false leaves the direct transport in place (first-run
// bootstrap, before sslocal exists).
func (c *Client) TryProxy(socksAddr string) bool {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.Dial("tcp", socksAddr)
	if err != nil {
		return false
	}
	conn.Close() //nolint:errcheck // probe only

	sd, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return false
	}
	cd, ok := sd.(proxy.ContextDialer)
	if !ok {
		return false
	}
	c.HTTP.Transport = &http.Transport{
		DialContext:           cd.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	return true
}

// UpdateAll refreshes GFW List, China domains and China IPs.
func (c *Client) UpdateAll(ctx context.Context, cfg *config.Config, out io.Writer) error {
	dir := router.RulesDir(mustConfigDir())
	// 0750: rule files themselves are public lists, but keep the directory
	// from being world-traversable next to private config material.
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	jobs := []struct {
		name string
		url  string
		file string
	}{
		{"GFW List", cfg.Update.GFWListURL, router.RuleFileNames.GFW},
		{"China Domains", cfg.Update.ChinaDomainsURL, router.RuleFileNames.ChinaDomain},
		{"China IP", cfg.Update.ChinaIPv4URL, router.RuleFileNames.ChinaIPv4},
	}
	for _, j := range jobs {
		r := c.updateOne(ctx, j.url, filepath.Join(dir, j.file))
		switch {
		case r.Skipped:
			fmt.Fprintf(out, "%-14s SKIPPED (no URL configured)\n", r.Name)
		case r.OK:
			fmt.Fprintf(out, "%-14s OK\n", r.Name)
		default:
			fmt.Fprintf(out, "%-14s FAILED (%v) — keeping previous rules\n", r.Name, r.Err)
		}
	}
	return nil
}

func (c *Client) updateOne(ctx context.Context, url, dest string) Result {
	name := filepath.Base(dest)
	if url == "" {
		return Result{Name: name, Skipped: true}
	}
	data, err := c.fetch(ctx, url)
	if err != nil {
		return Result{Name: name, Err: err}
	}
	// Validate before touching the old file.
	if err := validate(name, data); err != nil {
		return Result{Name: name, Err: fmt.Errorf("validation failed: %w", err)}
	}
	// Atomic replace: write temp file in the same directory then rename.
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".rule-*")
	if err != nil {
		return Result{Name: name, Err: err}
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return Result{Name: name, Err: err}
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return Result{Name: name, Err: err}
	}
	if err := os.Rename(tmpPath, dest); err != nil {
		os.Remove(tmpPath)
		return Result{Name: name, Err: err}
	}
	return Result{Name: name, OK: true}
}

func (c *Client) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20)) // 64 MiB cap
}

// validate performs lightweight sanity checks on downloaded content so a
// broken/HTML error page never replaces good rules.
func validate(fileName string, data []byte) error {
	if len(data) < 16 {
		return fmt.Errorf("too small (%d bytes)", len(data))
	}
	lower := fileName
	s := string(data)
	switch lower {
	case "gfw.list":
		// AutoProxy text or base64; both are ASCII-ish.
		for i := 0; i < len(s) && i < 512; i++ {
			if s[i] == 0 {
				return fmt.Errorf("binary content")
			}
		}
	case "china-domains.list":
		if !hasPrefix(s, "#", ";", "server=/") && !looksLikeDomains(s) {
			return fmt.Errorf("unrecognised domain list format")
		}
	case "china-ipv4.list":
		if !containsCIDR(s) {
			return fmt.Errorf("no CIDR entries found")
		}
	}
	return nil
}

func hasPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if len(s) >= len(p) && s[:len(p)] == p {
			return true
		}
	}
	return false
}

func looksLikeDomains(s string) bool {
	for _, line := range splitLines(s, 20) {
		if line == "" || line[0] == '#' {
			continue
		}
		for _, r := range line {
			if !(r == '.' || r == '-' || r == '/' || (r >= 'a' && r <= 'z') ||
				(r >= '0' && r <= '9')) {
				return false
			}
		}
		return true
	}
	return false
}

func containsCIDR(s string) bool {
	for _, line := range splitLines(s, 50) {
		if line == "" || line[0] == '#' {
			continue
		}
		dots, slash := 0, false
		for _, r := range line {
			if r == '.' {
				dots++
			}
			if r == '/' {
				slash = true
			}
		}
		if dots == 3 {
			return true
		}
		_ = slash
	}
	return false
}

func splitLines(s string, max int) []string {
	lines := make([]string, 0, max)
	start := 0
	for i := 0; i < len(s) && len(lines) < max; i++ {
		if s[i] == '\n' {
			lines = append(lines, trimCR(s[start:i]))
			start = i + 1
		}
	}
	if len(lines) < max {
		lines = append(lines, trimCR(s[start:]))
	}
	return lines
}

func trimCR(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\r' {
		return s[:len(s)-1]
	}
	return s
}

func mustConfigDir() string {
	d, err := config.DefaultDir()
	if err != nil {
		return ".config/sscli"
	}
	return d
}
