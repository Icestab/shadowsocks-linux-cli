package rules

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

// LoadGFWListFile parses a gfw-list file. It supports both raw AutoProxy
// format and the base64-encoded variant distributed by gfwlist/gfwlist.
//
// Recognised line forms:
//
//	||example.com        -> suffix entry
//	||example.com^       -> suffix entry (trailing marker stripped)
//	.example.com         -> suffix entry
//	example.com          -> exact entry
//	@@...                -> exception lines (ignored: whitelist unsupported)
//	/regex/ , !comment   -> ignored
func LoadGFWListFile(path string) (*DomainSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := string(data)
	if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text)); err == nil && strings.Contains(string(decoded), "\n") {
		text = string(decoded)
	}
	set := NewDomainSet()
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") ||
			strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "/") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "||"):
			d := strings.TrimPrefix(line, "||")
			set.AddSuffix(trimRuleTail(d))
		case strings.HasPrefix(line, "."):
			set.AddSuffix(strings.TrimPrefix(line, "."))
		default:
			if strings.ContainsAny(line, "*$^|[]") {
				continue // wildcard/regex/option syntax not supported
			}
			set.AddExact(trimRuleTail(line))
		}
	}
	return set, sc.Err()
}

// trimRuleTail removes AutoProxy path/anchor markers: "example.com/path^"
// -> "example.com".
func trimRuleTail(d string) string {
	if i := strings.IndexAny(d, "/^*"); i >= 0 {
		d = d[:i]
	}
	return d
}

// LoadDomainListFile parses a domain list file. Supported formats:
//   - plain domains, one per line ("baidu.com", suffix semantics)
//   - dnsmasq config lines from dnsmasq-china-list:
//     "server=/baidu.com/114.114.114.114" or "server=/baidu.com/"
//   - "#" and ";" comments, blank lines
func LoadDomainListFile(path string) (*DomainSet, error) {
	f, err := os.Open(path) // #nosec G304 -- path comes from our own config
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck
	set := NewDomainSet()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if d, ok := parseDnsmasqServerLine(line); ok {
			set.AddSuffix(d)
			continue
		}
		if fields := strings.Fields(line); len(fields) == 1 {
			set.AddSuffix(fields[0])
		}
	}
	return set, sc.Err()
}

func parseDnsmasqServerLine(line string) (string, bool) {
	if !strings.HasPrefix(line, "server=/") {
		return "", false
	}
	rest := strings.TrimPrefix(line, "server=/")
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return "", false
	}
	d := rest[:i]
	if d == "" || strings.Count(d, ".") == 0 { // skip bare TLD entries like server=/cn/
		return "", false
	}
	return d, true
}

// LoadCIDRListFile parses a CIDR list file: one "1.2.3.0/24" or bare IP per
// line, '#' comments allowed. IPv6 lines are accepted (reserved for later).
func LoadCIDRListFile(path string) (*CIDRSet, error) {
	f, err := os.Open(path) // #nosec G304 -- path comes from our own config
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck
	set := NewCIDRSet()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if fields := strings.Fields(line); len(fields) >= 1 {
			line = fields[0]
		}
		if !strings.Contains(line, "/") {
			line += "/32"
		}
		p, err := netip.ParsePrefix(line)
		if err != nil {
			// Skip malformed lines but keep loading; report at end? For
			// robustness we tolerate individual bad lines in downloaded data.
			continue
		}
		if err := set.Insert(p); err != nil {
			return nil, fmt.Errorf("insert %s: %w", p, err)
		}
	}
	return set, sc.Err()
}

// LoadCustomListFile parses custom.list: one rule per line,
//
//	domain <name> <direct|proxy>
//	domain_suffix <name> <direct|proxy>
//	ip <addr> <direct|proxy>
//	cidr <prefix> <direct|proxy>
func LoadCustomListFile(path string) ([]CustomRule, error) {
	f, err := os.Open(path) // #nosec G304 -- path comes from our own config
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck
	var out []CustomRule
	sc := bufio.NewScanner(f)
	for ln := 1; sc.Scan(); ln++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("%s:%d: expected '<kind> <value> <action>', got %q", path, ln, line)
		}
		var action Decision
		switch strings.ToLower(fields[2]) {
		case "direct":
			action = Direct
		case "proxy":
			action = Proxy
		default:
			return nil, fmt.Errorf("%s:%d: action must be direct|proxy", path, ln)
		}
		r := CustomRule{Action: action}
		switch fields[0] {
		case "domain":
			r.Domain = fields[1]
		case "domain_suffix":
			r.DomainSuffix = fields[1]
		case "ip":
			a, err := netip.ParseAddr(fields[1])
			if err != nil {
				return nil, fmt.Errorf("%s:%d: bad ip: %w", path, ln, err)
			}
			r.IP = a
		case "cidr":
			p, err := netip.ParsePrefix(fields[1])
			if err != nil {
				return nil, fmt.Errorf("%s:%d: bad cidr: %w", path, ln, err)
			}
			r.CIDR = p.Masked()
		default:
			return nil, fmt.Errorf("%s:%d: unknown kind %q", path, ln, fields[0])
		}
		out = append(out, r)
	}
	return out, sc.Err()
}
