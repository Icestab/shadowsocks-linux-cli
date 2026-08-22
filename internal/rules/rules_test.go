package rules

import (
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func mustInsert(t *testing.T, s *CIDRSet, prefix string) {
	t.Helper()
	if err := s.Insert(netip.MustParsePrefix(prefix)); err != nil {
		t.Fatalf("insert %s: %v", prefix, err)
	}
}

func TestDomainSetMatching(t *testing.T) {
	s := NewDomainSet()
	s.AddSuffix("example.com")
	s.AddExact("exact.org")

	cases := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"www.example.com", true},
		{"api.example.com", true},
		{"deep.sub.example.com", true},
		{"notexample.com", false}, // must not match suffix
		{"example.com.evil.com", false},
		{"EXAMPLE.COM", true}, // case-insensitive
		{"exact.org", true},
		{"sub.exact.org", false}, // exact entries don't cover subdomains
	}
	for _, c := range cases {
		if got := s.Contains(c.domain); got != c.want {
			t.Errorf("Contains(%q) = %v, want %v", c.domain, got, c.want)
		}
	}
}

func TestCIDRSetLongestPrefix(t *testing.T) {
	s := NewCIDRSet()
	mustInsert(t, s, "1.0.1.0/24")
	mustInsert(t, s, "10.0.0.0/8")
	cases := []struct {
		ip   string
		want bool
	}{
		{"1.0.1.55", true},
		{"1.0.2.1", false},
		{"10.255.255.255", true},
		{"11.0.0.1", false},
		{"192.168.1.1", false},
	}
	for _, c := range cases {
		ip := netip.MustParseAddr(c.ip)
		if got := s.Contains(ip); got != c.want {
			t.Errorf("Contains(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestEngineGFWMode(t *testing.T) {
	e := NewEngine(ModeGFW)
	e.GFWList().AddSuffix("github.com")
	e.GFWList().AddSuffix("google.com")
	e.ChinaDomains().AddSuffix("baidu.com")
	e.ChinaDomains().AddSuffix("qq.com")
	mustInsert(t, e.ChinaIP(), "114.114.114.0/24")

	type tc struct {
		domain string
		ip     string
		want   Decision
	}
	tests := []tc{
		{"www.baidu.com", "", Direct},
		{"qq.com", "", Direct},
		{"github.com", "", Proxy},
		{"www.google.com", "", Proxy},
		{"unknown-site.io", "", Direct}, // mode default: DIRECT in gfw mode
		{"", "192.168.1.1", Direct},     // LAN
		{"", "10.0.0.1", Direct},
		{"", "114.114.114.114", Direct}, // china IP
		{"", "8.8.8.8", Direct},         // unknown IP -> gfw default DIRECT
	}
	for _, c := range tests {
		var ip netip.Addr
		if c.ip != "" {
			ip = netip.MustParseAddr(c.ip)
		}
		got := e.Decide(c.domain, ip)
		if got != c.want {
			t.Errorf("gfw Decide(%q,%q) = %v want %v", c.domain, c.ip, got, c.want)
		}
	}
}

func TestEngineBypassAndGlobalModes(t *testing.T) {
	newEngine := func() *Engine {
		e := NewEngine(ModeBypass)
		e.ChinaDomains().AddSuffix("baidu.com")
		mustInsert(t, e.ChinaIP(), "114.114.114.0/24")
		return e
	}
	e := newEngine()
	var baidu = netip.MustParseAddr("220.181.38.148") // not in china-ip set above
	if got := e.Decide("www.baidu.com", netip.Addr{}); got != Direct {
		t.Errorf("bypass china domain = %v", got)
	}
	if got := e.Decide("", netip.MustParseAddr("114.114.114.114")); got != Direct {
		t.Errorf("bypass china ip = %v", got)
	}
	if got := e.Decide("github.com", baidu); got != Proxy {
		t.Errorf("bypass foreign default = %v", got)
	}

	g := newEngine()
	g.SetMode(ModeGlobal)
	if got := g.Decide("www.baidu.com", netip.Addr{}); got != Proxy {
		t.Errorf("global china domain should PROXY, got %v", got)
	}
	if got := g.Decide("", netip.MustParseAddr("114.114.114.114")); got != Proxy {
		t.Errorf("global china ip should PROXY, got %v", got)
	}
	if got := g.Decide("", netip.MustParseAddr("192.168.1.1")); got != Direct {
		t.Errorf("global LAN must stay DIRECT, got %v", got)
	}
}

func TestCustomRulesPriority(t *testing.T) {
	e := NewEngine(ModeGFW)
	e.SetCustom([]CustomRule{
		{Domain: "special.github-mirror.dev", Action: Direct},
		{DomainSuffix: "corp.internal", Action: Direct},
	})
	e.GFWList().AddSuffix("github.com") // would otherwise match

	if got := e.Decide("special.github-mirror.dev", netip.Addr{}); got != Direct {
		t.Errorf("custom rule should override gfw list: %v", got)
	}
	if got := e.Decide("a.corp.internal", netip.Addr{}); got != Direct {
		t.Errorf("custom suffix rule failed: %v", got)
	}
	// Unrelated domain must NOT hit the custom suffix rule; it should fall
	// through to the gfw-mode default.
	if _, level := e.Explain("other.corp.internal.evil.com", netip.Addr{}); level != "mode-default:gfw" {
		t.Errorf("unrelated domain matched %q, want mode-default:gfw", level)
	}
}

func TestLoadGFWListBase64(t *testing.T) {
	dir := t.TempDir()
	raw := "[AutoProxy 0.2.9]\n||github.com^\n||google.com\n@@||whitelisted.cn\n! comment\n"
	enc := base64.StdEncoding.EncodeToString([]byte(raw))
	path := filepath.Join(dir, "gfw.list")
	os.WriteFile(path, []byte(enc), 0o600)
	set, err := LoadGFWListFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !set.Contains("github.com") || !set.Contains("api.github.com") {
		t.Error("gfw list base64 parse failed for github.com")
	}
	if !set.Contains("google.com") {
		t.Error("gfw list exact line missing")
	}
}

func TestLoadChinaDomainsDnsmasqFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "china-domains.list")
	content := "# comment\ncn\nserver=/baidu.com/114.114.114.114\nserver=/taobao.com/\nplain-domain.cn\n"
	os.WriteFile(path, []byte(content), 0o600)
	set, err := LoadDomainListFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !set.Contains("www.baidu.com") {
		t.Error("dnsmasq server=/baidu.com/ not parsed")
	}
	if !set.Contains("item.taobao.com") {
		t.Error("dnsmasq server=/taobao.com/ not parsed")
	}
	if !set.Contains("foo.plain-domain.cn") {
		t.Error("plain domain line not parsed as suffix")
	}
	if set.Contains("notbaidu.com") {
		t.Error("false positive on suffix match")
	}
}

func TestLoadCustomListFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.list")
	content := "# custom rules\ndomain github.com proxy\ndomain_suffix corp.internal direct\nip 1.2.3.4 proxy\ncidr 10.20.0.0/16 direct\n"
	os.WriteFile(path, []byte(content), 0o600)
	rs, err := LoadCustomListFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 4 {
		t.Fatalf("got %d rules, want 4", len(rs))
	}
	e := NewEngine(ModeGFW)
	e.SetCustom(rs)
	if got := e.Decide("1.2.3.4", netip.MustParseAddr("1.2.3.4")); got != Proxy {
		t.Errorf("custom ip rule: %v", got)
	}
	if got := e.Decide("", netip.MustParseAddr("10.20.3.4")); got != Direct {
		t.Errorf("custom cidr rule: %v", got)
	}
}
