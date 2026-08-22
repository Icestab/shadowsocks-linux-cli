package router

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/dy/sscli/internal/config"
	"github.com/dy/sscli/internal/rules"
)

// RulesDirName is the subdirectory of the config dir holding rule files
// (requirement 七: rules live outside the program, never hardcoded).
const RulesDirName = "rules"

// RulesDir returns the rule files directory for the given config dir.
func RulesDir(configDir string) string { return filepath.Join(configDir, RulesDirName) }

// RuleFileNames maps logical lists to on-disk file names.
var RuleFileNames = struct {
	GFW         string
	ChinaDomain string
	ChinaIPv4   string
	ChinaIPv6   string
	Custom      string
}{
	GFW:         "gfw.list",
	ChinaDomain: "china-domains.list",
	ChinaIPv4:   "china-ipv4.list",
	ChinaIPv6:   "china-ipv6.list",
	Custom:      "custom.list",
}

// LoadEngine builds a rules.Engine from the config's custom rules plus any
// rule files present. Missing files are skipped (update installs them).
func LoadEngine(cfg *config.Config) (*rules.Engine, error) {
	engine := rules.NewEngine(rules.Mode(cfg.Mode))

	// Custom rules from config.yaml.
	var custom []rules.CustomRule
	for _, r := range cfg.Rules {
		cr := rules.CustomRule{Action: actionToDecision(r.Action)}
		if r.Domain != "" {
			cr.Domain = r.Domain
			custom = append(custom, cr)
			continue
		}
		if r.DomainSuffix != "" {
			cr.DomainSuffix = r.DomainSuffix
			custom = append(custom, cr)
			continue
		}
		if r.IP != "" {
			a, err := netip.ParseAddr(r.IP)
			if err != nil {
				return nil, fmt.Errorf("rule ip %q: %w", r.IP, err)
			}
			cr.IP = a
			custom = append(custom, cr)
			continue
		}
		if r.CIDR != "" {
			p, err := netip.ParsePrefix(r.CIDR)
			if err != nil {
				return nil, fmt.Errorf("rule cidr %q: %w", r.CIDR, err)
			}
			cr.CIDR = p.Masked()
			custom = append(custom, cr)
		}
	}
	engine.SetCustom(custom)

	dir := ""
	if d, err := config.DefaultDir(); err == nil {
		dir = d
	}
	rdir := RulesDir(dir)

	if f := filepath.Join(rdir, RuleFileNames.GFW); fileExists(f) {
		set, err := rules.LoadGFWListFile(f)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", f, err)
		}
		engine.GFWList().Merge(set)
	}
	if f := filepath.Join(rdir, RuleFileNames.ChinaDomain); fileExists(f) {
		set, err := rules.LoadDomainListFile(f)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", f, err)
		}
		engine.ChinaDomains().Merge(set)
	}
	if f := filepath.Join(rdir, RuleFileNames.ChinaIPv4); fileExists(f) {
		set, err := rules.LoadCIDRListFile(f)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", f, err)
		}
		engine.ChinaIP().MergeV4(set)
	}
	if f := filepath.Join(rdir, RuleFileNames.Custom); fileExists(f) {
		rs, err := rules.LoadCustomListFile(f)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", f, err)
		}
		engine.SetCustom(append(engine.Custom(), rs...))
	}
	return engine, nil
}

func actionToDecision(a config.Action) rules.Decision {
	if a == config.ActionProxy {
		return rules.Proxy
	}
	return rules.Direct
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}
