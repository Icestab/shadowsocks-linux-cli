// Package rules implements high-performance routing rule matching.
//
// Design targets tens of thousands to hundreds of thousands of entries:
//   - Domains use an exact-match hash set plus a suffix-match hash set,
//     giving O(number of labels) lookups without scanning the whole file.
//   - IPs/CIDRs use a binary radix trie over address bits, giving
//     O(bit-length) longest-prefix matches.
package rules

import (
	"strings"
)

// Decision is the routing outcome for a matched rule.
type Decision int

const (
	NoMatch Decision = iota
	Direct
	Proxy
)

func (d Decision) String() string {
	switch d {
	case Direct:
		return "DIRECT"
	case Proxy:
		return "PROXY"
	default:
		return "NOMATCH"
	}
}

// DomainSet matches fully-qualified domains against exact entries and
// parent-suffix entries ("domain" and "domain_suffix" semantics).
//
// Matching rules:
//   - "example.com" entry matches example.com exactly
//   - ".example.com"-style suffix entry matches example.com and every
//     subdomain (www.example.com, api.example.com)
//   - "notexample.com" must NOT match an example.com entry
type DomainSet struct {
	exact  map[string]struct{}
	suffix map[string]struct{} // stored WITHOUT leading dot, e.g. "example.com"
}

func NewDomainSet() *DomainSet {
	return &DomainSet{
		exact:  make(map[string]struct{}),
		suffix: make(map[string]struct{}),
	}
}

// AddExact registers a domain that matches only itself.
func (s *DomainSet) AddExact(domain string) {
	s.exact[normalizeDomain(domain)] = struct{}{}
}

// AddSuffix registers a domain that matches itself and all subdomains.
func (s *DomainSet) AddSuffix(domain string) {
	s.suffix[normalizeDomain(domain)] = struct{}{}
}

// Len reports the number of registered entries.
func (s *DomainSet) Len() int { return len(s.exact) + len(s.suffix) }

// Merge folds every entry of other into s.
func (s *DomainSet) Merge(other *DomainSet) {
	for d := range other.exact {
		s.exact[d] = struct{}{}
	}
	for d := range other.suffix {
		s.suffix[d] = struct{}{}
	}
}

// Contains reports whether domain hits any exact or suffix entry.
func (s *DomainSet) Contains(domain string) bool {
	d := normalizeDomain(domain)
	if _, ok := s.exact[d]; ok {
		return true
	}
	// Suffix entries match the domain itself and every parent label chain,
	// e.g. suffix "example.com" matches www.example.com AND example.com.
	for {
		if _, ok := s.suffix[d]; ok {
			return true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			return false
		}
		d = d[i+1:]
	}
}

func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimSuffix(d, ".")
	// gfw-list style "||example.com^" markers are stripped by callers;
	// tolerate them defensively here too.
	d = strings.TrimPrefix(d, "||")
	d = strings.TrimPrefix(d, ".")
	return d
}
