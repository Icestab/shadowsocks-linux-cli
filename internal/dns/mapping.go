// Package dns implements sscli's DNS layer: a split resolver, a
// domain->IP mapping table for domain-based routing of IP connections
// (requirement 十六), and a DNS server used to intercept queries.
package dns

import (
	"net/netip"
	"sync"
	"time"
)

// mappingEntry records the domains an IP has answered for. Multiple domains
// can map to one IP (CDN / IP reuse), so each IP holds a set; lookups pick
// the most recently confirmed candidate (see Mapping.DomainForIP).
type mappingEntry struct {
	domains map[string]time.Time // domain -> last-seen time
	expires time.Time            // max TTL across answers
}

// Mapping tracks which domain names resolved to which IPs. It is
// concurrency-safe and prunes expired entries lazily.
type Mapping struct {
	mu      sync.RWMutex
	byIP    map[netip.Addr]*mappingEntry
	minTTL  time.Duration // floor applied when answers carry TTL=0
	maxTTL  time.Duration // cap so stale entries cannot linger forever
	nowFunc func() time.Time
}

// NewMapping builds a mapping table with the given min/max entry lifetimes.
func NewMapping(minTTL, maxTTL time.Duration) *Mapping {
	if minTTL <= 0 {
		minTTL = time.Second
	}
	if maxTTL < minTTL {
		maxTTL = 24 * time.Hour
	}
	return &Mapping{
		byIP:    make(map[netip.Addr]*mappingEntry),
		minTTL:  minTTL,
		maxTTL:  maxTTL,
		nowFunc: time.Now,
	}
}

// Record stores that domain resolved to ip with the given DNS TTL (seconds).
func (m *Mapping) Record(domain string, ip netip.Addr, ttlSec uint32) {
	d := normalize(domain)
	if d == "" || !ip.IsValid() || ip.IsUnspecified() {
		return
	}
	now := m.nowFunc()
	ttl := time.Duration(ttlSec) * time.Second
	switch {
	case ttl < m.minTTL:
		ttl = m.minTTL
	case ttl > m.maxTTL:
		ttl = m.maxTTL
	}
	exp := now.Add(ttl)

	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byIP[ip]
	if !ok {
		e = &mappingEntry{domains: make(map[string]time.Time)}
		m.byIP[ip] = e
	}
	e.domains[d] = now
	if exp.After(e.expires) {
		e.expires = exp
	}
}

// DomainForIP returns the best-known domain for ip, or "" when unknown.
// Candidates are ranked by recency; entries past expiry are dropped.
func (m *Mapping) DomainForIP(ip netip.Addr) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byIP[ip]
	if !ok {
		return ""
	}
	now := m.nowFunc()
	if now.After(e.expires) {
		delete(m.byIP, ip)
		return ""
	}
	var (
		best     string
		bestTime time.Time
	)
	for d, t := range e.domains {
		if t.After(bestTime) {
			best, bestTime = d, t
		}
	}
	return best
}

// Len reports the number of tracked IPs after pruning expired entries.
func (m *Mapping) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.nowFunc()
	for ip, e := range m.byIP {
		if now.After(e.expires) {
			delete(m.byIP, ip)
		}
	}
	return len(m.byIP)
}

func normalize(d string) string {
	if len(d) > 1 && d[len(d)-1] == '.' {
		d = d[:len(d)-1]
	}
	return lower(d)
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
