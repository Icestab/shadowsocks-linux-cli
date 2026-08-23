package daemon

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"time"

	mdns "github.com/miekg/dns"
)

// defaultDoHEndpoints are the RFC 8484 bootstrap resolvers used to look up
// the SS server domain BEFORE any routing/DNS change. Resolving via
// encrypted HTTPS means the VPS name never reaches the local/ISP resolver
// in plaintext — the startup DNS leak. Aliyun first: reachable inside
// China without a proxy; Cloudflare as fallback.
var defaultDoHEndpoints = []string{
	"https://dns.alidns.com/dns-query",
	"https://cloudflare-dns.com/dns-query",
}

// dohHTTP has its own timeout; per-request deadlines are bounded in
// dohLookup.
var dohHTTP = &http.Client{Timeout: 5 * time.Second}

// resolveViaDoH queries each endpoint for the domain's A (then AAAA)
// records via DoH GET, returning the first non-empty answer.
func resolveViaDoH(ctx context.Context, endpoints []string, domain string) ([]netip.Addr, error) {
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no DoH endpoints configured")
	}
	var lastErr error
	for _, ep := range endpoints {
		addrs, err := dohLookup(ctx, ep, domain, mdns.TypeA)
		if err != nil {
			lastErr = err
			continue
		}
		if len(addrs) > 0 {
			return addrs, nil
		}
		// No A record: try AAAA before giving up on this endpoint.
		addrs, err = dohLookup(ctx, ep, domain, mdns.TypeAAAA)
		if err != nil {
			lastErr = err
			continue
		}
		if len(addrs) > 0 {
			return addrs, nil
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no DoH answer for %q", domain)
}

// dohLookup performs one RFC 8484 GET query and extracts A/AAAA answers.
func dohLookup(ctx context.Context, endpoint, domain string, qtype uint16) ([]netip.Addr, error) {
	q := new(mdns.Msg)
	q.SetQuestion(mdns.Fqdn(domain), qtype)
	q.RecursionDesired = true
	wire, err := q.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DoH query: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	url := endpoint + "?dns=" + base64.RawURLEncoding.EncodeToString(wire)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")

	resp, err := dohHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH %s: HTTP %d", endpoint, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("DoH %s: read body: %w", endpoint, err)
	}
	var msg mdns.Msg
	if err := msg.Unpack(body); err != nil {
		return nil, fmt.Errorf("DoH %s: unpack answer: %w", endpoint, err)
	}
	// NXDOMAIN or SERVFAIL are errors, not empty-positive answers.
	if msg.Rcode != mdns.RcodeSuccess {
		if msg.Rcode == mdns.RcodeNameError {
			return nil, fmt.Errorf("DoH %s: NXDOMAIN", endpoint)
		}
		return nil, fmt.Errorf("DoH %s: rcode %v", endpoint, mdns.RcodeToString[msg.Rcode])
	}
	var out []netip.Addr
	for _, rr := range msg.Answer {
		switch rec := rr.(type) {
		case *mdns.A:
			if a4, ok := netip.AddrFromSlice(rec.A); ok {
				out = append(out, a4.Unmap())
			}
		case *mdns.AAAA:
			if a6, ok := netip.AddrFromSlice(rec.AAAA); ok {
				out = append(out, a6.Unmap())
			}
		}
	}
	return out, nil
}