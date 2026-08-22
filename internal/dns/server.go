package dns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/Icestab/shadowsocks-linux-cli/internal/rules"
)

// Server is the internal DNS listener. In TUN mode every UDP/TCP packet
// with destination port 53 entering the userspace stack is redirected here
// (requirement 十五), so applications keep using their configured resolver
// while sscli controls the answers and records the domain->IP mapping.
type Server struct {
	resolver *Resolver
	engine   *rules.Engine // used to annotate answers; not for filtering
}

// NewServer builds a DNS server around a resolver.
func NewServer(resolver *Resolver, engine *rules.Engine) *Server {
	return &Server{resolver: resolver, engine: engine}
}

// HandleMsg processes one DNS query message and returns the response.
func (s *Server) HandleMsg(ctx context.Context, req *mdns.Msg) *mdns.Msg {
	resp := new(mdns.Msg)
	resp.SetReply(req)
	resp.RecursionAvailable = true
	if len(req.Question) == 0 {
		resp.Rcode = mdns.RcodeFormatError
		return resp
	}
	q := req.Question[0]
	domain := normalize(q.Name)

	switch q.Qtype {
	case mdns.TypeA, mdns.TypeAAAA:
	default:
		resp.Rcode = mdns.RcodeNotImplemented
		return resp
	}

	addrs, ttl, nxdomain := s.resolver.Resolve(ctx, domain, q.Qtype)
	if nxdomain {
		resp.Rcode = mdns.RcodeNameError
		return resp
	}
	if len(addrs) == 0 {
		// NODATA: the name exists but has no records of the requested
		// type (e.g. AAAA for an IPv4-only name). NOERROR with an empty
		// answer — NXDOMAIN here would make clients treat the whole name
		// as nonexistent.
		resp.Rcode = mdns.RcodeSuccess
		return resp
	}
	for _, ip := range addrs {
		var rr mdns.RR
		h := &mdns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: mdns.ClassINET, Ttl: ttl}
		if ip.Is4() || ip.Is4In6() {
			a4 := ip.Unmap().As4()
			rr = &mdns.A{Hdr: *h, A: net.IP(a4[:])}
		} else if q.Qtype == mdns.TypeAAAA {
			b := ip.As16()
			rr = &mdns.AAAA{Hdr: *h, AAAA: net.IP(b[:])}
		} else {
			continue // skip v6 answer to an A query
		}
		resp.Answer = append(resp.Answer, rr)
	}
	if len(resp.Answer) == 0 {
		resp.Rcode = mdns.RcodeNameError
	}
	return resp
}

// ListenAndServe runs UDP and TCP DNS servers at addr until ctx is
// cancelled. Both transports must be served: the DNS hijack redirects
// locally generated queries of either kind (nat OUTPUT :53 -> addr into
// 53090), and a UDP-only listener would leave TCP DNS querying an unserved
// port, failing every query that lands there.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	for _, netw := range []string{"udp", "tcp"} {
		wg.Add(1)
		go func(netw string) {
			defer wg.Done()
			if err := s.listenOne(ctx, addr, netw); err != nil && ctx.Err() == nil {
				errCh <- err
			}
		}(netw)
	}
	go func() {
		wg.Wait()
		close(errCh)
	}()
	var firstErr error
	for err := range errCh {
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (s *Server) listenOne(ctx context.Context, addr, netw string) error {
	mux := mdns.NewServeMux()
	mux.HandleFunc(".", func(w mdns.ResponseWriter, r *mdns.Msg) {
		resp := s.HandleMsg(ctx, r)
		if resp != nil {
			_ = w.WriteMsg(resp)
		}
	})
	srv := &mdns.Server{
		Addr:         addr,
		Net:          netw,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  func() time.Duration { return 30 * time.Second }, // TCP idle only
	}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown()
	}()
	if err := srv.ListenAndServe(); err != nil {
		return fmt.Errorf("dns server [%s] %s: %w", netw, addr, err)
	}
	return nil
}
