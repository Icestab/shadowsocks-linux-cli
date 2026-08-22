package dns

import (
	"context"
	"fmt"
	"net"

	mdns "github.com/miekg/dns"

	"github.com/dy/sscli/internal/rules"
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

	addrs, ttl := s.resolver.Resolve(ctx, domain, q.Qtype)
	if len(addrs) == 0 {
		resp.Rcode = mdns.RcodeNameError
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

// ListenAndServe runs a UDP DNS server at addr until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	mux := mdns.NewServeMux()
	mux.HandleFunc(".", func(w mdns.ResponseWriter, r *mdns.Msg) {
		resp := s.HandleMsg(ctx, r)
		if resp != nil {
			_ = w.WriteMsg(resp)
		}
	})
	srv := &mdns.Server{Addr: addr, Net: "udp", Handler: mux}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown()
	}()
	if err := srv.ListenAndServe(); err != nil {
		return fmt.Errorf("dns server %s: %w", addr, err)
	}
	return nil
}
