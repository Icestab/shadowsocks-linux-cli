package router

import (
	"context"
	"net"

	mdns "github.com/miekg/dns"

	"github.com/Icestab/sscli/internal/dns"
	"github.com/Icestab/sscli/internal/tun"
)

// flowAdapter adapts Router+dns.Server to the tun.FlowRouter interface,
// keeping the tun package free of concrete dependencies.
type flowAdapter struct {
	router *Router
	dnsSrv *dns.Server
}

// NewFlowAdapter builds a tun.FlowRouter over the given router and DNS server.
func NewFlowAdapter(r *Router, dnsSrv *dns.Server) tun.FlowRouter {
	return &flowAdapter{router: r, dnsSrv: dnsSrv}
}

// DialFlow dials addr through the selected outbound path.
func (f *flowAdapter) DialFlow(ctx context.Context, network, addr string) (tun.Conn, error) {
	conn, _, err := f.router.Dial(ctx, network, addr)
	return conn, err
}

// HandleDNS parses a raw DNS wire query, resolves it and returns the raw
// response bytes.
func (f *flowAdapter) HandleDNS(ctx context.Context, query []byte) []byte {
	var msg mdns.Msg
	if err := msg.Unpack(query); err != nil {
		return nil
	}
	resp := f.dnsSrv.HandleMsg(ctx, &msg)
	if resp == nil {
		return nil
	}
	b, err := resp.Pack()
	if err != nil {
		return nil
	}
	_ = net.IPv4len // keep import minimal
	return b
}
