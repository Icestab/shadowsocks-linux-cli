package tun

import (
	"context"
	"fmt"
	"io"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// handleTCP terminates one incoming TCP flow: it completes the gvisor
// endpoint (completing the kernel-side handshake through our stack), dials
// the real destination through the router, and pipes both sides.
func (s *Stack) handleTCP(ctx context.Context, r *tcp.ForwarderRequest) {
	id := r.ID()
	dst := netAddr(id.LocalAddress, id.LocalPort)

	wq := &waiter.Queue{}
	ep, err := r.CreateEndpoint(wq)
	if err != nil {
		r.Complete(false)
		return
	}
	r.Complete(true)

	outbound, derr := s.router.DialFlow(ctx, "tcp", dst)
	if derr != nil {
		ep.Close()
		return
	}
	gc := gonet.NewTCPConn(wq, ep)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		pipeBoth(ctx, gc, outbound)
	}()
}

// handleUDP routes UDP datagrams. Port 53 goes to the internal DNS server;
// other UDP relay is deferred (Phase 1 scope) but arrives here, so the
// extension point already exists.
func (s *Stack) handleUDP(ctx context.Context, r *udp.ForwarderRequest) {
	id := r.ID()

	wq := &waiter.Queue{}
	ep, err := r.CreateEndpoint(wq)
	if err != nil {
		return
	}
	gc := gonet.NewUDPConn(wq, ep)

	if uint16(id.LocalPort) == s.dnsPort {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveDNSOverUDP(ctx, gc)
		}()
		return
	}
	// Non-DNS UDP is out of Phase 1 scope; closing sends ICMP unreachable
	// back into the userspace stack.
	ep.Close()
	_ = gc
}

// serveDNSOverUDP answers DNS queries received via the TUN until closed.
func (s *Stack) serveDNSOverUDP(ctx context.Context, conn *gonet.UDPConn) {
	defer conn.Close()
	buf := make([]byte, 4096)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		resp := s.router.HandleDNS(ctx, buf[:n])
		if resp == nil {
			continue
		}
		_, _ = conn.WriteTo(resp, nil)
	}
}

// pipeBoth copies in both directions until either side closes.
func pipeBoth(ctx context.Context, a io.ReadWriteCloser, b Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(a, struct{ io.Reader }{b})
		a.Close()
		b.Close()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(struct{ io.Writer }{b}, a)
		a.Close()
		b.Close()
		done <- struct{}{}
	}()
	select {
	case <-ctx.Done():
	case <-done:
	}
	a.Close()
	b.Close()
}

func netAddr(addr tcpip.Address, port uint16) string {
	return fmt.Sprintf("%s:%d", addr, port)
}
