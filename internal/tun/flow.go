package tun

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

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
	// Admission control: refuse with RST once the concurrent-flow budget is
	// exhausted (see maxConcurrentFlows). Non-blocking on purpose — a full
	// budget rejects new flows immediately instead of piling up waiters.
	// NOTE: Complete(true) is required for the refusal to reach the app —
	// Complete(false) merely releases the request (the SYN would otherwise
	// retransmit until the app gives up).
	select {
	case s.flowSlots <- struct{}{}:
		defer func() { <-s.flowSlots }()
	default:
		r.Complete(true)
		return
	}

	id := r.ID()
	dst := netAddr(id.LocalAddress, id.LocalPort)

	wq := &waiter.Queue{}
	ep, err := r.CreateEndpoint(wq)
	if err != nil {
		r.Complete(false)
		return
	}
	r.Complete(true)

	// Destination port 0 is not a valid TCP service port (RFC 793); flows
	// like this occasionally show up in the TUN (observed once per boot in
	// the wild, source still unidentified). Completing the endpoint settles
	// the kernel side (the app sees the connection fail normally) but we
	// must not waste a 10 s phantom dial on it.
	if id.LocalPort == 0 {
		if debugEnabled() {
			fmt.Printf("[sscli][debug] tcp flow with dst port 0 dropped (invalid): %s\n", dst)
		}
		ep.Close()
		return
	}

	outbound, derr := s.router.DialFlow(ctx, "tcp", dst)
	if debugEnabled() {
		fmt.Printf("[sscli][debug] tcp %s dial: %v\n", dst, derr)
	}
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
		// Track the flow so Stack.Close can terminate it alongside the
		// idle reaper (see serveDNSOverUDP).
		s.udpMu.Lock()
		s.udpConns[gc] = struct{}{}
		s.udpMu.Unlock()
		s.activeDNSFlows.Add(1)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.activeDNSFlows.Add(-1)
			defer func() {
				s.udpMu.Lock()
				delete(s.udpConns, gc)
				s.udpMu.Unlock()
			}()
			s.serveDNSOverUDP(ctx, gc)
		}()
		return
	}
	// Non-DNS UDP is out of Phase 1 scope; closing sends ICMP unreachable
	// back into the userspace stack.
	ep.Close()
}

// serveDNSOverUDP answers DNS queries received via the TUN until the flow
// goes silent for the idle timeout or the stack closes.
//
// gvisor keeps a forwarder-created UDP endpoint — and therefore this
// goroutine — alive until the owner closes it: udp.Forwarder has no idle
// timeout. Local resolvers that open a fresh socket per query (plain glibc
// getaddrinfo) would otherwise pin one goroutine + endpoint PER QUERY
// forever, growing without bound for the daemon's whole lifetime. The
// idle timer closes the conn, which wakes the blocked ReadFrom with
// ErrClosedForReceive and ends the flow; Stack.Close does the same for
// every live flow so shutdown is not delayed. A query racing the close is
// simply lost — the client retries and obtains a fresh flow.
func (s *Stack) serveDNSOverUDP(ctx context.Context, conn *gonet.UDPConn) {
	defer conn.Close()
	idle := s.dnsIdleTimeout
	if idle <= 0 {
		idle = udpDNSIdleTimeout
	}
	// time.AfterFunc uses the runtime timer heap, not a goroutine per flow.
	reaper := time.AfterFunc(idle, func() { _ = conn.Close() })
	defer reaper.Stop()
	buf := make([]byte, 4096)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		reaper.Reset(idle)
		resp := s.router.HandleDNS(ctx, buf[:n])
		if resp == nil {
			continue
		}
		_, _ = conn.WriteTo(resp, nil)
	}
}

func debugEnabled() bool { return os.Getenv("SSCLI_DEBUG") != "" }

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
