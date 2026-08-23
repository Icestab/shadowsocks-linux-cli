package tun

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// udpRelayRouter dials every UDP flow to a local echo server (stand-in for
// the real router: a marked DIRECT socket or the sslocal SOCKS5 UDP
// ASSOCIATE), recording the destinations.
type udpRelayRouter struct {
	mu     sync.Mutex
	echo   string
	dialed []string
}

func (u *udpRelayRouter) DialFlow(ctx context.Context, network, addr string) (Conn, error) {
	u.mu.Lock()
	u.dialed = append(u.dialed, network+" "+addr)
	u.mu.Unlock()
	return net.Dial("udp", u.echo)
}

func (u *udpRelayRouter) dialedList() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.dialed...)
}

func (u *udpRelayRouter) HandleDNS(ctx context.Context, query []byte) []byte { return nil }

// startUDPEcho returns a loopback UDP echo server address and its stopper.
func startUDPEcho(t *testing.T) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8192)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			n, raddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], raddr)
		}
	}()
	return pc.LocalAddr().String(), func() {
		pc.Close()
		<-done
	}
}

// TestUDPRelayEchoAndReap exercises the non-DNS UDP path end to end: a
// datagram on a non-53 port must be relayed through the router's outbound
// (here: a local echo), answered, and the flow reaped after the idle
// window — same leak guard as the DNS flows (gvisor forwarder endpoints
// never time out on their own).
func TestUDPRelayEchoAndReap(t *testing.T) {
	echoAddr, stopEcho := startUDPEcho(t)
	defer stopEcho()

	rt := &udpRelayRouter{echo: echoAddr}
	s := &Stack{
		router:           rt,
		dnsPort:          53,
		relayIdleTimeout: 150 * time.Millisecond,
		flowSlots:        make(chan struct{}, maxConcurrentFlows),
		udpConns:         make(map[*gonet.UDPConn]struct{}),
	}
	ep, st := newUDPServerHarness(t, s) // reuse the UDP forwarder harness
	defer st.Close()
	defer ep.Close()

	src := netip.MustParseAddr("198.18.0.1")
	pkt := buildUDPPacket(src, netip.MustParseAddr("8.8.8.8"), 54321, 8765, []byte("ping-1"))

	inject := func() {
		t.Helper()
		pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(ep.MaxHeaderLength()),
			Payload:            bufFromData(pkt),
		})
		ep.InjectInbound(ipv4.ProtocolNumber, pb)
		pb.DecRef()
	}
	readEcho := func(payload string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		p := ep.ReadContext(ctx)
		if p == nil {
			t.Fatal("no relayed reply packet emitted by the stack")
		}
		defer p.DecRef()
		out := p.ToView().ToSlice()
		if len(out) < 28 {
			t.Fatalf("reply too short: %d bytes", len(out))
		}
		udpH := out[20:]
		if sport := binary.BigEndian.Uint16(udpH[0:2]); sport != 8765 {
			t.Errorf("reply source port = %d, want 8765", sport)
		}
		if dport := binary.BigEndian.Uint16(udpH[2:4]); dport != 54321 {
			t.Errorf("reply dst port = %d, want 54321", dport)
		}
		if got := string(udpH[8:]); got != payload {
			t.Errorf("reply payload = %q, want %q", got, payload)
		}
	}

	// 1. A non-DNS datagram is dialed through the router and echoed back.
	inject()
	readEcho("ping-1")
	if got := rt.dialedList(); len(got) != 1 || got[0] != "udp 8.8.8.8:8765" {
		t.Errorf("router dials = %v, want [udp 8.8.8.8:8765]", got)
	}
	if got := s.activeUDPFlows.Load(); got != 1 {
		t.Fatalf("active UDP flows = %d, want 1", got)
	}

	// 2. Idle reaping ends the flow.
	deadline := time.Now().Add(2 * time.Second)
	for s.activeUDPFlows.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("relay flow was not reaped after the idle timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 3. A later datagram on the same 5-tuple opens a fresh flow (and
	// re-dials through the router).
	inject()
	readEcho("ping-1")
	if got := s.activeUDPFlows.Load(); got != 1 {
		t.Fatalf("active UDP flows = %d, want 1 after re-query", got)
	}
	if got := len(rt.dialedList()); got != 2 {
		t.Errorf("router dial count = %d, want 2 (fresh flow re-dials)", got)
	}
}