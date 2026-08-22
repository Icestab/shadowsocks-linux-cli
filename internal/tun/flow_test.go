package tun

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// TestHandleTCPAdmissionRefusesWhenFull verifies the concurrent-flow budget
// (maxConcurrentFlows): when the budget is exhausted, handleTCP must RST
// the sender instead of accepting the flow — otherwise a single local
// process could open unbounded connections and exhaust the daemon (memory,
// fds, goroutines).
func TestHandleTCPAdmissionRefusesWhenFull(t *testing.T) {
	var sut *Stack
	ep, st := newForwarderHarness(t, func(r *tcp.ForwarderRequest) {
		sut.handleTCP(context.Background(), r)
	})
	defer st.Close()
	defer ep.Close()

	sut = &Stack{dev: &Device{dev: newFakeTUN(), Name: "test0", MTU: 1500}, ep: ep}
	sut.flowSlots = make(chan struct{}, 1)
	sut.flowSlots <- struct{}{} // budget exhausted

	inject := func(pkt []byte) {
		pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(ep.MaxHeaderLength()),
			Payload:            bufFromData(pkt),
		})
		ep.InjectInbound(ipv4.ProtocolNumber, pb)
		pb.DecRef()
	}
	inject(buildTCPSYN(netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("153.3.238.127"), 40000, 80))

	// The sender must get an RST back into the channel (and nothing else:
	// no SYN-ACK, no dial — the router is nil and must never be touched).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pkt := ep.ReadContext(ctx)
	if pkt == nil {
		t.Fatalf("no RST emitted for refused flow (resetsSent=%d segSendErr=%d ipOutErr=%d ipTxDropped=%d)",
			st.Stats().TCP.ResetsSent.Value(),
			st.Stats().TCP.SegmentSendErrors.Value(),
			st.Stats().IP.OutgoingPacketErrors.Value(),
			st.Stats().IP.IPTablesOutputDropped.Value(),
		)
	}
	view := pkt.ToView().ToSlice()
	if len(view) < 40 {
		t.Fatalf("emitted packet too short: %d bytes", len(view))
	}
	tcpH := view[20:]
	if tcpH[13]&0x04 == 0 {
		t.Errorf("expected RST flag, got %#x", tcpH[13])
	}
	pkt.DecRef()
}

// TestHandleTCPAcceptsWhenBudgetAvailable sanity-checks the admission path
// itself: with a free slot, the flow must pass admission and reach the
// router (a stub that records the dial). The full SYN->SYN-ACK->ACK
// handshake is driven through the real forwarder because handleTCP's
// CreateEndpoint blocks until the ACK arrives.
func TestHandleTCPAcceptsWhenBudgetAvailable(t *testing.T) {
	var sut *Stack
	ep, st := newForwarderHarness(t, func(r *tcp.ForwarderRequest) {
		sut.handleTCP(context.Background(), r)
	})
	defer st.Close()
	defer ep.Close()

	sut = &Stack{dev: &Device{dev: newFakeTUN(), Name: "test0", MTU: 1500}, ep: ep}
	sut.flowSlots = make(chan struct{}, 1) // budget with one free slot
	dialed := make(chan string, 1)
	sut.router = &stubRouter{t: t, dialed: dialed}

	src := netip.MustParseAddr("198.18.0.1")
	dst := netip.MustParseAddr("153.3.238.127")
	inject := func(pkt []byte) {
		pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(ep.MaxHeaderLength()),
			Payload:            bufFromData(pkt),
		})
		ep.InjectInbound(ipv4.ProtocolNumber, pb)
		pb.DecRef()
	}

	// 1. App SYN (seq 0).
	inject(buildTCPPacket(src, dst, 40001, 443, 0x02 /* SYN */, 0, 0, nil))

	// 2. Stack answers SYN-ACK: read it out of the channel, mirror the ACK.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pkt := ep.ReadContext(ctx)
	if pkt == nil {
		t.Fatal("no SYN-ACK emitted")
	}
	view := pkt.ToView().ToSlice()
	if len(view) < 40 {
		t.Fatalf("SYN-ACK too short: %d", len(view))
	}
	synAck := view[20:]
	if synAck[13]&0x12 != 0x12 {
		t.Fatalf("expected SYN|ACK, got %#x", synAck[13])
	}
	serverSeq := binary.BigEndian.Uint32(synAck[4:8])
	serverACK := binary.BigEndian.Uint32(synAck[8:12])
	pkt.DecRef()

	// 3. App ACK: seq = our SYN seq + 1, ack = server seq + 1.
	inject(buildTCPPacket(src, dst, 40001, 443, 0x10 /* ACK */, serverACK, serverSeq+1, nil))

	// 4. The handshake completes; handleTCP dials the destination.
	select {
	case got := <-dialed:
		if got != "153.3.238.127:443" {
			t.Errorf("dialed %q, want 153.3.238.127:443", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("flow never reached the router despite free budget slot")
	}
}

// stubRouter records DialFlow calls. It never completes the dial; the test
// only asserts that admission let the flow through.
type stubRouter struct {
	t      *testing.T
	dialed chan<- string
}

func (r *stubRouter) DialFlow(ctx context.Context, network, addr string) (Conn, error) {
	if network != "tcp" {
		r.t.Errorf("DialFlow network = %q, want tcp", network)
	}
	select {
	case r.dialed <- addr:
	default:
	}
	return nil, context.Canceled // never completes; admission is what we test
}

func (r *stubRouter) HandleDNS(ctx context.Context, query []byte) []byte { return nil }

var _ FlowRouter = (*stubRouter)(nil)