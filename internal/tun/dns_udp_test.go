package tun

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// buildUDPPacket crafts a syntactically valid IPv4+UDP packet with correct
// checksums, mimicking a datagram the kernel would route into the TUN.
func buildUDPPacket(src, dst netip.Addr, sport, dport uint16, payload []byte) []byte {
	src4, dst4 := src.As4(), dst.As4()
	total := 28 + len(payload)
	pkt := make([]byte, total)

	// IPv4 header.
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[8] = 64 // TTL
	pkt[9] = 17 // UDP
	copy(pkt[12:16], src4[:])
	copy(pkt[16:20], dst4[:])
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))

	// UDP header.
	udpH := pkt[20:]
	binary.BigEndian.PutUint16(udpH[0:2], sport)
	binary.BigEndian.PutUint16(udpH[2:4], dport)
	binary.BigEndian.PutUint16(udpH[4:6], uint16(8+len(payload)))
	copy(udpH[8:], payload)

	// UDP checksum with pseudo-header (same helper as TCP: sum over
	// pseudo-header then segment).
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src4[:])
	copy(pseudo[4:8], dst4[:])
	pseudo[8] = 0
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(8+len(payload)))
	binary.BigEndian.PutUint16(udpH[6:8], tcpChecksum(pseudo, udpH[:8+len(payload)]))
	return pkt
}

// cannedRouter returns a fixed DNS payload for every query and never dials.
type cannedRouter struct{ resp []byte }

func (c *cannedRouter) DialFlow(ctx context.Context, network, addr string) (Conn, error) {
	return nil, fmt.Errorf("unexpected dial in UDP DNS test: %s %s", network, addr)
}

func (c *cannedRouter) HandleDNS(ctx context.Context, query []byte) []byte { return c.resp }

// newUDPServerHarness wires a promiscuous spoofed stack whose UDP
// forwarder routes straight into the real Stack.handleUDP — the exact
// wiring NewStack uses for DNS flows.
func newUDPServerHarness(t *testing.T, s *Stack) (*channel.Endpoint, *stack.Stack) {
	t.Helper()
	ep := channel.New(512, 1500, "")
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})
	if err := st.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	if err := st.SetSpoofing(1, true); err != nil {
		t.Fatalf("SetSpoofing: %v", err)
	}
	pa := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{198, 18, 0, 1}),
			PrefixLen: 32,
		},
	}
	if err := st.AddProtocolAddress(1, pa, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %v", err)
	}
	st.SetPromiscuousMode(1, true)
	any4, err := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes(make([]byte, 4)))
	if err != nil {
		t.Fatalf("NewSubnet: %v", err)
	}
	st.SetRouteTable([]tcpip.Route{{Destination: any4, NIC: 1}})
	fwd := udp.NewForwarder(st, func(r *udp.ForwarderRequest) {
		s.handleUDP(context.Background(), r)
	})
	st.SetTransportProtocolHandler(udp.ProtocolNumber, fwd.HandlePacket)
	return ep, st
}

// TestUDPServerReapsIdleDNSFlows guards the UDP DNS flow leak: gvisor's
// udp.Forwarder endpoints have NO idle timeout and our server loop reads
// until error, so without the reaper every one-off DNS query (plain glibc
// opens a fresh socket per lookup) would pin a goroutine + endpoint
// forever. The flow must answer queries, close itself after the idle
// window, and a later query on the SAME 5-tuple must start a fresh flow.
func TestUDPServerReapsIdleDNSFlows(t *testing.T) {
	resp := []byte("dns-response-bytes")
	s := &Stack{
		router:         &cannedRouter{resp: resp},
		dnsPort:        53,
		dnsIdleTimeout: 150 * time.Millisecond,
		udpConns:       make(map[*gonet.UDPConn]struct{}),
	}
	ep, st := newUDPServerHarness(t, s)
	defer st.Close()
	defer ep.Close()

	src := netip.MustParseAddr("198.18.0.1")
	query := buildUDPPacket(src, netip.MustParseAddr("8.8.8.8"), 54321, 53, []byte("fake-dns-query"))

	inject := func() {
		t.Helper()
		pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(ep.MaxHeaderLength()),
			Payload:            bufFromData(query),
		})
		ep.InjectInbound(ipv4.ProtocolNumber, pb)
		pb.DecRef()
	}
	readReply := func() {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pkt := ep.ReadContext(ctx)
		if pkt == nil {
			t.Fatal("no reply packet emitted by the stack")
		}
		defer pkt.DecRef()
		out := pkt.ToView().ToSlice()
		if len(out) < 28 {
			t.Fatalf("reply too short: %d bytes", len(out))
		}
		udpH := out[20:]
		if sport := binary.BigEndian.Uint16(udpH[0:2]); sport != 53 {
			t.Errorf("reply source port = %d, want 53", sport)
		}
		if dport := binary.BigEndian.Uint16(udpH[2:4]); dport != 54321 {
			t.Errorf("reply dst port = %d, want 54321", dport)
		}
		if got := udpH[8:]; !bytes.Equal(got, resp) {
			t.Errorf("reply payload = %q, want %q", got, resp)
		}
	}

	// 1. A query spawns a flow and gets answered.
	inject()
	readReply()
	if got := s.activeUDPFlows.Load(); got != 1 {
		t.Fatalf("active DNS flows = %d, want 1 after first query", got)
	}

	// 2. After the idle window the flow must reap itself (goroutine gone).
	deadline := time.Now().Add(2 * time.Second)
	for s.activeUDPFlows.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("DNS flow was not reaped after the idle timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 3. A new query on the same 5-tuple gets a fresh flow and is answered.
	inject()
	readReply()
	if got := s.activeUDPFlows.Load(); got != 1 {
		t.Fatalf("active DNS flows = %d, want 1 after re-query", got)
	}
}

// TestStackCloseTerminatesDNSFlows proves Stack.Close ends live DNS flows
// (closing the endpoint wakes the blocked ReadFrom), so shutdown is not
// delayed by silent flows.
func TestStackCloseTerminatesDNSFlows(t *testing.T) {
	resp := []byte("dns-response-bytes")
	_, cancel := context.WithCancel(context.Background())
	s := &Stack{
		router:         &cannedRouter{resp: resp},
		dnsPort:        53,
		dnsIdleTimeout: time.Hour, // far beyond the test; only Close may end it
		udpConns:       make(map[*gonet.UDPConn]struct{}),
		cancel:         cancel,
	}
	ep, st := newUDPServerHarness(t, s)
	defer st.Close()
	defer ep.Close()

	src := netip.MustParseAddr("198.18.0.1")
	query := buildUDPPacket(src, netip.MustParseAddr("8.8.8.8"), 54321, 53, []byte("fake-dns-query"))
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(ep.MaxHeaderLength()),
		Payload:            bufFromData(query),
	})
	ep.InjectInbound(ipv4.ProtocolNumber, pb)
	pb.DecRef()

	// Let the flow come up.
	deadline := time.Now().Add(2 * time.Second)
	for s.activeUDPFlows.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("DNS flow never came up")
		}
		time.Sleep(10 * time.Millisecond)
	}

	s.Close()

	deadline = time.Now().Add(2 * time.Second)
	for s.activeUDPFlows.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("Stack.Close did not terminate the DNS flow")
		}
		time.Sleep(10 * time.Millisecond)
	}
}