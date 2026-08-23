package tun

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// buildTCPSYN crafts a syntactically valid IPv4+TCP SYN packet with correct
// checksums, mimicking exactly what the kernel routes into the TUN for an
// application connection (source = the TUN's own 198.18.0.1, because the
// default route in table 5162 leaves via sscli0 and kernel source-address
// selection picks the TUN address).
func buildTCPSYN(src, dst netip.Addr, sport, dport uint16) []byte {
	return buildTCPPacket(src, dst, sport, dport, 0x02 /* SYN */, 0, 0, nil)
}

// buildTCPPacket crafts a syntactically valid IPv4+TCP packet with correct
// checksums. seq/ack/flags/payload are explicit so tests can drive a full
// handshake (SYN -> SYN-ACK -> ACK) through the real gvisor wiring.
func buildTCPPacket(src, dst netip.Addr, sport, dport uint16, flags byte, seq, ack uint32, payload []byte) []byte {
	src4, dst4 := src.As4(), dst.As4()
	total := 40 + len(payload)
	pkt := make([]byte, total)

	// IPv4 header.
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[8] = 64 // TTL
	pkt[9] = 6  // TCP
	copy(pkt[12:16], src4[:])
	copy(pkt[16:20], dst4[:])
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum(pkt[:20]))

	// TCP header.
	tcpH := pkt[20:]
	binary.BigEndian.PutUint16(tcpH[0:2], sport)
	binary.BigEndian.PutUint16(tcpH[2:4], dport)
	binary.BigEndian.PutUint32(tcpH[4:8], seq)
	binary.BigEndian.PutUint32(tcpH[8:12], ack)
	tcpH[12] = 0x50                    // data offset 5
	tcpH[13] = flags                   // SYN/ACK/RST...
	binary.BigEndian.PutUint16(tcpH[16:18], 65535) // window

	// TCP checksum with pseudo-header.
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src4[:])
	copy(pseudo[4:8], dst4[:])
	pseudo[8] = 0
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcpH)+len(payload)))
	binary.BigEndian.PutUint16(tcpH[16:18], tcpChecksum(pseudo, append(tcpH, payload...)))
	return pkt
}

func bufFromData(b []byte) buffer.Buffer {
	var buf buffer.Buffer
	buf.Append(buffer.NewViewWithData(b))
	return buf
}

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func tcpChecksum(pseudo, tcpH []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	for i := 0; i+1 < len(tcpH); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpH[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func addrFromTCPIP(a tcpip.Address) netip.Addr {
	var b [4]byte
	copy(b[:], a.AsSlice())
	return netip.AddrFrom4(b)
}

// newTestStack replicates the exact wiring of Stack.NewStack: channel link
// endpoint, promiscuous NIC, match-all route table, TCP forwarder.
func newTestStack(t *testing.T, forwarded chan<- netip.AddrPort, createErr chan<- string) (*channel.Endpoint, *stack.Stack) {
	t.Helper()
	ep := channel.New(512, 1500, "")
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
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

	fwd := tcp.NewForwarder(st, 0, 65536, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		forwarded <- netip.AddrPortFrom(addrFromTCPIP(id.LocalAddress), id.LocalPort)
		wq := &waiter.Queue{}
		ep, err := r.CreateEndpoint(wq)
		if err != nil {
			if createErr != nil {
				select {
				case createErr <- err.String():
				default:
				}
			}
			r.Complete(false)
			return
		}
		r.Complete(true)
		_ = ep
	})
	st.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	return ep, st
}

// TestGvisorForwarderReceivesForeignDstSYN proves that the Stack wiring
// used by NewStack — channel endpoint + promiscuous NIC + match-all route
// table — delivers an inbound TCP SYN destined to a NON-local address to
// the forwarder, and that the stack emits the SYN-ACK back into the
// channel. If this fails, every TUN flow is dropped inside gvisor before
// the router ever sees it.
func TestGvisorForwarderReceivesForeignDstSYN(t *testing.T) {
	forwarded := make(chan netip.AddrPort, 4)
	createErr := make(chan string, 4)
	ep, st := newTestStack(t, forwarded, createErr)
	defer st.Close()
	defer ep.Close()

	src := netip.MustParseAddr("198.18.0.1")
	dst := netip.MustParseAddr("153.3.238.127") // non-local, like a real app dest
	syn := buildTCPSYN(src, dst, 54438, 27314)

	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(ep.MaxHeaderLength()),
		Payload:            bufFromData(syn),
	})
	ep.InjectInbound(ipv4.ProtocolNumber, pb)
	pb.DecRef()

	select {
	case got := <-forwarded:
		want := netip.AddrPortFrom(dst, 27314)
		if got != want {
			t.Fatalf("forwarder dst = %v, want %v", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("forwarder was never invoked: non-local SYN dropped by the stack")
	}

	// The stack must emit the SYN-ACK into the channel (this is the packet
	// pumpStackToTUN would write back to the TUN).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pkt := ep.ReadContext(ctx)
	if pkt == nil {
		select {
		case err := <-createErr:
			t.Fatalf("CreateEndpoint failed: %s", err)
		default:
		}
		t.Fatalf("stack emitted no SYN-ACK into the channel (ip4 outgoing errs=%d, malformed recv=%d, tcp failed conns=%d)",
			st.Stats().IP.OutgoingPacketErrors.Value(), st.Stats().IP.MalformedPacketsReceived.Value(), st.Stats().TCP.FailedConnectionAttempts.Value())
	}
	view := pkt.ToView().ToSlice()
	if len(view) < 40 {
		t.Fatalf("emitted packet too short: %d bytes", len(view))
	}
	tcpH := view[20:]
	if sport := binary.BigEndian.Uint16(tcpH[0:2]); sport != 27314 {
		t.Errorf("SYN-ACK source port = %d, want 27314 (echo of dst port)", sport)
	}
	if dport := binary.BigEndian.Uint16(tcpH[2:4]); dport != 54438 {
		t.Errorf("SYN-ACK dst port = %d, want 54438 (echo of src port)", dport)
	}
	if tcpH[13]&0x12 != 0x12 {
		t.Errorf("expected SYN|ACK flags, got %#x", tcpH[13])
	}
	pkt.DecRef()
}

// TestGvisorDropsWithoutPromiscuous is the control: without promiscuous
// mode the same SYN must be dropped (proves the test is sensitive to the
// promiscuous flag that NewStack relies on).
func TestGvisorDropsWithoutPromiscuous(t *testing.T) {
	forwarded := make(chan netip.AddrPort, 4)
	ep := channel.New(512, 1500, "")
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})
	if err := st.CreateNIC(1, ep); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	// Promiscuous mode deliberately OFF.
	any4, err := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes(make([]byte, 4)))
	if err != nil {
		t.Fatalf("NewSubnet: %v", err)
	}
	st.SetRouteTable([]tcpip.Route{{Destination: any4, NIC: 1}})
	fwd := tcp.NewForwarder(st, 0, 65536, func(r *tcp.ForwarderRequest) {
		forwarded <- netip.AddrPortFrom(addrFromTCPIP(r.ID().LocalAddress), r.ID().LocalPort)
	})
	st.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	defer st.Close()
	defer ep.Close()

	syn := buildTCPSYN(netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("153.3.238.127"), 54438, 27314)
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(ep.MaxHeaderLength()),
		Payload:            bufFromData(syn),
	})
	ep.InjectInbound(ipv4.ProtocolNumber, pb)
	pb.DecRef()

	select {
	case got := <-forwarded:
		t.Fatalf("forwarder invoked with dst %v although promiscuous mode is off", got)
	case <-time.After(500 * time.Millisecond):
		// expected: dropped
	}
}