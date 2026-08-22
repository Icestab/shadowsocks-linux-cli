package tun

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// makeView is retained for potential zero-copy paths; the batch pump
// currently uses NewViewWithData.
func makeView(pkt []byte) *buffer.View {
	return buffer.NewViewWithData(append([]byte(nil), pkt...))
}

// parsePrefixAddr extracts the IP part of "198.18.0.1/15" style config.
func parsePrefixAddr(cidr string) netip.Addr {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return netip.Addr{}
	}
	return p.Addr()
}

// virtioNetHdrLen is the size of the kernel's virtio_net_hdr. wireguard-go's
// tun.CreateTUN always creates the device with IFF_VNET_HDR, which makes the
// kernel prepend this header to every packet read from the device AND expect
// it in front of every packet written back. tun.Device.Write therefore
// requires the packet to be supplied at a nonzero offset with that much
// scratch space in front (it zeroes the scratch bytes into the on-wire
// header; see handleGRO in wireguard-go's tun/offload_linux.go). Passing
// offset=0 makes every Write fail with "invalid offset" and silently drops
// the whole kernel-return path of the TUN — the stack emits SYN-ACKs and
// DNS replies into the void, apps never complete a connection, and with the
// DNS hijack active the machine looks entirely offline.
const virtioNetHdrLen = 10

// packForWrite copies a raw IP packet into a buffer that wireguard-go's
// tun.Device.Write accepts for an IFF_VNET_HDR device: virtioNetHdrLen
// scratch bytes in front, the packet starting at [virtioNetHdrLen:]. The
// returned offset is the value Write expects.
func packForWrite(pkt []byte) ([]byte, int) {
	buf := make([]byte, virtioNetHdrLen+len(pkt))
	copy(buf[virtioNetHdrLen:], pkt)
	return buf, virtioNetHdrLen
}

// maxConcurrentFlows bounds the number of simultaneously routed flows.
// Without a cap, the gvisor forwarder accepts an unbounded number of
// connections from local processes, letting any single app exhaust the
// daemon's memory/fds/goroutines (local DoS).
const maxConcurrentFlows = 4096

// Stack bridges the TUN device into a gvisor userspace TCP/IP stack and
// forwards each flow through the router.
type Stack struct {
	dev     *Device
	ep      *channel.Endpoint
	s       *stack.Stack
	router  FlowRouter
	dnsPort uint16 // UDP packets to this port go to the DNS handler
	nicID   tcpip.NICID

	// flowSlots is the admission-control semaphore: one slot per active
	// flow, acquired on accept and released when the flow ends.
	flowSlots chan struct{}

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// FlowRouter is the subset of the router the TUN stack needs (interface to
// keep packages decoupled).
type FlowRouter interface {
	DialFlow(ctx context.Context, network, addr string) (Conn, error)
	// HandleDNS answers a raw DNS query payload and returns the response.
	HandleDNS(ctx context.Context, query []byte) []byte
}

// Conn is a bidirectional byte stream.
type Conn interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

// NewStack builds and starts the userspace stack on dev. tcpHandler and
// udpHandler receive every accepted flow; DNS UDP flows are diverted to
// dnsHandler before udpHandler sees them.
func NewStack(dev *Device, router FlowRouter) (*Stack, error) {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Stack{
		dev:       dev,
		router:    router,
		dnsPort:   53,
		nicID:     1,
		flowSlots: make(chan struct{}, maxConcurrentFlows),
		cancel:    cancel,
	}

	const defaultMTU = 1500
	mtu := uint32(dev.MTU)
	if mtu == 0 {
		mtu = defaultMTU
	}
	s.ep = channel.New(512, mtu, "")

	opts := stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	}
	ns := stack.New(opts)

	if err := ns.CreateNIC(s.nicID, s.ep); err != nil {
		return nil, fmt.Errorf("gvisor create NIC: %v", err)
	}
	// Spoofing must be ON: app traffic captured by policy routing leaves the
	// kernel with the TUN's own address as its source (the route leaves via
	// sscli0, so source-address selection picks 198.18.0.1). The reply's
	// source is the app's original destination, which the stack only knows as
	// a temporary address. Without spoofing, the handshake's route lookup for
	// (src=<app-dst>, dst=198.18.0.1) fails with "no route to host" and no
	// SYN-ACK is ever emitted: every captured connection hangs in SYN-SENT
	// (observed live: rx stays 0, no debug logs, no eth0 egress). Spoofing
	// makes the stack accept/answer for any address — the standard gvisor
	// mechanism for transparent proxying stacks.
	if err := ns.SetSpoofing(s.nicID, true); err != nil {
		return nil, fmt.Errorf("gvisor enable spoofing: %v", err)
	}
	tunAddr := parsePrefixAddr(dev.tunAddress)
	if tunAddr.IsValid() {
		pa := tcpip.ProtocolAddress{
			Protocol: ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{
				Address:   tcpip.AddrFrom4(tunAddr.As4()),
				PrefixLen: 32,
			},
		}
		if err := ns.AddProtocolAddress(s.nicID, pa, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("gvisor add address: %v", err)
		}
	}
	// Accept packets for any destination: the TUN receives everything that
	// policy routing steers into it, not just its own subnet.
	ns.SetPromiscuousMode(s.nicID, true)
	// Route everything arriving on the NIC to the NIC itself: two default
	// routes (0.0.0.0/0 and ::/0) expressed as match-all subnets.
	any4, err := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes(make([]byte, 4)))
	if err != nil {
		return nil, fmt.Errorf("gvisor subnet v4: %v", err)
	}
	any6, err := tcpip.NewSubnet(tcpip.AddrFrom16([16]byte{}), tcpip.MaskFromBytes(make([]byte, 16)))
	if err != nil {
		return nil, fmt.Errorf("gvisor subnet v6: %v", err)
	}
	ns.SetRouteTable([]tcpip.Route{
		{Destination: any4, NIC: s.nicID},
		{Destination: any6, NIC: s.nicID},
	})

	tcpFwd := tcp.NewForwarder(ns, 0, 65536, func(r *tcp.ForwarderRequest) {
		s.handleTCP(ctx, r)
	})
	ns.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(ns, func(r *udp.ForwarderRequest) {
		s.handleUDP(ctx, r)
	})
	ns.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	s.s = ns

	s.wg.Add(3)
	go s.pumpTUNToStack(ctx)
	go s.pumpStackToTUN(ctx)
	go s.monitorTUN(ctx)
	return s, nil
}

// monitorTUN drains wireguard-go's device event channel. The device's
// background netlink/hack listeners block once the channel (capacity 5)
// fills; draining keeps them responsive. Events are surfaced in debug logs.
func (s *Stack) monitorTUN(ctx context.Context) {
	defer s.wg.Done()
	events := s.dev.dev.Events()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			if debugEnabled() {
				fmt.Printf("[sscli][debug] tun event: %v\n", ev)
			}
		}
	}
}

// Close stops the pumps and releases the stack.
//
// NOTE: callers must close the underlying TUN device first (or ensure
// traffic is flowing) — pumpTUNToStack otherwise blocks in Read and
// s.wg.Wait() would deadlock. See daemon.shutdown for the safe order.
func (s *Stack) Close() {
	s.cancel()
	s.wg.Wait()
}

// pumpTUNToStack reads IP packets from the kernel TUN and injects them into
// the gvisor link endpoint.
//
// The read is a batch API: with IFF_VNET_HDR + TUNSETOFFLOAD (both always
// enabled by wireguard-go's tun.CreateTUN), the kernel may coalesce an
// application's TCP burst into ONE GSO "superpacket" (up to ~64 KB, many
// MSS segments). wireguard-go's Read segments it via gsoSplit, which needs
// one output buffer per segment — we hand it BatchSize buffers. This is not
// optional: with a single buffer, every multi-segment GSO packet made
// Read fail with "too many segments" and the pump exited permanently,
// blackholing the whole TUN after the first data burst.
//
// BatchSize can still be exceeded for pathological superpackets; that error
// is a partial-read signal, not a device failure: drop and keep going
// (wireguard-go's own device loop does the same).
func (s *Stack) pumpTUNToStack(ctx context.Context) {
	defer s.wg.Done()
	batch := s.dev.dev.BatchSize()
	if batch < 1 {
		batch = 1
	}
	if batch > 64 { // a 64 KB GSO superpacket needs <= 45 MSS segments
		batch = 64
	}
	bufs := make([][]byte, batch)
	for i := range bufs {
		bufs[i] = make([]byte, 65536)
	}
	sizes := make([]int, batch)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := s.dev.dev.Read(bufs, sizes, 0)
		if err != nil {
			if err == tun.ErrTooManySegments {
				if debugEnabled() {
					fmt.Printf("[sscli][debug] tun read: dropped oversized GSO packet: %v\n", err)
				}
				continue
			}
			if ctx.Err() == nil {
				fmt.Printf("[sscli] warning: TUN read stopped: %v\n", err)
			}
			return // device closed
		}
		for i := 0; i < n; i++ {
			pkt := bufs[i][:sizes[i]]
			if len(pkt) == 0 {
				continue
			}
			proto := networkProto(pkt)
			if proto == 0 {
				continue // not an IPv4/IPv6 packet
			}
			var payload buffer.Buffer
			payload.Append(buffer.NewViewWithData(append([]byte(nil), pkt...)))
			pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
				ReserveHeaderBytes: int(s.ep.MaxHeaderLength()),
				Payload:            payload,
			})
			s.ep.InjectInbound(proto, pb)
			pb.DecRef()
		}
	}
}

// pumpStackToTUN writes stack-emitted packets back out to the TUN.
func (s *Stack) pumpStackToTUN(ctx context.Context) {
	defer s.wg.Done()
	for {
		pkt := s.ep.ReadContext(ctx)
		if pkt == nil {
			return
		}
		out := pkt.ToView().ToSlice()
		if len(out) > 0 {
			buf, offset := packForWrite(out)
			if _, err := s.dev.dev.Write([][]byte{buf}, offset); err != nil && debugEnabled() {
				fmt.Printf("[sscli][debug] tun write: %v\n", err)
			}
		}
		pkt.DecRef()
	}
}

func networkProto(pkt []byte) tcpip.NetworkProtocolNumber {
	if len(pkt) < 1 {
		return 0
	}
	switch pkt[0] >> 4 {
	case 4:
		return ipv4.ProtocolNumber
	case 6:
		return ipv6.ProtocolNumber
	default:
		return 0
	}
}
