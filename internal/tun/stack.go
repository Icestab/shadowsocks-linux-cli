package tun

import (
	"context"
	"fmt"
	"net/netip"
	"sync"

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

// Stack bridges the TUN device into a gvisor userspace TCP/IP stack and
// forwards each flow through the router.
type Stack struct {
	dev     *Device
	ep      *channel.Endpoint
	s       *stack.Stack
	router  FlowRouter
	dnsPort uint16 // UDP packets to this port go to the DNS handler
	nicID   tcpip.NICID

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
		dev:     dev,
		router:  router,
		dnsPort: 53,
		nicID:   1,
		cancel:  cancel,
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

	s.wg.Add(2)
	go s.pumpTUNToStack(ctx)
	go s.pumpStackToTUN(ctx)
	return s, nil
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
// the gvisor link endpoint. The wireguard/tun device uses a batch API; we
// read one packet at a time, which is plenty for a CLI proxy.
func (s *Stack) pumpTUNToStack(ctx context.Context) {
	defer s.wg.Done()
	bufs := make([][]byte, 1)
	bufs[0] = make([]byte, 65536)
	sizes := make([]int, 1)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, err := s.dev.dev.Read(bufs, sizes, 0)
		if err != nil {
			return // device closed
		}
		_ = n
		pkt := bufs[0][:sizes[0]]
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
			_, _ = s.dev.dev.Write([][]byte{out}, 0)
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
