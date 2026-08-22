package tun

import (
	"context"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// fakeReadStep is one scripted result of fakeTUN.Read.
type fakeReadStep struct {
	pkts [][]byte
	err  error
}

// fakeTUN implements tun.Device with a scripted Read for testing the pump
// without kernel privileges.
type fakeTUN struct {
	mu     sync.Mutex
	script []fakeReadStep
	idx    int
	events chan tun.Event
}

func newFakeTUN(steps ...fakeReadStep) *fakeTUN {
	return &fakeTUN{script: steps, events: make(chan tun.Event, 4)}
}

func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.idx >= len(f.script) {
		return 0, os.ErrClosed
	}
	step := f.script[f.idx]
	f.idx++
	if step.err != nil {
		return 0, step.err
	}
	n := len(step.pkts)
	if n > len(bufs) {
		n = len(bufs)
	}
	for i := 0; i < n; i++ {
		sizes[i] = copy(bufs[i][offset:], step.pkts[i])
	}
	return n, nil
}

func (f *fakeTUN) Write([][]byte, int) (int, error) { return 0, nil }
func (f *fakeTUN) MTU() (int, error)                 { return 1500, nil }
func (f *fakeTUN) Name() (string, error)             { return "test0", nil }
func (f *fakeTUN) Events() <-chan tun.Event          { return f.events }
func (f *fakeTUN) Close() error                      { return nil }
func (f *fakeTUN) BatchSize() int                    { return 4 }
func (f *fakeTUN) File() *os.File                    { return nil }

// TestPumpProcessesEverySegmentOfABatchRead is the regression test for
// "TUN read stopped: too many segments": the kernel coalesces TCP bursts
// into GSO superpackets that wireguard-go segments into MULTIPLE buffers
// per Read. The pump must inject every returned segment (the earlier code
// allocated exactly ONE buffer, so any 2+ segment GSO packet failed the
// read and killed the pump after the first data burst — the machine went
// offline right after the first successful connection).
func TestPumpProcessesEverySegmentOfABatchRead(t *testing.T) {
	received := make(chan netip.AddrPort, 16)
	ep, st := newForwarderHarness(t, received)
	defer st.Close()
	defer ep.Close()

	src := netip.MustParseAddr("198.18.0.1")
	synA := buildTCPSYN(src, netip.MustParseAddr("153.3.238.127"), 1111, 80)
	synB := buildTCPSYN(src, netip.MustParseAddr("198.51.100.7"), 2222, 443)
	synC := buildTCPSYN(src, netip.MustParseAddr("203.0.113.9"), 3333, 22)

	// Script: one multi-packet read, then a too-many-segments error, then
	// another packet. The pump must survive the error and keep serving.
	fdev := newFakeTUN(
		fakeReadStep{pkts: [][]byte{synA, synB}},
		fakeReadStep{err: tun.ErrTooManySegments},
		fakeReadStep{pkts: [][]byte{synC}},
	)
	s := &Stack{dev: &Device{dev: fdev, Name: "test0", MTU: 1500}, ep: ep}
	s.wg.Add(1) // pumpTUNToStack defers wg.Done; NewStack normally adds before launch

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		s.pumpTUNToStack(ctx)
		close(done)
	}()

	// The forwarder spawns one goroutine per SYN, so the flow signals may
	// arrive in any order; assert the SET of flows, not their order.
	want := map[netip.AddrPort]string{
		netip.AddrPortFrom(netip.MustParseAddr("153.3.238.127"), 80):  "segment A (first of batch)",
		netip.AddrPortFrom(netip.MustParseAddr("198.51.100.7"), 443): "segment B (second of batch)",
		netip.AddrPortFrom(netip.MustParseAddr("203.0.113.9"), 22):   "packet C (after ErrTooManySegments)",
	}
	deadline := time.After(5 * time.Second)
	for len(want) > 0 {
		select {
		case got := <-received:
			if _, ok := want[got]; !ok {
				t.Fatalf("unexpected flow %v", got)
			}
			delete(want, got)
		case <-deadline:
			t.Fatalf("missing flows; ip rx=%d valid=%d invalidDst=%d malformed=%d disabled=%d",
				st.Stats().IP.PacketsReceived.Value(),
				st.Stats().IP.ValidPacketsReceived.Value(),
				st.Stats().IP.InvalidDestinationAddressesReceived.Value(),
				st.Stats().IP.MalformedPacketsReceived.Value(),
				st.Stats().IP.DisabledPacketsReceived.Value(),
			)
		}
	}

	// The pump must still be alive after the script ran out and the device
	// reported closure; cancel stops it cleanly.
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pump did not stop after cancel")
	}
}

// newForwarderHarness wires a channel endpoint + spoofed promiscuous stack
// with a forwarder whose handler only reports flows (does not handshake).
func newForwarderHarness(t *testing.T, received chan<- netip.AddrPort) (*channel.Endpoint, *stack.Stack) {
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
		received <- netip.AddrPortFrom(addrFromTCPIP(r.ID().LocalAddress), r.ID().LocalPort)
	})
	st.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	return ep, st
}