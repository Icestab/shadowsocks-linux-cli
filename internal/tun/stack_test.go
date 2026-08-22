package tun

import (
	"bytes"
	"testing"
)

func TestPackForWrite(t *testing.T) {
	pkt := make([]byte, 40) // minimal IPv4 header + some payload
	for i := range pkt {
		pkt[i] = byte(i)
	}
	buf, offset := packForWrite(pkt)

	if offset != virtioNetHdrLen {
		t.Fatalf("offset = %d, want virtioNetHdrLen (%d)", offset, virtioNetHdrLen)
	}
	if len(buf) != virtioNetHdrLen+len(pkt) {
		t.Fatalf("buffer len = %d, want %d", len(buf), virtioNetHdrLen+len(pkt))
	}
	// The packet must sit exactly at [offset:] so wireguard-go's
	// tun.Device.Write accepts the buffer for an IFF_VNET_HDR device
	// (offset=0 fails handleGRO with "invalid offset" and the write is
	// dropped - the TUN return path dies silently).
	if !bytes.Equal(buf[offset:], pkt) {
		t.Errorf("packet bytes not preserved at offset %d", offset)
	}
	// The leading scratch space is zeroed so the kernel sees a well-formed
	// virtio_net_hdr (GSO_NONE, no csum flags) in front of the packet.
	for i := 0; i < offset; i++ {
		if buf[i] != 0 {
			t.Fatalf("scratch byte %d = %#x, want 0", i, buf[i])
		}
	}
}

func TestPackForWriteEmptyPacket(t *testing.T) {
	buf, offset := packForWrite(nil)
	if offset != virtioNetHdrLen {
		t.Fatalf("offset = %d, want %d", offset, virtioNetHdrLen)
	}
	if len(buf) != virtioNetHdrLen {
		t.Fatalf("buffer len = %d, want %d", len(buf), virtioNetHdrLen)
	}
}