package proxy

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/net/proxy"

	"github.com/Icestab/sscli/internal/config"
)

// Fwmark is the packet mark applied to sscli's own outbound sockets so the
// kernel policy rules route them via the original default gateway instead
// of back into the TUN device (proxy-loop prevention).
const Fwmark = 0x162

// Dialer produces outbound connections for a routing decision.
type Dialer interface {
	// DialContext connects to host:port. host may be a domain name; PROXY
	// passes it through SOCKS5 ATYP=domain (resolved remotely), DIRECT
	// resolves locally.
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// ProxyDialer dials targets through the managed sslocal SOCKS5 endpoint.
type ProxyDialer struct {
	socksAddr string
}

// NewProxyDialer returns a dialer that routes through sslocal's local
// SOCKS5 server.
func NewProxyDialer(cfg *config.Config) *ProxyDialer {
	return &ProxyDialer{socksAddr: cfg.Sslocal.SocksAddr}
}

func (d *ProxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var auth *proxy.Auth // no auth on loopback sslocal
	dialer, err := proxy.SOCKS5("tcp", d.socksAddr, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("socks5 dialer: %w", err)
	}
	cd, ok := dialer.(proxy.ContextDialer)
	if !ok {
		// Fall back to plain Dial in a goroutine honouring ctx cancellation
		// loosely.
		type res struct {
			c   net.Conn
			err error
		}
		ch := make(chan res, 1)
		go func() {
			c, e := dialer.Dial(network, addr)
			ch <- res{c, e}
		}()
		select {
		case r := <-ch:
			return r.c, r.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return cd.DialContext(ctx, network, addr)
}

// DirectDialer dials natively with SO_MARK set so packets bypass the TUN
// policy routing. Requires CAP_NET_ADMIN; without privileges we fall back
// to unmarked dialing (fine when no TUN hijack is active, e.g. tests).
type DirectDialer struct {
	Timeout time.Duration
}

var _ Dialer = (*DirectDialer)(nil)

func (d *DirectDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dl := d.Timeout
	if dl == 0 {
		dl = 10 * time.Second
	}
	nd := net.Dialer{
		Timeout: dl,
		Control: func(network, address string, c syscall.RawConn) error {
			var ctlErr error
			err := c.Control(func(fd uintptr) {
				ctlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, Fwmark)
			})
			if err != nil {
				return err
			}
			if ctlErr != nil {
				// EPERM without CAP_NET_ADMIN: tolerate — only matters while
				// the TUN default route is installed.
				return nil //nolint:nilerr // deliberate fallback, see comment
			}
			return nil
		},
	}
	return nd.DialContext(ctx, network, addr)
}
