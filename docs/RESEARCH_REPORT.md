# sscli Research Report: Go TUN Proxy Client Dependencies & Architecture

**Date:** 2025-07  
**Target:** WSL2 + native Linux, Go 1.26

---

## 1. Userspace TCP/IP Stack: gVisor Netstack

### Confirmation

**Yes — gvisor netstack is the standard choice.** The following projects all use it:

- **[xjasonlyu/tun2socks](https://github.com/xjasonlyu/tun2socks)** (v2, MIT license): Uses `gvisor.dev/gvisor/pkg/tcpip` stack with `golang.zx2c4.com/wireguard/tun` for TUN device creation. The engine in `core/stack.go` creates a gvisor `stack.Stack`, attaches a `channel.Endpoint` as the NIC, and bridges IP packets between the TUN fd and the gvisor channel.
- **sing-box** (SagerNet): Uses `sing-tun` which wraps gvisor netstack. In `tun/gvisor.go`, it creates a `stack.Stack`, attaches a `channel.Endpoint`, and uses gvisor's built-in TCP/IP handling with custom transport dispatchers.
- **mihomo** (MetaCubeX/Clash.Meta): Uses gvisor netstack identically — `stack.Stack` + `channel.Endpoint`, with custom DNS handling.
- **[celzero/firestack](https://github.com/celzero/firestack)** (Intra for Android): Also uses gvisor netstack.
- **[noisysockets/netstack](https://github.com/noisysockets/netstack)**: A fork/vendored copy of gvisor netstack with a cleaner API, though the original `gvisor.dev/gvisor` is the canonical import.

### Architecture Pattern (used by all of the above)

```
TUN device (wireguard/tun) <---> goroutine reads IP packets
                                      |
                                      v
                              gvisor channel.Endpoint (link layer)
                                      |
                                      v
                              gvisor stack.Stack (TCP/IP stack)
                                      |
                                      v
                              Transport Demuxer (TCP/UDP handlers)
                                      |
                                      v
                              Your proxy logic (SOCKS5 dial / direct dial)
```

The key insight: gvisor netstack operates as a pure userspace TCP/IP stack. IP packets flow from TUN → `channel.Endpoint` → gvisor stack processes them → your handler gets notified of new connections/data. For outgoing connections, your handler creates endpoints in the stack, and gvisor generates the IP packets that you write back to TUN.

### Licensing

| Library | License | Usable as library? |
|---------|---------|-------------------|
| `gvisor.dev/gvisor` | Apache 2.0 | ✅ Yes — permissive, commercial use OK |
| [xjasonlyu/tun2socks](https://github.com/xjasonlyu/tun2socks) | MIT | ✅ Yes — can import, but it's a standalone binary, not designed as a library. Take inspiration, use gvisor directly. |
| [sing-tun](https://github.com/sagernet/sing-tun) | GPLv3 | ⚠️ **Copyleft** — can import, but your project must be GPLv3. Not suitable for proprietary/commercial use. |
| [sing-box](https://github.com/SagerNet/sing-box) | BSL 1.1 (was Apache 2.0, changed) | ⚠️ Business Source License — restrictions on competing services |

**Recommendation:** Use `gvisor.dev/gvisor` directly (Apache 2.0). Do NOT import `sing-tun` or `sing-box` — they pull in massive dependency trees and carry copyleft/restrictive licenses. The gvisor netstack API is well-documented and the pattern is simple enough to implement yourself (~200 lines).

### Module Import

```
gvisor.dev/gvisor@v0.0.0-20250619
```

> Note: gvisor uses pseudo-versions (no semver tags). Pin to a recent commit hash. Check [pkg.go.dev](https://pkg.go.dev/gvisor.dev/gvisor) for latest.

---

## 2. TUN Device Creation: wireguard/tun

### API Confirmation

Module: `golang.zx2c4.com/wireguard/tun`

**Current API (v0.0.20210219 and later — this package is intentionally unversioned):**

```go
package main

import (
    "os"
    "golang.zx2c4.com/wireguard/tun"
)

func createTUN(name string, mtu int) (tun.Device, error) {
    // Creates/opens TUN device by name (e.g., "sscli0")
    // On Linux, creates /dev/net/tun with IFF_TUN | IFF_NO_PI
    device, err := tun.CreateTUN(name, mtu)
    if err != nil {
        return nil, err
    }

    // Get the actual OS file descriptor for raw IP packet I/O
    fd, err := device.File()  // returns *os.File
    if err != nil {
        return nil, err
    }

    return device, nil
}
```

**Key methods on `tun.Device` interface:**

```go
type Device interface {
    Read(buf []byte, offset int) (n int, err error)   // Read IP packets from TUN
    Write(buf []byte, offset int) (n int, err error)   // Write IP packets to TUN
    Flush() error
    Close() error
    MTU() (int, error)
    Name() (string, error)     // returns "sscli0" etc.
    Events() <-chan TUNEvent   // sends TUNUp/TUNDown events
    File() *os.File            // raw fd for use with gvisor
}
```

**Bridging with gvisor:** You use `device.File()` to get the `*os.File`, then wrap it with gvisor's link layer or use the `channel.Endpoint` pattern:

```go
import (
    "gvisor.dev/gvisor/pkg/tcpip"
    "gvisor.dev/gvisor/pkg/tcpip/link/channel"
    "gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Create gvisor stack
s := stack.New(stack.Options{
    TransportProtocols: []stack.TransportProtocolFactory{
        tcp.NewProtocol,
        udp.NewProtocol,
    },
})

// Create channel endpoint (link layer between TUN and gvisor)
ep := channel.New(256, 1500, tcpip.FullHardwareAddress{})

// Attach to stack as NIC
s.CreateNIC(1, ep)

// Set default route
s.SetRouteTable([]tcpip.Route{{
    Destination: tcpip.MustParseAddress("0.0.0.0/0"),
    NIC:         1,
}})
```

**Wireguard/tun license:** MIT — permissive, no restrictions.

> **Package note:** `golang.zx2c4.com/wireguard/tun` is the canonical import path (not `github.com/WireGuard/wireguard-go/tun`). The package uses pseudo-versioning. For Go 1.26, use the latest available pseudo-version from `pkg.go.dev/golang.zx2c4.com/wireguard/tun`.

---

## 3. SOCKS5 Client Library: `golang.org/x/net/proxy`

### API

Module: `golang.org/x/net/proxy`

**Yes, supports SOCKS5 with username/password auth.**

```go
package main

import (
    "context"
    "fmt"
    "net"

    "golang.org/x/net/proxy"
)

func dialViaSocks5(socksAddr, targetHost, targetPort string, user, pass string) (net.Conn, error) {
    // Create SOCKS5 dialer with optional auth
    var auth *proxy.Auth
    if user != "" {
        auth = &proxy.Auth{User: user, Password: pass}
    }

    dialer, err := proxy.SOCKS5("tcp", socksAddr, auth, proxy.Direct)
    if err != nil {
        return nil, fmt.Errorf("creating SOCKS5 dialer: %w", err)
    }

    // The returned dialer implements ContextDialer (since Go 1.18+)
    // So DialContext is available:
    ctx := context.Background()
    conn, err := dialer.(interface {
        DialContext(ctx context.Context, network, address string) (net.Conn, error)
    }).DialContext(ctx, "tcp", net.JoinHostPort(targetHost, targetPort))
    if err != nil {
        return nil, err
    }
    return conn, nil
}
```

### Context Support

`x/net/proxy` historically did NOT support `context.Context` (see [golang/go#19354](https://github.com/golang/go/issues/19354)). However:

- The `Dialer` returned by `proxy.SOCKS5()` implements the **`ContextDialer`** interface (added in x/net). This is confirmed by [golang/go#58376](https://github.com/golang/go/issues/58376) which documents that returned Dialers now implement `ContextDialer`.
- Since Go 1.18+, the returned type assertion to `interface{ DialContext(...) }` works.
- **ATYP=domain support:** When you pass a hostname (not IP) as the target address, the SOCKS5 client in `x/net` sends it as ATYP=0x03 (domain name), which means the SOCKS5 proxy (sslocal) performs DNS resolution on the remote side. This is exactly what you want for rule-based routing with domain matching.

### Alternative Libraries

| Library | Context Support | Auth | Notes |
|---------|----------------|------|-------|
| `golang.org/x/net/proxy` | ✅ via ContextDialer | ✅ user/pass | Standard library, minimal, proven |
| `github.com/things-go/go-socks5` | Server-side only | ✅ | This is a SOCKS5 **server** lib, not client |
| `github.com/armon/go-socks5` | Server-side only | ✅ | Same — server lib |

**Recommendation:** `golang.org/x/net/proxy` is the clear choice. It's the de facto standard, minimal, and well-maintained as part of the Go extended ecosystem.

### Module Import

```
golang.org/x/net@v0.33.0
```

---

## 4. SO_MARK on Outgoing Sockets (Direct Flows)

### Approach

Use `net.Dialer{Control: ...}` with `golang.org/x/sys/unix` to set `SO_MARK` on the socket before connect. This marks the packet so `ip rule` / `iptables` can route it outside the TUN (bypass the route table that sends traffic to the TUN device).

```go
package main

import (
    "context"
    "net"
    "syscall"

    "golang.org/x/sys/unix"
)

const FwMark uint32 = 0x100 // must match your ip rule / ip route mark

func dialWithMark(addr string) (net.Conn, error) {
    dialer := &net.Dialer{
        Control: func(network, address string, c syscall.RawConn) error {
            return c.Control(func(fd uintptr) {
                unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(FwMark))
            })
        },
        Timeout: 10 * time.Second,
    }

    conn, err := dialer.DialContext(context.Background(), "tcp", addr)
    if err != nil {
        return nil, err
    }
    return conn, nil
}
```

### Requirements

- **`CAP_NET_ADMIN`** capability is required to set `SO_MARK`. Your process needs:
  - `sudo setcap cap_net_admin+ep ./sscli` (file capability), or
  - Run as root, or
  - Use `sudo` / `sysctl` to allow unprivileged user marking (not default).
- Corresponding **ip rule** setup:
  ```bash
  # Packets with mark 0x100 skip the TUN route and go via default route
  ip rule add fwmark 0x100 lookup main priority 10
  ```
  This must be set up before TUN mode starts, or alongside it.

### Module Import

```
golang.org/x/sys@v0.28.0
```

---

## 5. DNS Loop Prevention & Hijacking in TUN Mode

### Mechanism (as used by sing-box, mihomo, tun2socks)

All TUN-mode proxies intercept DNS internally to prevent loops. The mechanism is:

**Inside the userspace gvisor TCP/IP stack, intercept all UDP packets destined for port 53 (DNS) and redirect them to an internal resolver instead of forwarding them out.**

Detailed flow:

1. **The gvisor stack's UDP transport handler is configured with a custom dispatcher.** When a UDP packet arrives at the stack with destination port 53:
   - If the packet is from a process on the host (it entered TUN → gvisor processed it → it's a DNS query), **intercept it**.
   - Resolve it via the internal DNS resolver (which may use a DoH/DoT upstream, or a local DNS server, or fake-IP mapping).
   - Return the DNS response back through the stack to the original requester.

2. **Why this prevents loops:** Without interception, a DNS query (UDP to :53) entering the TUN would be forwarded through the proxy, which might need to resolve the proxy server's address via DNS → infinite loop. By intercepting port 53 inside the userspace stack, DNS never leaves the process.

3. **Implementation pattern:**
   ```go
   // In your gvisor UDP handler registration:
   // Register a custom ForwarderDialer that handles UDP
   // For DNS (dst port 53), route to internal resolver
   // For other UDP, route via proxy rules

   // Example from sing-box/mihomo approach:
   func handleUDP(ep stack.TransportEndpointID, netBuf stack.TransportBuffer, hook *stack.UDPReferenceID) {
       dstPort := tcpip.Port(hook.DstPort)
       if dstPort == 53 {
           // Parse DNS query
           // Resolve via internal resolver (DoH, DoT, or local)
           // Send response back through the stack
           return
       }
       // Forward to SOCKS5 or direct
   }
   ```

4. **fake-IP mode (sing-box/mihomo advanced feature):**
   - Instead of intercepting DNS and resolving normally, they maintain a fake-IP pool (e.g., `198.18.0.0/16`).
   - When a DNS query arrives, they return a fake IP from the pool, map it to the domain, and when a TCP connection arrives to that fake IP, they look up the domain and connect via the proxy.
   - This avoids DNS leaks entirely because the real DNS resolution happens only when the connection is established.

5. **For sscli (simpler approach):**
   - Intercept UDP port 53 inside the gvisor stack.
   - Forward to your chosen DNS server (e.g., the one provided by sslocal, or a DoH server).
   - Optionally maintain a domain→IP mapping table for rule-based routing.
   - This is simpler than fake-IP and sufficient for rule-based routing.

### DNS Leak Prevention Checklist

- ✅ Intercept ALL UDP port 53 traffic inside the userspace stack
- ✅ Never let DNS queries exit via the TUN
- ✅ Use your own DNS resolver (DoH recommended for security)
- ✅ For SOCKS5 flows, let the proxy resolve DNS (send domain names via SOCKS5 ATYP=domain)
- ✅ For direct flows, resolve DNS locally before connecting

---

## 6. WSL2 TUN Device Support

### Status

**Yes, `/dev/net/tun` is functional in WSL2 (microsoft-standard-WSL2 kernel).**

Key findings:

1. **`/dev/net/tun` works** in modern WSL2 kernels (5.x+). The WSL2 kernel includes the TUN/TAP driver (`CONFIG_TUN=m` or `=y`).

2. **Known issues:**
   - **[clash-verge-rev#516](https://github.com/clash-verge-rev/clash-verge-rev/issues/516):** Reports of TUN mode causing network hangs in WSL2 after prolonged use. Workaround: restart the TUN interface periodically. This appears to be a routing/iptables interaction issue, not a TUN driver issue.
   - **DNS resolution** in WSL2 can be tricky because WSL2 has its own DNS resolver (generated by the Windows host). TUN mode must handle this carefully.

3. **`wireguard/tun` works in WSL2:** The `golang.zx2c4.com/wireguard/tun` package uses `ioctl` to create TUN devices via `/dev/net/tun`, which works in WSL2.

4. **Kernel module:** The WSL2 kernel (microsoft-standard-WSL2) includes tun support. You can verify:
   ```bash
   ls /dev/net/tun          # Should exist
   lsmod | grep tun          # Should show tun module
   cat /proc/modules | grep tun
   ```

5. **Limitations:**
   - WSL2 networking is NAT-based by default. TUN mode works but routing can be complex.
   - `CAP_NET_ADMIN` is available in WSL2 (you run as root or use sudo).
   - Some users report issues with specific TUN setups conflicting with WSL2's own networking. Test thoroughly.

---

## Recommended Dependency List

| Module | Version | Purpose | License |
|--------|---------|---------|---------|
| `golang.zx2c4.com/wireguard/tun` | pseudo-version (latest) | TUN device creation | MIT |
| `gvisor.dev/gvisor` | pseudo-version (latest commit) | Userspace TCP/IP stack | Apache 2.0 |
| `golang.org/x/net` | v0.33.0 | SOCKS5 proxy client | BSD-3-Clause |
| `golang.org/x/sys` | v0.28.0 | SO_MARK, socket options | BSD-3-Clause |
| `golang.org/x/sync` | v0.10.0 | errgroup, semaphore | BSD-3-Clause |

**No copyleft contamination.** All selected dependencies are permissive (MIT, Apache 2.0, BSD).

### go.mod

```go
module github.com/youruser/sscli

go 1.26

require (
    golang.zx2c4.com/wireguard/tun    v0.0.0-202XXXXXXX  // latest pseudo-version
    gvisor.dev/gvisor                   v0.0.0-20250619XXXXXXXX  // pin recent commit
    golang.org/x/net                    v0.33.0
    golang.org/x/sys                    v0.28.0
    golang.org/x/sync                   v0.10.0
)
```

---

## Key Implementation Snippets Summary

### Full TUN → gvisor → Handler Pipeline

```go
package main

import (
    "context"
    "encoding/binary"
    "log"
    "net"
    "sync"
    "syscall"
    "time"

    "golang.org/x/net/proxy"
    "golang.org/x/sys/unix"
    "gvisor.dev/gvisor/pkg/tcpip"
    "gvisor.dev/gvisor/pkg/tcpip/link/channel"
    "gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
    "gvisor.dev/gvisor/pkg/tcpip/stack"
    "gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
    "gvisor.dev/gvisor/pkg/tcpip/transport/udp"
    "gvisor.dev/gvisor/pkg/waiter"
    "golang.zx2c4.com/wireguard/tun"
)

const (
    TUNName    = "sscli0"
    MTU        = 1500
    SOCKS5Addr = "127.0.0.1:1080"
    FwMark     = 0x100
    DNSPort    = 53
)

func main() {
    // 1. Create TUN device
    tunDev, err := tun.CreateTUN(TUNName, MTU)
    if err != nil {
        log.Fatalf("creating TUN: %v", err)
    }
    defer tunDev.Close()

    // 2. Create gvisor stack
    s := stack.New(stack.Options{
        TransportProtocols: []stack.TransportProtocolFactory{
            tcp.NewProtocol,
            udp.NewProtocol,
        },
    })

    // 3. Create channel endpoint (link layer)
    ep := channel.New(256, MTU, tcpip.FullHardwareAddress{})

    // 4. Attach NIC
    if err := s.CreateNIC(1, ep); err != nil {
        log.Fatalf("creating NIC: %v", err)
    }

    // 5. Set default route
    s.SetRouteTable([]tcpip.Route{{
        Destination: tcpip.MustParseAddress("0.0.0.0/0"),
        NIC:         1,
    }})

    // 6. Register TCP handler
    fwd := tcp.NewForwarder(s, 0, 10, func(r *tcp.ForwarderRequest) {
        go handleTCPForward(r)
    })
    s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)

    // 7. Register UDP handler (DNS interception)
    udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
        go handleUDPForward(r)
    })
    s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

    // 8. Bridge: TUN → gvisor channel
    go tunToChannel(tunDev, ep)

    // 9. Bridge: gvisor channel → TUN
    go channelToTUN(ep, tunDev)

    // Keep running
    select {}
}

func handleTCPForward(r *tcp.ForwarderRequest) {
    wq := &waiter.Queue{}
    ep, err := r.CreateEndpoint(wq)
    if err != nil {
        r.Complete(false)
        return
    }
    r.Complete(true)

    // Determine target from the endpoint
    // (In real code, get the original destination from the TCP state)
    targetAddr := getOriginalDst(ep) // your implementation

    // Check domain→IP map for rule-based routing
    domain := lookupDomain(targetAddr) // your implementation

    if shouldRouteViaProxy(domain) {
        // SOCKS5 route
        conn, err := dialViaSocks5(SOCKS5Addr, targetAddr, "", "")
        if err != nil {
            ep.Close()
            return
        }
        bridgeEndpoints(ep, wq, conn)
    } else {
        // Direct route with SO_MARK
        conn, err := dialWithMark(targetAddr)
        if err != nil {
            ep.Close()
            return
        }
        bridgeEndpoints(ep, wq, conn)
    }
}

func handleUDPForward(r *udp.ForwarderRequest) {
    // Get destination port
    // If port 53 → internal DNS resolver
    // Otherwise → SOCKS5 or direct
    // (Implementation depends on your DNS strategy)
}

func dialViaSocks5(socksAddr, target, user, pass string) (net.Conn, error) {
    var auth *proxy.Auth
    if user != "" {
        auth = &proxy.Auth{User: user, Password: pass}
    }
    dialer, err := proxy.SOCKS5("tcp", socksAddr, auth, proxy.Direct)
    if err != nil {
        return nil, err
    }
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    return dialer.(interface {
        DialContext(context.Context, string, string) (net.Conn, error)
    }).DialContext(ctx, "tcp", target)
}

func dialWithMark(addr string) (net.Conn, error) {
    dialer := &net.Dialer{
        Control: func(network, address string, c syscall.RawConn) error {
            return c.Control(func(fd uintptr) {
                unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(FwMark))
            })
        },
        Timeout: 10 * time.Second,
    }
    return dialer.DialContext(context.Background(), "tcp", addr)
}
```

---

## Cited URLs

- gVisor netstack: https://pkg.go.dev/gvisor.dev/gvisor/pkg/tcpip/link/channel
- gVisor stack: https://pkg.go.dev/gvisor.dev/gvisor/pkg/tcpip/stack
- gVisor GitHub: https://github.com/google/gvisor
- wireguard/tun: https://pkg.go.dev/golang.zx2c4.com/wireguard/tun
- x/net/proxy: https://pkg.go.dev/golang.org/x/net/proxy
- x/net/proxy SOCKS5: https://godocs.io/golang.org/x/net/proxy
- sing-tun (GPLv3, avoid): https://pkg.go.dev/github.com/sagernet/sing-tun
- sing-tun license: https://pkg.go.dev/github.com/sagernet/sing-tun@v0.1.11?tab=licenses
- sing-box TUN architecture: https://deepwiki.com/SagerNet/sing-box/4.1-tun-interface-and-transparent-proxying
- mihomo TUN support: https://deepwiki.com/8003901/mihomo/4.3-tun-support
- mihomo TUN interface: https://deepwiki.com/muink/mihomo/5.3-tun-interface
- tun2socks GitHub: https://github.com/xjasonlyu/tun2socks
- tun2socks stack.go: http://git.zishuo.net/package/tun2socks/src/commit/b5f61c099939babc1988cc1d3737fe4965555d06/core/stack.go
- ContextDialer in x/net/proxy: https://github.com/golang/go/issues/58376
- SO_MARK / Control func: https://github.com/aporeto-inc/trireme-lib/blob/v10.248.11/controller/internal/enforcer/applicationproxy/markedconn/markedconn.go#L135
- WSL2 TUN issues: https://github.com/clash-verge-rev/clash-verge-rev/issues/516
- gvisor networking guide: https://gvisor.dev/docs/architecture_guide/networking/
- channel.Endpoint: https://godocs.io/gvisor.dev/gvisor/pkg/tcpip/link/channel
- noisysockets/netstack (gvisor fork): https://github.com/noisysockets/netstack

---

## Summary of Recommendations

1. **Use `gvisor.dev/gvisor` directly** — Apache 2.0, well-documented, no copyleft. Don't import sing-tun or sing-box as libraries.
2. **Use `golang.zx2c4.com/wireguard/tun`** for TUN device creation — MIT, battle-tested, works on Linux and WSL2.
3. **Use `golang.org/x/net/proxy`** for SOCKS5 client — standard, supports ATYP=domain, ContextDialer available.
4. **Use `golang.org/x/sys/unix`** for SO_MARK — set via `net.Dialer{Control: ...}`, requires `CAP_NET_ADMIN`.
5. **DNS interception:** Intercept UDP port 53 inside the gvisor stack's UDP transport handler. Keep it simple — resolve via DoH or your preferred DNS. Maintain a domain→IP map for rule-based routing.
6. **WSL2:** TUN works, test routing carefully. Ensure `ip rule` setup doesn't conflict with WSL2's own networking.
