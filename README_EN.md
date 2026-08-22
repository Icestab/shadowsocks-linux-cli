# sscli — Native Linux CLI Shadowsocks Routing Client

[中文文档](README.md) | English

A lightweight, native-Linux, GUI-free Shadowsocks routing client. It takes over all system traffic through a TUN device and routes it DIRECT or through Shadowsocks based on GFW List, China domain/IP lists, and LAN rules — applications need **no proxy environment variables** at all: `curl`, `git`, `npm` just work.

```text
Linux/WSL application traffic
      │
      ▼
  TUN device sscli0 (198.18.0.1/15)
      │
      ▼
sscli userspace network stack (gvisor netstack)
      │
      ├─ DIRECT ──→ native egress (socket marked with fwmark 0x162 escapes TUN)
      │
      └─ PROXY ───→ SOCKS5 127.0.0.1:1080 → sslocal → VPS
```

The Shadowsocks protocol itself is **not re-implemented**: sscli manages the official prebuilt `sslocal` binary from [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust) as a supervised subprocess.

## Features

- **Three modes**: `gfw` (default, proxy only GFW-listed targets), `bypass` (proxy everything except China), `global` (proxy everything except LAN)
- **TUN takeover** via gvisor netstack — the same userspace TCP/IP stack used by sing-box/mihomo
- **Loop prevention**, three layers: fwmark on sscli's own sockets, 14 private-range policy exemptions, and a /32 host route for the VPS through the original gateway (covers the unmarked sslocal child process)
- **Split DNS**: domestic upstreams carry the fwmark escape; foreign queries are exchanged over TCP inside the proxy tunnel so plaintext DNS never leaves the machine. A TTL-aware domain→IP mapping enables domain rules on IP connections.
- **Rule engine**: exact/suffix domain hashing + CIDR radix trie; six-level priority; 95k+ entries match in microseconds
- **Crash-safe networking**: SIGINT/SIGTERM/SIGHUP restore TUN/routes/rules; `sscli stop` sweeps leftovers idempotently after a crash
- **IPv6 leak protection**: v6 is blocked by default until full support lands

## Installation

### Option 1: one-liner (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/Icestab/shadowsocks-linux-cli/master/scripts/install-remote.sh | bash
```

Resolves the latest release, verifies the checksum and installs everything.
Env overrides: `SS_VERSION=v0.1.1`, `PREFIX=~/.local`.

### Option 2: prebuilt release package

Grab `sscli-v<version>-linux-<arch>.tar.xz` (+ `.sha256`) from [Releases](https://github.com/Icestab/shadowsocks-linux-cli/releases). Packages are offline-complete: they bundle the sscli binary, the official sslocal binary, and a rule-file baseline captured at build time.

```bash
echo "<official-sha256>  sscli-v0.1.1-linux-x86_64.tar.xz" | sha256sum -c -   # optional
tar xJf sscli-v0.1.1-linux-x86_64.tar.xz && cd sscli-v0.1.1-linux-x86_64
sudo ./install.sh     # offline deployment, then refreshes rules online automatically
```

### Option 3: build from source

```bash
./scripts/install.sh          # builds and installs to /usr/local/bin
```

Then edit the server section:

```bash
sudo vim /etc/sscli/config.yaml    # server address / port / method / password
sudo sscli start
```

Minimal config:

```yaml
mode: gfw            # gfw | bypass | global

server:
  address: your.server.com
  port: 443
  method: aes-256-gcm
  password: "your-password"

tun:
  name: sscli0
  mtu: 1500

sslocal:
  binary_path: /usr/local/bin/sslocal
```

## Usage

```bash
sudo sscli start              # requires root/CAP_NET_ADMIN (TUN + policy routing)
sscli status                  # runtime status (server address masked)
sscli mode bypass             # switch mode (takes effect after restart)
sscli route github.com baidu.com   # inspect routing decisions
sscli dns google.com          # test resolution + routing path
sscli test                    # self-check (privileges/TUN/DNS/SS chain/rules)
sscli update                  # refresh GFW List / China domain / China IP rules
sudo sscli stop               # stop and restore the network
```

Only `start`/`stop`/`restart` need root; every other command runs unprivileged.

## Rule priority

```text
1. Private/LAN        (reserved, always DIRECT)
2. User-defined rules
3. China domains      (gfw/bypass only)
4. China IPs          (gfw/bypass only)
5. GFW List
6. Mode default       DIRECT (gfw) | PROXY (bypass/global)
```

## Known limitations

- Non-53 UDP is not forwarded yet (dropped); HTTP/3 sites fall back to HTTP/2
- Full IPv6 proxying pending; v6 is blocked by default to prevent leaks
- WSL2 mirrored networking mode may conflict with policy routing; use NAT mode
- No Fake-IP/DoH/DoT yet (interfaces reserved)

See [docs/testing.md](docs/testing.md) (Chinese) for the full test guide.

## License

MIT. Third-party components: gvisor (Apache-2.0), wireguard/tun (MIT), miekg/dns (BSD-3), x/net (BSD-3); shadowsocks-rust used as an external MIT-licensed binary.
