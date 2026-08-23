// Package daemon owns the sscli runtime lifecycle: start, stop, status.
package daemon

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Icestab/shadowsocks-linux-cli/internal/config"
	"github.com/Icestab/shadowsocks-linux-cli/internal/dns"
	"github.com/Icestab/shadowsocks-linux-cli/internal/logrotate"
	"github.com/Icestab/shadowsocks-linux-cli/internal/network"
	"github.com/Icestab/shadowsocks-linux-cli/internal/proxy"
	"github.com/Icestab/shadowsocks-linux-cli/internal/router"
	"github.com/Icestab/shadowsocks-linux-cli/internal/tun"
)

const (
	routingTable = 5162
	dnsListener  = "127.0.0.1:53090" // internal; TUN port-53 flows are answered in-process
)

// Runtime holds every live component of a running sscli instance.
type Runtime struct {
	cfg     *config.Config
	sslocal *proxy.Sslocal
	dev     *tun.Device
	stack   *tun.Stack
	nm      *network.Manager
	cancel  context.CancelFunc

	dnsDone <-chan struct{} // closed when the internal DNS listener exited

	forceCh chan os.Signal // second signal triggers forced exit
}

// hijackStatePath is where the DNS-hijack rule delta is recorded so stop
// (and crash recovery) removes exactly the rules we created.
func hijackStatePath() (string, error) {
	d, err := StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, network.HijackStateFileName), nil
}

// establishedStatePath is where the established-connection exemption rule
// delta is recorded (same directory as the hijack state).
func establishedStatePath() (string, error) {
	d, err := StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, network.EstablishedStateFileName), nil
}

const daemonEnv = "SSCLI_DAEMON"

// LogFile returns the path of the daemon log (StateDir/sscli.log).
func LogFile() (string, error) {
	d, err := StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "sscli.log"), nil
}

// Start launches the full pipeline. Default behavior is to daemonize:
// re-exec self in a new session, wait until it is up, then return so the
// terminal stays usable. Pass foreground=true (sscli start --foreground)
// to run attached instead. Requires root/CAP_NET_ADMIN either way.
func Start(loadCfg func() (*config.Config, error), foreground bool) error {
	cfg, err := loadCfg()
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("sscli start requires root (sudo) for TUN and routing management")
	}
	if running, pid := isRunning(); running {
		return fmt.Errorf("sscli already running (pid %d)", pid)
	}

	if !foreground && os.Getenv(daemonEnv) != "1" {
		return daemonize()
	}

	rt, err := boot(cfg)
	if err != nil {
		// Anything partially started must be torn down before we exit:
		// never leave the machine without a working network (安全第一).
		shutdown(rt)
		return err
	}

	pid, err := writePid()
	if err != nil {
		shutdown(rt)
		return err
	}
	fmt.Printf("sscli daemon ready (pid %d), mode=%s tun=%s\n", pid, cfg.Mode, cfg.TUN.Name)

	waitForSignalOrChildExit(rt)
	// 第二个信号 = 用户要求强制退出：跳过优雅收尾，只做最快的网络清扫。
	if rt.forceCh != nil {
		go func() {
			<-rt.forceCh
			fmt.Println("second signal: forcing exit with fast network sweep")
			if hp, he := hijackStatePath(); he == nil {
				network.TeardownDNSHijack(hp) //nolint:errcheck
			}
			if ep, ee := establishedStatePath(); ee == nil {
				network.TeardownEstablishedExempt(ep) //nolint:errcheck
			}
			network.NewManager(cfg.TUN.Name, proxy.Fwmark, routingTable).Teardown() //nolint:errcheck
			network.DeleteLink(cfg.TUN.Name)                                        //nolint:errcheck
			removePid()
			os.Exit(1)
		}()
	}
	shutdown(rt)
	removePid()
	fmt.Println("sscli stopped, network restored.")
	return nil
}

// boot brings up all components in dependency order, returning a runtime
// even on failure so partial state can be cleaned.
func boot(cfg *config.Config) (*Runtime, error) {
	rt := &Runtime{cfg: cfg}
	ctx, cancel := context.WithCancel(context.Background())
	rt.cancel = cancel

	// 1. Resolve server address BEFORE any routing changes (system DNS is
	// still usable now; after hijack it may not be). ALL addresses are
	// pinned (a DNS round-robin server would otherwise loop: an unpinned
	// address re-enters the TUN and bypass/global mode re-decides it
	// PROXY -> back into sslocal forever).
	serverIPs, err := resolveServerIPs(cfg.Server.Address)
	if err != nil {
		return rt, fmt.Errorf("resolve server: %w", err)
	}

	// 2. Snapshot original routes for restoration checks.
	rt.nm = network.NewManager(cfg.TUN.Name, proxy.Fwmark, routingTable)
	if _, err := rt.nm.OriginalDefaultRoutes(); err != nil {
		return rt, fmt.Errorf("snapshot routes: %w", err)
	}

	// 3. Managed sslocal (Shadowsocks protocol — prebuilt binary).
	if d, err := StateDir(); err == nil {
		os.Setenv("SSCLI_SSLOCAL_LOG", filepath.Join(d, "sslocal.log"))
	}
	// Pin the resolved primary IP so sslocal never needs DNS for the VPS
	// name: once the hijack is active that resolution would route back
	// through sslocal itself and deadlock the whole data plane. sslocal's
	// config takes a single address; the remaining addresses are still
	// pinned in the router and the host routes below.
	proxy.StartIP = serverIPs[0].String()
	rt.sslocal = proxy.NewSslocal(cfg)
	if err := rt.sslocal.Start(); err != nil {
		return rt, err
	}

	// 4. TUN device + address + link up.
	dev, err := tun.Create(cfg.TUN.Name, cfg.TUN.MTU)
	if err != nil {
		return rt, err
	}
	rt.dev = dev
	if err := network.ConfigureTUN(cfg.TUN.Name, cfg.TUN.Address); err != nil {
		return rt, err
	}

	// 5. Existing-connection exemption BEFORE the routing switch: from the
	// moment the TUN lookup rule takes over, reply packets of connections
	// that pre-date sscli (an SSH session into this machine) would be
	// captured and swallowed by the gvisor forwarder (it only accepts
	// SYNs). `conntrack --ctstate ESTABLISHED,RELATED` packets get the
	// fwmark instead, keeping them on the original main-table path;
	// NEW connections (SYN, no conntrack entry yet) still enter the TUN
	// and are split-routed as before. This rule must exist before
	// nm.Setup, otherwise the window between the two leaves established
	// replies vulnerable.
	estState, esErr := establishedStatePath()
	if esErr != nil {
		return rt, fmt.Errorf("resolve established state path: %w", esErr)
	}
	if err := network.SetupEstablishedExempt(estState); err != nil {
		return rt, err
	}

	// 6. Policy routing with loop-prevention exceptions + DNS hijack
	// (redirects local :53 into our resolver so the domain->IP mapping
	// fills even when the system resolver sits on a private address).
	if err := rt.nm.Setup(serverIPs); err != nil {
		return rt, err
	}
	if cfg.DNS.Enabled {
		hijackState, hsErr := hijackStatePath()
		if hsErr != nil {
			return rt, fmt.Errorf("resolve hijack state path: %w", hsErr)
		}
		if err := network.SetupDNSHijack(hijackState); err != nil {
			return rt, err
		}
	}

	// 7. Rules engine from config + rule files.
	engine, err := router.LoadEngine(cfg)
	if err != nil {
		return rt, err
	}

	// 8. DNS layer and router. Foreign upstream queries go through the
	// SOCKS5 endpoint so plaintext DNS never leaves the machine directly;
	// domestic queries escape the TUN via the fwmark (set in NewResolver).
	mapping := dns.NewMapping(time.Duration(cfg.DNS.CacheTTL)*time.Second, time.Hour)
	resolver := dns.NewResolver(nil, nil, engine.ChinaDomains(), mapping)

	pd := proxy.NewProxyDialer(cfg)
	resolver.SetProxyDial(pd.DialContext)
	dnsSrv := dns.NewServer(resolver, engine)

	dd := &proxy.DirectDialer{}
	r := router.New(engine, mapping, pd, dd, serverIPs...)

	// 9. gvisor userspace stack bridging the TUN into the router.
	st, err := tun.NewStack(rt.dev, router.NewFlowAdapter(r, dnsSrv))
	if err != nil {
		return rt, err
	}
	rt.stack = st

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := dnsSrv.ListenAndServe(ctx, dnsListener); err != nil && ctx.Err() == nil {
			fmt.Printf("warning: dns listener: %v\n", err)
		}
	}()
	rt.dnsDone = done
	return rt, nil
}

// Stop terminates a running instance by PID signal; the child performs its
// own cleanup. Falls back to a best-effort sweep of stale network state.
func Stop() error {
	running, pid := isRunning()
	if !running {
		// Sweep leftovers from a crashed previous run (idempotent).
		hijackState, _ := hijackStatePath()
		network.TeardownDNSHijack(hijackState) //nolint:errcheck // best-effort sweep
		estState, _ := establishedStatePath()
		network.TeardownEstablishedExempt(estState) //nolint:errcheck // best-effort sweep
		nm := network.NewManager(defaultTunName(), proxy.Fwmark, routingTable)
		err := nm.Teardown()
		network.DeleteLink(defaultTunName()) //nolint:errcheck // may not exist
		if err != nil {
			return err
		}
		return ErrNotRunning
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := p.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	// 等待优雅退出；超时则 SIGKILL 并由本进程接管网络清扫
	// （被 kill 的子进程无法清理自己的 iptables/路由）。
	for i := 0; i < 100; i++ {
		time.Sleep(100 * time.Millisecond)
		if r, _ := isRunning(); !r {
			return nil
		}
	}
	fmt.Println("graceful stop timed out, sending SIGKILL and sweeping network state...")
	_ = p.Kill()
	for i := 0; i < 30; i++ {
		time.Sleep(100 * time.Millisecond)
		if r, _ := isRunning(); !r {
			break
		}
	}
	hijackState, hsErr := hijackStatePath()
	if hsErr == nil {
		network.TeardownDNSHijack(hijackState) //nolint:errcheck // victim cannot clean up itself
	}
	estState, esErr := establishedStatePath()
	if esErr == nil {
		network.TeardownEstablishedExempt(estState) //nolint:errcheck
	}
	nm := network.NewManager(defaultTunName(), proxy.Fwmark, routingTable)
	_ = nm.Teardown()
	network.DeleteLink(defaultTunName()) //nolint:errcheck
	return fmt.Errorf("pid %d had to be killed; network state was force-swept — please verify connectivity", pid)
}

func defaultTunName() string { return "sscli0" }

// daemonize re-executes this exact command line with SSCLI_DAEMON=1 in a
// new session, waits for the pid file, and returns. On early child death
// the last log lines are surfaced to explain why.
func daemonize() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	logPath, err := LogFile()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0o750); err != nil {
		return err
	}
	logrotate.MaybeRotate(logPath) // 每次启动轮转，防止日志无限涨盘
	logF, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logF.Close() //nolint:errcheck

	cmd := exec.Command(self, os.Args[1:]...)
	cmd.Env = append(os.Environ(), daemonEnv+"=1")
	cmd.Stdin = nil
	cmd.Stdout = logF
	cmd.Stderr = logF
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawn daemon: %w", err)
	}
	child := cmd.Process.Pid

	// 等待 pid 文件出现（子进程 boot 完成后写入）。
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(150 * time.Millisecond)
		if r, _ := isRunning(); r {
			fmt.Printf("sscli started (pid %d)\nlog: %s\n", child, logPath)
			return nil
		}
		// 子进程已退出且未留下 pid：启动失败，回显日志尾部。
		if cmd.ProcessState != nil || !processAlive(child) {
			logF.Sync()
			return fmt.Errorf("daemon exited during startup; last log lines:\n%s", tailFile(logPath, 15))
		}
	}
	return fmt.Errorf("daemon did not report startup within 20s; check %s", logPath)
}

func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}

func tailFile(path string, n int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "(no log)"
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func waitForSignalOrChildExit(rt *Runtime) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	rt.forceCh = ch
	select {
	case s := <-ch:
		fmt.Println("received signal:", s)
	case <-rt.sslocal.Done():
		fmt.Println("warning: sslocal exited unexpectedly")
	}
}

// shutdown tears everything down in reverse order; every step is best-effort
// so one failure cannot block network restoration.
func shutdown(rt *Runtime) {
	if rt == nil {
		return
	}
	// 顺序至关重要：先取消上下文并关闭 TUN 设备解除 pump 阻塞，
	// 再等 stack 收尾——否则 pump 卡在 Read 上导致整个关闭流程死锁。
	if rt.cancel != nil {
		rt.cancel()
	}
	if rt.dev != nil {
		rt.dev.Close()
	}
	if rt.stack != nil {
		rt.stack.Close()
	}
	// 要求 6：DNS 监听器必须先于规则移除关闭——等待其退出（限时）。
	if rt.dnsDone != nil {
		select {
		case <-rt.dnsDone:
		case <-time.After(2 * time.Second):
		}
	}
	hijackState, _ := hijackStatePath()
	network.TeardownDNSHijack(hijackState) //nolint:errcheck // best-effort sweep
	estState, _ := establishedStatePath()
	network.TeardownEstablishedExempt(estState) //nolint:errcheck // best-effort sweep
	if rt.nm != nil {
		_ = rt.nm.Teardown()
	} else {
		(&network.Manager{TUNName: defaultTunName(), Fwmark: proxy.Fwmark, Table: routingTable}).Teardown() //nolint:errcheck
	}
	if rt.cfg != nil {
		network.DeleteLink(rt.cfg.TUN.Name) //nolint:errcheck // may not exist
	}
	network.DeleteLink(defaultTunName()) //nolint:errcheck
	if rt.sslocal != nil {
		_ = rt.sslocal.Stop()
	}
	if rt.cancel != nil {
		rt.cancel()
	}
}

// resolveServerIPs returns every address of the SS server (literal or
// domain), IPv4 first. The first element is the primary sslocal dials; the
// full set is pinned in the router and routed around the TUN so a
// round-robin server can never feed a loop.
//
// Domain resolution happens over DoH first (privacy): the VPS name would
// otherwise hit the local/ISP resolver in plaintext once at every start.
// Only when every DoH endpoint fails do we fall back to the system
// resolver, with a warning.
func resolveServerIPs(addr string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(addr); err == nil {
		return []netip.Addr{ip}, nil
	}
	if addrs, err := resolveViaDoH(context.Background(), defaultDoHEndpoints, addr); err == nil && len(addrs) > 0 {
		return prioritizeAddrs(addrs)
	}
	fmt.Println("warning: DoH bootstrap unavailable, resolving server via system DNS (one plaintext query to your configured resolver)")
	ips, err := net.LookupIP(addr)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("no address for %q", addr)
	}
	return prioritizeIPs(ips)
}

// prioritizeIPs converts a net.LookupIP result into deduplicated netip
// addresses, ordered IPv4 first.
func prioritizeIPs(ips []net.IP) ([]netip.Addr, error) {
	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			addrs = append(addrs, a.Unmap())
		}
	}
	return prioritizeAddrs(addrs)
}

// prioritizeAddrs dedupes and orders IPv4 first.
func prioritizeAddrs(addrs []netip.Addr) ([]netip.Addr, error) {
	var v4, v6 []netip.Addr
	seen := make(map[netip.Addr]struct{})
	for _, a := range addrs {
		if !a.IsValid() || a.IsUnspecified() {
			continue
		}
		if _, dup := seen[a]; dup {
			continue
		}
		seen[a] = struct{}{}
		if a.Is4() {
			v4 = append(v4, a)
		} else {
			v6 = append(v6, a)
		}
	}
	all := append(v4, v6...)
	if len(all) == 0 {
		return nil, fmt.Errorf("server address resolved to no usable IPs")
	}
	return all, nil
}

func writePid() (int, error) {
	d, err := StateDir()
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(d, 0o750); err != nil {
		return 0, err
	}
	pid := os.Getpid()
	return pid, os.WriteFile(d+"/sscli.pid", []byte(strconv.Itoa(pid)), 0o644)
}

func removePid() {
	if d, err := StateDir(); err == nil {
		os.Remove(d + "/sscli.pid") //nolint:errcheck
	}
}

func isRunning() (bool, int) {
	d, err := StateDir()
	if err != nil {
		return false, 0
	}
	data, err := os.ReadFile(d + "/sscli.pid")
	if err != nil {
		return false, 0
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return false, 0
	}
	// Signal 0 probes liveness without delivering anything — but a pid in
	// the file can also be an UNRELATED process that reused the number
	// after a crash. Verify identity before ever signaling it.
	if p, err := os.FindProcess(pid); err == nil && p.Signal(syscall.Signal(0)) == nil && pidIsSSCLI(pid) {
		return true, pid
	}
	os.Remove(d + "/sscli.pid") //nolint:errcheck // stale (or foreign) pid
	return false, 0
}

// pidIsSSCLI reports whether pid belongs to an sscli process by comparing
// its /proc/<pid>/exe with our own executable (the daemonized child
// re-execs this very binary). Guards Stop/isRunning against signaling an
// innocent process that reused a stale pid. A replaced binary shows
// " (deleted)" on a still-running process — strip it before comparing.
func pidIsSSCLI(pid int) bool {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return false
	}
	exe = strings.TrimSuffix(exe, " (deleted)")
	self, err := os.Executable()
	if err != nil {
		return false
	}
	if filepath.Clean(exe) == filepath.Clean(self) {
		return true
	}
	// Different path but the same binary (e.g. running via a symlink):
	// compare the underlying inode as a last resort.
	return sameInode(exe, self)
}

func sameInode(a, b string) bool {
	ia, err := os.Stat(a)
	if err != nil {
		return false
	}
	ib, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ia, ib)
}
