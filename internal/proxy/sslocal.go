// Package proxy manages the shadowsocks-rust sslocal subprocess and the
// outbound dialers (SOCKS5 for PROXY, fwmark-marked native dialing for DIRECT).
package proxy

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/Icestab/sscli/internal/config"
)

// Sslocal manages one sslocal child process in SOCKS5 local mode.
//
// The server password is passed via a temporary JSON config file created
// with mode 0600 — never on the command line, where it would be visible in
// /proc/<pid>/cmdline to every user on the system.
type Sslocal struct {
	mu        sync.Mutex
	cfg       *config.Config
	cmd       *exec.Cmd
	cfgFile   string
	logFile   *os.File
	stopped   bool
	done      chan struct{} // closed when the child exits after Stop
	monitorMu sync.Mutex
}

// NewSslocal creates a manager; Start launches the process.
func NewSslocal(cfg *config.Config) *Sslocal {
	return &Sslocal{cfg: cfg}
}

// sslocalConfig mirrors the JSON schema accepted by `sslocal -c`.
type sslocalConfig struct {
	LocalAddress string `json:"local_address"`
	LocalPort    int    `json:"local_port"`
	Server       string `json:"server"`
	ServerPort   int    `json:"server_port"`
	Password     string `json:"password"`
	Method       string `json:"method"`
	TimeoutSec   int    `json:"timeout,omitempty"`
	FastOpen     bool   `json:"fast_open,omitempty"`
	NoDelay      bool   `json:"no_delay"`
	TCPRelayOnly bool   `json:"-"`
}

// Start writes the temp config, spawns sslocal and waits until its SOCKS5
// port accepts connections.
func (s *Sslocal) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cmd != nil {
		return fmt.Errorf("sslocal already running")
	}
	bin := s.cfg.Sslocal.BinaryPath
	if bin == "" {
		bin = "sslocal"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return fmt.Errorf("sslocal binary not found at %q: install shadowsocks-rust or set sslocal.binary_path", s.cfg.Sslocal.SocksAddr[:0]+bin)
	}

	host, portStr, err := net.SplitHostPort(s.cfg.Sslocal.SocksAddr)
	if err != nil {
		return fmt.Errorf("invalid sslocal.socks_addr %q: %w", s.cfg.Sslocal.SocksAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid sslocal.socks_addr port: %w", err)
	}
	if host == "" {
		host = "127.0.0.1"
	}

	lc := sslocalConfig{
		LocalAddress: host,
		LocalPort:    port,
		Server:       s.cfg.Server.Address,
		ServerPort:   s.cfg.Server.Port,
		Password:     s.cfg.Server.Password,
		Method:       s.cfg.Server.Method,
		NoDelay:      true,
	}
	data, err := json.Marshal(lc)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp("", "sscli-sslocal-*.json")
	if err != nil {
		return err
	}
	s.cfgFile = tmp.Name()
	// 0600: file holds the Shadowsocks password.
	if err := os.Chmod(s.cfgFile, 0o600); err != nil {
		tmp.Close()
		s.cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		s.cleanup()
		return err
	}
	tmp.Close()

	cmd := exec.Command(bin, "-c", s.cfgFile)
	cmd.Stdout = nil
	cmd.Stderr = nil

	// Detach from this process group so Ctrl-C on interactive use doesn't
	// kill sslocal before we can clean up routes ourselves.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		s.cleanup()
		return fmt.Errorf("start sslocal: %w", err)
	}
	s.cmd = cmd
	s.stopped = false
	s.done = make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(s.done)
	}()

	// Wait for the SOCKS5 listener.
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-s.done:
			s.mu.Lock()
			err := fmt.Errorf("sslocal exited during startup")
			s.mu.Unlock()
			s.cleanupLocked()
			return err
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	s.stopLocked()
	return fmt.Errorf("sslocal SOCKS5 listener %s did not come up within 10s", addr)
}

// Running reports whether the child process is alive.
func (s *Sslocal) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cmd != nil && !s.stopped
}

// Done returns a channel closed when the child exits.
func (s *Sslocal) Done() <-chan struct{} {
	s.monitorMu.Lock()
	defer s.monitorMu.Unlock()
	return s.done
}

// Stop terminates sslocal gracefully (SIGTERM then SIGKILL) and removes
// the temp config containing the password. Safe to call twice.
func (s *Sslocal) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopLocked()
}

func (s *Sslocal) stopLocked() error {
	if s.cmd != nil && !s.stopped {
		s.stopped = true
		_ = s.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-s.done:
		case <-time.After(3 * time.Second):
			_ = s.cmd.Process.Kill()
			<-s.done
		}
	}
	s.cleanupLocked()
	return nil
}

func (s *Sslocal) cleanupLocked() {
	if s.cfgFile != "" {
		_ = os.Remove(s.cfgFile)
		s.cfgFile = ""
	}
	s.cmd = nil
}

func (s *Sslocal) cleanup() {
	if s.cfgFile != "" {
		_ = os.Remove(filepath.Clean(s.cfgFile))
		s.cfgFile = ""
	}
}
