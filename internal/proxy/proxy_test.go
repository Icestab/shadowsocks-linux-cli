package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/dy/sscli/internal/config"
)

// TestSocks5DialerThroughSSChain is an end-to-end test of the PROXY path:
//
//	local HTTP server <- sslocal (SOCKS5) <- ssserver (loopback)
//
// It requires prebuilt shadowsocks-rust binaries; skipped when absent.
func TestSocks5DialerThroughSSChain(t *testing.T) {
	binDir := filepath.Join("..", "..", ".toolchain", "ss-rust")
	sslocalBin := filepath.Join(binDir, "sslocal")
	ssserverBin := filepath.Join(binDir, "ssserver")
	if _, err := os.Stat(sslocalBin); err != nil {
		t.Skipf("sslocal not present at %s; download shadowsocks-rust to run e2e test", sslocalBin)
	}
	if _, err := os.Stat(ssserverBin); err != nil {
		t.Skip("ssserver not present")
	}

	// 1. Local origin HTTP server.
	msg := "hello through the SS tunnel"
	origin := newOriginServer(t, msg)
	defer origin.Close()

	// 2. ssserver on loopback.
	serverCfg := filepath.Join(t.TempDir(), "ssserver.json")
	if err := os.WriteFile(serverCfg, []byte(fmt.Sprintf(`{
		"server":"127.0.0.1","server_port":28388,
		"password":"test-pass","method":"aes-256-gcm"
	}`)), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := exec.Command(ssserverBin, "-c", serverCfg)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = srv.Process.Kill()
		_, _ = srv.Process.Wait()
	}()
	time.Sleep(500 * time.Millisecond)

	// 3. sslocal via our manager.
	cfg := &config.Config{}
	cfg.Defaults()
	cfg.Server = config.Server{
		Address: "127.0.0.1", Port: 28388,
		Method: "aes-256-gcm", Password: "test-pass",
	}
	cfg.Sslocal.BinaryPath = sslocalBin
	cfg.Sslocal.SocksAddr = "127.0.0.1:21080"
	mgr := NewSslocal(cfg)
	if err := mgr.Start(); err != nil {
		t.Fatalf("sslocal start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Stop() })

	// 4. Dial through the chain with our ProxyDialer.
	d := NewProxyDialer(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", origin.Listener.Addr().String())
	if err != nil {
		t.Fatalf("proxy dial: %v", err)
	}
	defer conn.Close()
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", origin.Listener.Addr())
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if want := "200 OK"; !contains(string(body), want) || !contains(string(body), msg) {
		t.Errorf("unexpected response via SS chain: %.200s", body)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

type testServer struct {
	*http.Server
	Listener net.Listener
}

func newOriginServer(t *testing.T, msg string) *testServer {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, msg)
	})
	srv := &http.Server{Handler: mux} //nolint:gosec // test server
	go func() { _ = srv.Serve(l) }()
	return &testServer{Server: srv, Listener: l}
}
