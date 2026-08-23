package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// serveRule serves content as a rule list at any path.
func serveRule(content string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(content))
	}))
}

const goodDomains = "# comment\nserver=/baidu.cn/114.114.114.114\n"

func TestUpdateOneTOFUAcceptsFirstThenPins(t *testing.T) {
	srv := serveRule(goodDomains)
	defer srv.Close()
	c := &Client{HTTP: srv.Client()}
	dest := filepath.Join(t.TempDir(), "china-domains.list")

	// First update: accepted and hash recorded.
	r := c.updateOne(context.Background(), srv.URL, dest)
	if !r.OK || r.Err != nil {
		t.Fatalf("first update = %+v, want OK", r)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Fatalf("rule file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), hashStateName)); err != nil {
		t.Fatalf("hash state missing: %v", err)
	}

	// Identical content: accepted again.
	r = c.updateOne(context.Background(), srv.URL, dest)
	if !r.OK || r.Err != nil {
		t.Fatalf("repeat update = %+v, want OK", r)
	}
}

func TestUpdateOneWarnsOnChangedContent(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "china-domains.list")

	srv := serveRule(goodDomains)
	defer srv.Close()
	c := &Client{HTTP: srv.Client()}
	if r := c.updateOne(context.Background(), srv.URL, dest); !r.OK {
		t.Fatalf("first update failed: %+v", r)
	}

	// Feed now serves different content (e.g. a tampered mirror): the
	// file IS replaced (rule lists legitimately rotate), but the drift
	// must be reported as a warning.
	srvT := serveRule("server=/evil.cn/6.6.6.6\n")
	defer srvT.Close()
	r := c.updateOne(context.Background(), srvT.URL, dest)
	if !r.OK {
		t.Fatalf("changed content must still update (warn-only TOFU): %+v", r)
	}
	if r.Warn == "" {
		t.Fatal("expected a drift warning")
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "server=/evil.cn/6.6.6.6\n" {
		t.Errorf("rule file not replaced: %q", data)
	}
	// The new hash is now the baseline: the next identical update is
	// quiet again.
	r = c.updateOne(context.Background(), srvT.URL, dest)
	if !r.OK || r.Warn != "" {
		t.Errorf("repeat update = %+v, want OK without warning", r)
	}
}

func TestUpdateOneIgnoresFailedFetchBeforeHash(t *testing.T) {
	c := &Client{HTTP: &http.Client{}}
	dest := filepath.Join(t.TempDir(), "china-domains.list")
	r := c.updateOne(context.Background(), "http://127.0.0.1:1/none", dest)
	if r.OK {
		t.Fatal("unreachable feed must fail")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), hashStateName)); err == nil {
		t.Fatal("hash state must not be written when the fetch failed")
	}
}