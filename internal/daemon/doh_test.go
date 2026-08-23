package daemon

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	mdns "github.com/miekg/dns"
)

// dohTestServer runs an RFC 8484-style handler: it unpacks the ?dns=
// query and answers with the given records (or the given rcode).
func dohTestServer(t *testing.T, answer []mdns.RR, rcode int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Query().Get("dns")
		if raw == "" {
			http.Error(w, "missing dns", http.StatusBadRequest)
			return
		}
		wire, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			http.Error(w, "bad dns", http.StatusBadRequest)
			return
		}
		var q mdns.Msg
		if err := q.Unpack(wire); err != nil {
			http.Error(w, "bad dns", http.StatusBadRequest)
			return
		}
		resp := new(mdns.Msg)
		if rcode != mdns.RcodeSuccess {
			resp.SetRcode(&q, rcode)
		} else {
			resp.SetReply(&q)
			resp.Answer = answer
		}
		out, err := resp.Pack()
		if err != nil {
			http.Error(w, "pack failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestResolveViaDoH(t *testing.T) {
	a := &mdns.A{
		Hdr: mdns.RR_Header{Name: "vps.example.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
		A:   net.IPv4(18, 139, 140, 0),
	}
	ep := dohTestServer(t, []mdns.RR{a}, mdns.RcodeSuccess)

	addrs, err := resolveViaDoH(context.Background(), []string{ep.URL}, "vps.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("18.139.140.0") {
		t.Errorf("resolveViaDoH = %v, want [18.139.140.0]", addrs)
	}
}

func TestResolveViaDoHFallsBackAcrossEndpoints(t *testing.T) {
	// First endpoint errors (HTTP 500), second answers.
	bad := dohTestServer(t, nil, mdns.RcodeServerFailure)
	a := &mdns.A{
		Hdr: mdns.RR_Header{Name: "vps.example.", Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: 60},
		A:   net.IPv4(203, 0, 113, 9),
	}
	good := dohTestServer(t, []mdns.RR{a}, mdns.RcodeSuccess)

	addrs, err := resolveViaDoH(context.Background(), []string{bad.URL, good.URL}, "vps.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("203.0.113.9") {
		t.Errorf("resolveViaDoH = %v, want [203.0.113.9]", addrs)
	}
}

func TestResolveViaDoHNXDOMAINIsError(t *testing.T) {
	ep := dohTestServer(t, nil, mdns.RcodeNameError)
	if _, err := resolveViaDoH(context.Background(), []string{ep.URL}, "gone.example"); err == nil {
		t.Fatal("NXDOMAIN should surface as an error, not an empty success")
	}
}