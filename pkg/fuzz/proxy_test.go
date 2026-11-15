package fuzz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/http/proxyenv"
	"github.com/vigolium/vigolium/pkg/proxytarget/proxytest"
	"github.com/vigolium/vigolium/pkg/replay"
)

// fuzzTarget is a target on a random loopback port (never 80) that records the
// path and Host of every request.
func fuzzTarget(t *testing.T) (host string, port int, seen func() []string) {
	t.Helper()
	var (
		mu   sync.Mutex
		hits []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.Host+" "+r.URL.Path)
		mu.Unlock()
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	host, port = hostPort(t, srv.URL)
	return host, port, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := append([]string(nil), hits...)
		sort.Strings(out)
		return out
	}
}

func runThroughProxy(t *testing.T, raw []byte, host string, port int, payloads []string, proxy *proxytest.Proxy) {
	t.Helper()
	client := replay.NewClient(nil, 5*time.Second, proxyenv.Resolve(proxy.URL.String(), func(string) string { return "" }))
	positions, err := ResolvePositions(raw, Selectors{})
	if err != nil {
		t.Fatalf("ResolvePositions: %v", err)
	}
	report, err := Run(context.Background(), Job{
		Raw: raw, Scheme: "http", Hostname: host, Port: port,
		Positions: positions, Payloads: payloads,
		Client: client, NoRedirects: true, Concurrency: 1,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.Sent != len(payloads) {
		t.Fatalf("Sent = %d, want %d", report.Sent, len(payloads))
	}
}

// TestFuzzPathThroughHTTPProxyKeepsPort is the reported case:
// `vigolium fuzz http://127.0.0.1:<port>/FUZZ` with an HTTP proxy configured.
// Every send (baseline and payloads) must reach the proxy as
// http://127.0.0.1:<port>/…, not http://127.0.0.1/… (port 80).
func TestFuzzPathThroughHTTPProxyKeepsPort(t *testing.T) {
	host, port, seen := fuzzTarget(t)
	proxy := proxytest.New(t)
	authority := host + ":" + strconv.Itoa(port)

	raw := []byte("GET /FUZZ HTTP/1.1\r\nHost: " + authority + "\r\n\r\n")
	runThroughProxy(t, raw, host, port, []string{"admin", "backup"}, proxy)

	hits := proxy.Hits()
	if len(hits) == 0 {
		t.Fatal("nothing went through the proxy")
	}
	for _, h := range hits {
		if !strings.HasPrefix(h.RequestTarget, "http://"+authority+"/") {
			t.Errorf("proxy request target %q does not name %s", h.RequestTarget, authority)
		}
		if h.Host != authority {
			t.Errorf("proxy Host = %q, want %q", h.Host, authority)
		}
	}
	got := seen()
	for _, want := range []string{authority + " /admin", authority + " /backup"} {
		if !slices.Contains(got, want) {
			t.Errorf("target never saw %q; saw %v", want, got)
		}
	}
}

// TestFuzzHostHeaderThroughHTTPProxy: a fuzzed Host header is the payload, so
// it must reach the target, while the proxy is still asked for the real
// host:port. The send path used to overwrite the Host with the bare hostname,
// which both dropped the port and erased the payload.
func TestFuzzHostHeaderThroughHTTPProxy(t *testing.T) {
	host, port, seen := fuzzTarget(t)
	proxy := proxytest.New(t)
	authority := host + ":" + strconv.Itoa(port)

	raw := []byte("GET /vh HTTP/1.1\r\nHost: FUZZ.example\r\n\r\n")
	runThroughProxy(t, raw, host, port, []string{"admin", "intranet"}, proxy)

	for _, h := range proxy.Hits() {
		if h.RequestTarget != "http://"+authority+"/vh" {
			t.Errorf("proxy request target = %q, want http://%s/vh", h.RequestTarget, authority)
		}
	}
	got := seen()
	for _, want := range []string{"admin.example /vh", "intranet.example /vh"} {
		if !slices.Contains(got, want) {
			t.Errorf("target never saw Host payload %q; saw %v", want, got)
		}
	}
}
