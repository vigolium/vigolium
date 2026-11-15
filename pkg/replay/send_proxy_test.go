package replay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"

	"github.com/vigolium/vigolium/pkg/http/proxyenv"
	"github.com/vigolium/vigolium/pkg/proxytarget/proxytest"
)

// proxyHit is what a forward proxy saw: the request target it was asked to
// fetch (absolute-form for plain HTTP) and the Host header that came with it.
type proxyHit struct {
	requestURI string
	host       string
}

// recordingProxy starts a forward HTTP proxy that records each request and
// forwards it to the absolute URL in the request line, the way Burp routes
// plain-HTTP traffic (see proxytest). A request whose absolute-form target
// names the wrong port fails here exactly as it does behind a real proxy.
func recordingProxy(t *testing.T) (*url.URL, func() []proxyHit) {
	t.Helper()
	p := proxytest.New(t)
	return p.URL, func() []proxyHit {
		var out []proxyHit
		for _, h := range p.Hits() {
			out = append(out, proxyHit{requestURI: h.RequestTarget, host: h.Host})
		}
		return out
	}
}

// targetServer answers on a random loopback port (never 80) and echoes the
// Host header it received.
func targetServer(t *testing.T) (host string, port int, gotHost func() string) {
	t.Helper()
	var (
		mu   sync.Mutex
		seen string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = r.Host
		mu.Unlock()
		_, _ = w.Write([]byte("target-ok"))
	}))
	t.Cleanup(srv.Close)
	host, port = splitAddr(t, srv.Listener.Addr().String())
	if port == 80 {
		t.Skip("test server landed on port 80; the regression needs a non-default port")
	}
	return host, port, func() string {
		mu.Lock()
		defer mu.Unlock()
		return seen
	}
}

func proxiedClient(t *testing.T, proxy *url.URL) *http.Client {
	t.Helper()
	return NewClient(nil, 0, proxyenv.Resolve(proxy.String(), func(string) string { return "" }))
}

// TestSendRawThroughHTTPProxyKeepsPort pins the regression: the send path set
// the Host to the bare hostname, and net/http writes the absolute-form request
// target for an HTTP proxy from the Host, so a target on 127.0.0.1:<port>
// reached the proxy as "GET http://127.0.0.1/x" and was forwarded to port 80.
func TestSendRawThroughHTTPProxyKeepsPort(t *testing.T) {
	host, port, gotHost := targetServer(t)
	proxy, hits := recordingProxy(t)
	authority := host + ":" + strconv.Itoa(port)

	raw := "GET /x?q=1 HTTP/1.1\r\nHost: " + authority + "\r\n\r\n"
	sum := SendRaw(context.Background(), proxiedClient(t, proxy), []byte(raw), "http", host, port, true, 0)
	if sum.Error != "" {
		t.Fatalf("send failed: %s", sum.Error)
	}
	if sum.Status != http.StatusOK || string(sum.RawBody) != "target-ok" {
		t.Fatalf("request did not reach the target through the proxy: status=%d body=%q", sum.Status, sum.RawBody)
	}

	got := hits()
	if len(got) != 1 {
		t.Fatalf("proxy saw %d requests, want 1", len(got))
	}
	if want := "http://" + authority + "/x?q=1"; got[0].requestURI != want {
		t.Errorf("proxy request target = %q, want %q", got[0].requestURI, want)
	}
	if got[0].host != authority {
		t.Errorf("proxy Host = %q, want %q", got[0].host, authority)
	}
	if gotHost() != authority {
		t.Errorf("target Host = %q, want %q", gotHost(), authority)
	}
}

// TestSendRawHostOverrideThroughHTTPProxy covers a deliberate Host override
// (a fuzzed Host header, a replay retargeted with --target). The Host header
// must reach the target unchanged while the proxy is still told to fetch the
// real host:port; net/http alone would route the request to the override.
func TestSendRawHostOverrideThroughHTTPProxy(t *testing.T) {
	host, port, gotHost := targetServer(t)
	proxy, hits := recordingProxy(t)
	authority := host + ":" + strconv.Itoa(port)

	raw := "GET /admin HTTP/1.1\r\nHost: internal.vhost.test\r\n\r\n"
	sum := SendRaw(context.Background(), proxiedClient(t, proxy), []byte(raw), "http", host, port, true, 0)
	if sum.Error != "" || sum.Status != http.StatusOK {
		t.Fatalf("send failed: status=%d err=%s", sum.Status, sum.Error)
	}
	got := hits()
	if len(got) != 1 {
		t.Fatalf("proxy saw %d requests, want 1", len(got))
	}
	if want := "http://" + authority + "/admin"; got[0].requestURI != want {
		t.Errorf("proxy request target = %q, want %q", got[0].requestURI, want)
	}
	if got[0].host != "internal.vhost.test" {
		t.Errorf("proxy Host = %q, want the override", got[0].host)
	}
	if gotHost() != "internal.vhost.test" {
		t.Errorf("target Host = %q, want the override", gotHost())
	}
}

// TestSendRawDefaultPortThroughHTTPProxy pins default-port handling on the wire:
// http on 80 names no port in the proxy request target (as before), and any
// other port is named. The destination need not exist; only what the proxy
// was asked for matters.
func TestSendRawDefaultPortThroughHTTPProxy(t *testing.T) {
	proxy, hits := recordingProxy(t)
	client := proxiedClient(t, proxy)

	cases := []struct {
		port       int
		wantTarget string
		wantHost   string
	}{
		{80, "http://default-port.invalid/x", "default-port.invalid"},
		{0, "http://default-port.invalid/x", "default-port.invalid"},
		{443, "http://default-port.invalid:443/x", "default-port.invalid:443"},
		{8080, "http://default-port.invalid:8080/x", "default-port.invalid:8080"},
	}
	for _, tc := range cases {
		before := len(hits())
		// No Host header: the destination authority is sent as the Host.
		_ = SendRaw(context.Background(), client, []byte("GET /x HTTP/1.0\r\n\r\n"), "http", "default-port.invalid", tc.port, true, 0)
		got := hits()[before:]
		if len(got) != 1 {
			t.Fatalf("port %d: proxy saw %d requests, want 1", tc.port, len(got))
		}
		if got[0].requestURI != tc.wantTarget || got[0].host != tc.wantHost {
			t.Errorf("port %d: proxy saw target %q Host %q, want %q Host %q",
				tc.port, got[0].requestURI, got[0].host, tc.wantTarget, tc.wantHost)
		}
	}
}

// TestSendRawDirectHostHeader checks the direct (unproxied) path: the request
// dials the right port and the Host header is the raw request's own, or the
// target authority when the raw request carries none.
func TestSendRawDirectHostHeader(t *testing.T) {
	host, port, gotHost := targetServer(t)
	authority := host + ":" + strconv.Itoa(port)
	client := NewClient(nil, 0, proxyenv.Choice{})

	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"host header with port", "GET / HTTP/1.1\r\nHost: " + authority + "\r\n\r\n", authority},
		{"overridden host header", "GET / HTTP/1.1\r\nHost: vhost.test\r\n\r\n", "vhost.test"},
		{"no host header", "GET / HTTP/1.0\r\n\r\n", authority},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sum := SendRaw(context.Background(), client, []byte(tc.raw), "http", host, port, true, 0)
			if sum.Error != "" || sum.Status != http.StatusOK {
				t.Fatalf("send failed: status=%d err=%s", sum.Status, sum.Error)
			}
			if gotHost() != tc.want {
				t.Errorf("target Host = %q, want %q", gotHost(), tc.want)
			}
		})
	}
}

func TestAuthority(t *testing.T) {
	cases := []struct {
		scheme, host string
		port         int
		want         string
	}{
		{"http", "example.com", 80, "example.com"},
		{"https", "example.com", 443, "example.com"},
		{"http", "example.com", 443, "example.com:443"},
		{"https", "example.com", 80, "example.com:80"},
		{"http", "127.0.0.1", 13313, "127.0.0.1:13313"},
		{"", "example.com", 80, "example.com"},
		{"http", "example.com", 0, "example.com"},
		{"http", "::1", 8080, "[::1]:8080"},
		{"http", "::1", 80, "[::1]"},
		{"https", "[::1]", 443, "[::1]"},
	}
	for _, tc := range cases {
		if got := Authority(tc.scheme, tc.host, tc.port); got != tc.want {
			t.Errorf("Authority(%q, %q, %d) = %q, want %q", tc.scheme, tc.host, tc.port, got, tc.want)
		}
	}
}
