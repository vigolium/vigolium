package portsweep

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

// portOf extracts the numeric port from an httptest server URL.
func portOf(t *testing.T, rawURL string) int {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("port of %q: %v", rawURL, err)
	}
	return p
}

// fastOpts returns Options with short timeouts so tests don't stall on the
// non-HTTP / closed-port paths.
func fastOpts(ports []int) Options {
	return Options{
		Ports:         ports,
		Concurrency:   16,
		DialTimeout:   500 * time.Millisecond,
		HTTPTimeout:   500 * time.Millisecond,
		HoneypotRatio: 0.7,
	}
}

func TestSweep_DistinctServicesConfirmed(t *testing.T) {
	// Two real HTTP services with different bodies → both confirmed, not honeypot.
	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "alpha")
		_, _ = fmt.Fprint(w, "service one")
	}))
	defer s1.Close()
	s2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "beta")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, "service two is different")
	}))
	defer s2.Close()

	p1, p2 := portOf(t, s1.URL), portOf(t, s2.URL)
	res := Sweep(context.Background(), "127.0.0.1", fastOpts([]int{p1, p2}))

	if res.Honeypot {
		t.Fatalf("distinct services flagged as honeypot: %+v", res)
	}
	if len(res.Open) != 2 {
		t.Fatalf("want 2 confirmed ports, got %d: %+v", len(res.Open), res.Open)
	}
	// A 403 still counts as a confirmed web server.
	var saw403 bool
	for _, pr := range res.Open {
		if pr.Status == http.StatusForbidden {
			saw403 = true
		}
		if pr.Scheme != "http" {
			t.Errorf("port %d: want scheme http, got %q", pr.Port, pr.Scheme)
		}
	}
	if !saw403 {
		t.Errorf("expected the 403 service to be confirmed: %+v", res.Open)
	}
}

func TestSweep_HoneypotIdenticalBanner(t *testing.T) {
	// Four ports all returning the same body+status → honeypot, all discarded.
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "tarpit")
		_, _ = fmt.Fprint(w, "the same page everywhere")
	})
	var ports []int
	for i := 0; i < 4; i++ {
		s := httptest.NewServer(handler)
		defer s.Close()
		ports = append(ports, portOf(t, s.URL))
	}

	res := Sweep(context.Background(), "127.0.0.1", fastOpts(ports))
	if !res.Honeypot {
		t.Fatalf("identical-banner host not flagged as honeypot: %+v", res)
	}
	if len(res.Open) != 0 {
		t.Fatalf("honeypot should discard all ports, got %d: %+v", len(res.Open), res.Open)
	}
	if res.TCPOpen != 4 {
		t.Errorf("want TCPOpen=4, got %d", res.TCPOpen)
	}
}

func TestSweep_NonHTTPPortDropped(t *testing.T) {
	// A raw TCP listener that accepts then immediately closes is TCP-open but
	// never speaks HTTP → it must not be confirmed.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	res := Sweep(context.Background(), "127.0.0.1", fastOpts([]int{port}))

	if len(res.Open) != 0 {
		t.Fatalf("non-HTTP port confirmed: %+v", res.Open)
	}
	if res.TCPOpen != 1 {
		t.Errorf("want TCPOpen=1 (port accepted a connection), got %d", res.TCPOpen)
	}
}

func TestSweep_ClosedPortNotReported(t *testing.T) {
	// Bind then release a port so it is (very likely) closed during the sweep.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	res := Sweep(context.Background(), "127.0.0.1", fastOpts([]int{port}))
	if len(res.Open) != 0 {
		t.Fatalf("closed port reported as open: %+v", res.Open)
	}
	if res.Probed != 1 {
		t.Errorf("want Probed=1, got %d", res.Probed)
	}
}

func TestSweep_EmptyInputs(t *testing.T) {
	if got := Sweep(context.Background(), "", fastOpts([]int{8080})); len(got.Open) != 0 || got.Honeypot {
		t.Errorf("empty host should be a no-op, got %+v", got)
	}
	if got := Sweep(context.Background(), "127.0.0.1", fastOpts([]int{})); got.Probed != len(DefaultPorts) {
		t.Errorf("empty ports should fall back to DefaultPorts, got Probed=%d", got.Probed)
	}
}

func TestIsHoneypot(t *testing.T) {
	same := func(n int) []PortResult {
		out := make([]PortResult, n)
		for i := range out {
			out[i] = PortResult{Port: 8000 + i, fp: "200||deadbeef"}
		}
		return out
	}
	distinct := func(n int) []PortResult {
		out := make([]PortResult, n)
		for i := range out {
			out[i] = PortResult{Port: 8000 + i, fp: fmt.Sprintf("200||%d", i)}
		}
		return out
	}

	tests := []struct {
		name      string
		probed    int
		tcpOpen   int
		open      []PortResult
		threshold float64
		want      bool
	}{
		{"all-open identical → honeypot", 5, 5, same(5), 0.7, true},
		{"all-open distinct → not honeypot", 5, 5, distinct(5), 0.7, false},
		{"low ratio identical → not honeypot", 13, 2, same(2), 0.7, false},
		{"two identical below min-count → not honeypot", 2, 2, same(2), 0.7, false},
		{"ratio gate disabled → never honeypot", 5, 5, same(5), 0, false},
		{"mostly identical (one odd) → honeypot", 5, 5, append(same(4), PortResult{Port: 9000, fp: "x"}), 0.7, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isHoneypot(tc.probed, tc.tcpOpen, tc.open, tc.threshold); got != tc.want {
				t.Errorf("isHoneypot = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPortResultURL(t *testing.T) {
	if got := (PortResult{Port: 8443, Scheme: "https"}).URL("example.com"); got != "https://example.com:8443/" {
		t.Errorf("URL = %q", got)
	}
	// Bare IPv6 hosts must be bracketed to form a valid URL.
	if got := (PortResult{Port: 8080, Scheme: "http"}).URL("::1"); got != "http://[::1]:8080/" {
		t.Errorf("IPv6 URL = %q", got)
	}
}
