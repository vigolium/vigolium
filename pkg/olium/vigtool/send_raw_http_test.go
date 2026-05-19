package vigtool

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
		wantTLS  bool
	}{
		{"https://app.example.com", "app.example.com", 443, true},
		{"http://app.example.com", "app.example.com", 80, false},
		{"http://app.example.com:8080", "app.example.com", 8080, false},
		{"app.example.com:443", "app.example.com", 443, true},
		{"app.example.com", "app.example.com", 80, false},
	}
	for _, c := range cases {
		h, p, tlsOn, err := parseTarget(c.in, map[string]any{})
		if err != nil {
			t.Errorf("%s: unexpected error %v", c.in, err)
			continue
		}
		if h != c.wantHost || p != c.wantPort || tlsOn != c.wantTLS {
			t.Errorf("%s: got (%s,%d,%v) want (%s,%d,%v)", c.in, h, p, tlsOn, c.wantHost, c.wantPort, c.wantTLS)
		}
	}
}

func TestHostScope(t *testing.T) {
	if got := hostOf("https://app.example.com/login?x=1"); got != "app.example.com" {
		t.Errorf("hostOf url = %q", got)
	}
	if got := hostOf("app.example.com:8443"); got != "app.example.com" {
		t.Errorf("hostOf host:port = %q", got)
	}
	if got := hostOf("prioritize the auth flow"); got != "" {
		t.Errorf("free-text scope note should not be host-like, got %q", got)
	}
	allowed := []string{"app.example.com"}
	if !hostInScope("app.example.com", allowed) {
		t.Error("exact host should be in scope")
	}
	if hostInScope("evil.com", allowed) {
		t.Error("unrelated host must be out of scope")
	}
	if hostInScope("sub.app.example.com", allowed) {
		t.Error("subdomain must NOT be auto-allowed (strict policy)")
	}
	if hostInScope("app.example.com", nil) {
		t.Error("empty allowlist must block everything")
	}
}

func TestSendRawHTTPOutOfScopeIsBlocked(t *testing.T) {
	tl := NewSendRawHTTPTool(&ScanContext{Target: "http://only.example.com"})
	res, _ := tl.Execute(context.Background(), map[string]any{
		"target":      "http://127.0.0.1:9",
		"raw_request": "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
	}, nil)
	if !res.IsError {
		t.Fatal("expected out-of-scope target to be blocked")
	}
	if !strings.Contains(res.Content, "out of scope") {
		t.Errorf("error should explain scope block: %s", res.Content)
	}
}

func TestSendRawHTTPSocketRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Drain the request line so the client's write completes.
		br := bufio.NewReader(conn)
		_, _ = br.ReadString('\n')
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"))
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	tl := NewSendRawHTTPTool(&ScanContext{Target: "http://127.0.0.1"})
	res, _ := tl.Execute(context.Background(), map[string]any{
		"target":          fmt.Sprintf("http://127.0.0.1:%d", port),
		"raw_request":     "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
		"read_timeout_ms": 1500,
	}, nil)
	if res.IsError {
		t.Fatalf("unexpected error: %s", res.Content)
	}
	if !strings.Contains(res.Content, "hello") || !strings.Contains(res.Content, "200 OK") {
		t.Errorf("response not captured verbatim: %s", res.Content)
	}
}

func TestSendRawHTTPRequiresArgs(t *testing.T) {
	tl := NewSendRawHTTPTool(&ScanContext{Target: "http://x.example.com"})
	res, _ := tl.Execute(context.Background(), map[string]any{"target": "http://x.example.com"}, nil)
	if !res.IsError {
		t.Error("expected error when raw_request missing")
	}
}
