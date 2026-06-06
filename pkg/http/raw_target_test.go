package http

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/core/network"
	"github.com/vigolium/vigolium/pkg/core/services"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// rawLineListener accepts one connection, captures the request head (everything
// up to the blank line), replies with a minimal 200, and returns the captured
// head on the channel. It lets a test assert the exact bytes on the wire.
func rawLineListener(t *testing.T) (addr string, head <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ch := make(chan string, 1)
	go func() {
		defer func() { _ = ln.Close() }()
		conn, err := ln.Accept()
		if err != nil {
			ch <- ""
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(conn)
		var b strings.Builder
		for {
			line, err := br.ReadString('\n')
			b.WriteString(line)
			if err != nil || line == "\r\n" || line == "\n" {
				break
			}
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		ch <- b.String()
	}()
	return ln.Addr().String(), ch
}

func firstLine(head string) string {
	if i := strings.IndexByte(head, '\n'); i >= 0 {
		return strings.TrimRight(head[:i], "\r\n")
	}
	return strings.TrimRight(head, "\r\n")
}

func headerValue(head, name string) string {
	for _, line := range strings.Split(head, "\n") {
		line = strings.TrimRight(line, "\r")
		if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func newTestRequester(t *testing.T) *Requester {
	t.Helper()
	opts := types.DefaultOptions()
	if err := network.Init(opts); err != nil {
		t.Fatalf("network.Init: %v", err)
	}
	r, err := NewRequester(opts, &services.Services{Options: opts})
	if err != nil {
		t.Fatalf("NewRequester: %v", err)
	}
	return r
}

// TestRawRequestTarget_WritesLiteralRequestLine proves the keystone primitive of
// the "Cracking the lens" routing-based attacks: with Options.RawRequestTarget
// set, the request-line target is written verbatim on the wire (here an
// absolute-form URI) while the TCP connection still goes to the request's real
// host. The Host header is preserved from the request, not overwritten with the
// connection host — so a Host/target mismatch reaches the server.
func TestRawRequestTarget_WritesLiteralRequestLine(t *testing.T) {
	r := newTestRequester(t)
	addr, head := rawLineListener(t)

	rr, err := httpmsg.GetRawRequestFromURL("http://" + addr + "/origin-form")
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	const target = "http://internal.example:8080/latest/meta-data/"
	resp, _, err := r.Execute(rr, Options{
		RawRequest:       true,
		RawRequestTarget: target,
		NoRedirects:      true,
		NoClustering:     true,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if resp != nil {
		resp.Close()
	}

	got := <-head
	if got == "" {
		t.Fatal("listener captured nothing")
	}
	wantLine := "GET " + target + " HTTP/1.1"
	if fl := firstLine(got); fl != wantLine {
		t.Errorf("request line = %q, want %q", fl, wantLine)
	}
	// Connection went to the listener (real host), and the Host header is the
	// real host with its port stripped by the requester — NOT the target host.
	if h := headerValue(got, "Host"); !strings.HasPrefix(h, "127.0.0.1") {
		t.Errorf("Host header = %q, want it to name the connection host 127.0.0.1", h)
	}
}

// TestRawRequest_WithoutTarget_UsesOriginForm is the control: the same RawRequest
// path with no RawRequestTarget emits a normal origin-form request line. This
// proves the absolute-form line above comes from the override, not the raw client.
func TestRawRequest_WithoutTarget_UsesOriginForm(t *testing.T) {
	r := newTestRequester(t)
	addr, head := rawLineListener(t)

	rr, err := httpmsg.GetRawRequestFromURL("http://" + addr + "/origin-form")
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	resp, _, err := r.Execute(rr, Options{RawRequest: true, NoRedirects: true, NoClustering: true})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if resp != nil {
		resp.Close()
	}

	got := <-head
	if fl := firstLine(got); fl != "GET /origin-form HTTP/1.1" {
		t.Errorf("request line = %q, want origin-form %q", fl, "GET /origin-form HTTP/1.1")
	}
}
