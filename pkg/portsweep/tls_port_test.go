package portsweep

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// chanListener hands out connections a demultiplexer routed to it.
type chanListener struct {
	ch   chan net.Conn
	addr net.Addr
	done chan struct{}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error   { return nil }
func (l *chanListener) Addr() net.Addr { return l.addr }

type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// nginxLikeTLSPort serves HTTPS on one port and answers plain HTTP on the SAME
// port with nginx's 400 "plain HTTP request was sent to HTTPS port".
func nginxLikeTLSPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	tlsL := &chanListener{ch: make(chan net.Conn), addr: ln.Addr(), done: done}
	plainL := &chanListener{ch: make(chan net.Conn), addr: ln.Addr(), done: done}

	tlsSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "<html>secure app</html>")
	}))
	tlsSrv.Listener = tlsL
	tlsSrv.StartTLS()
	plainSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "<html><center><h1>400 Bad Request</h1></center><center>The plain HTTP request was sent to HTTPS port</center></html>")
	})}
	go func() { _ = plainSrv.Serve(plainL) }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				br := bufio.NewReader(c)
				b, err := br.Peek(1)
				if err != nil {
					_ = c.Close()
					return
				}
				pc := &peekConn{Conn: c, r: br}
				if b[0] == 0x16 {
					tlsL.ch <- pc
				} else {
					plainL.ch <- pc
				}
			}(c)
		}
	}()
	t.Cleanup(func() {
		close(done)
		_ = ln.Close()
		tlsSrv.Close()
		_ = plainSrv.Close()
	})
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return port
}

// A TLS port that answers plain HTTP with a 400 "plain HTTP request
// was sent to HTTPS port" is recorded as https, not http.
func TestConfirmHTTP_PlainToTLSPortIsHTTPS(t *testing.T) {
	port := nginxLikeTLSPort(t)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test server
	pr, ok := confirmHTTP(context.Background(), client, "127.0.0.1", port)
	if !ok {
		t.Fatal("port not confirmed")
	}
	if pr.Scheme != "https" || pr.Status != http.StatusOK {
		t.Fatalf("scheme %s status %d, want https 200", pr.Scheme, pr.Status)
	}
}

func TestLooksLikeTLSPort(t *testing.T) {
	if !looksLikeTLSPort(497, nil) {
		t.Error("497 is nginx's HTTP-to-HTTPS status")
	}
	if looksLikeTLSPort(400, []byte("missing parameter")) {
		t.Error("an ordinary 400 is not a TLS port")
	}
}
