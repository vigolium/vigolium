package h2raw

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// h2Server is a TLS server negotiating h2 whose /echo handler reads the whole
// body and answers 200 with it (400 when the body read fails).
func h2Server(t *testing.T) (*httptest.Server, Options) {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "bad body: "+err.Error())
			return
		}
		w.Header().Set("X-Proto", r.Proto)
		_, _ = w.Write(append([]byte(r.Method+" "+r.URL.Path+" "), body...))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, Options{TLSConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"}, Timeout: 3 * time.Second}
}

func addr(srv *httptest.Server) string { return srv.Listener.Addr().String() }

func i64(v int64) *int64 { return &v }

func TestSend_WellFormedRequest(t *testing.T) {
	srv, opts := h2Server(t)
	res, err := Send(context.Background(), addr(srv), Request{
		Method: "POST", Path: "/echo", Authority: "example.com", ContentLength: i64(5), Body: []byte("hello"),
		Headers: [][2]string{{"Content-Type", "text/plain"}},
	}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Answered || res.TimedOut || res.Status != 200 || string(res.Body) != "POST /echo hello" || res.ALPN != "h2" {
		t.Fatalf("result = %+v (body %q)", res, res.Body)
	}
	var proto string
	for _, h := range res.Headers {
		if h[0] == "x-proto" {
			proto = h[1]
		}
	}
	if proto != "HTTP/2.0" {
		t.Fatalf("server saw %q, want HTTP/2.0", proto)
	}
}

// A content-length the DATA falls short of, with the stream ended, is answered
// at once (the server refuses the short body); the same request with the
// stream left open is not answered before the timeout — the oracle.
func TestSend_ContentLengthMismatchTiming(t *testing.T) {
	srv, opts := h2Server(t)
	opts.Timeout = 1500 * time.Millisecond

	ended, err := Send(context.Background(), addr(srv), Request{
		Method: "POST", Path: "/echo", Authority: "example.com", ContentLength: i64(50), Body: []byte("short"),
	}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !ended.Answered || ended.TimedOut || ended.Elapsed >= opts.Timeout {
		t.Fatalf("ended stream: %+v", ended)
	}
	if ended.Status != http.StatusBadRequest && ended.ResetCode == "" {
		t.Fatalf("ended stream answered %d without a reset; want a refusal of the short body", ended.Status)
	}

	open, err := Send(context.Background(), addr(srv), Request{
		Method: "POST", Path: "/echo", Authority: "example.com", ContentLength: i64(50), Body: []byte("short"),
		OpenStream: true, ChunkSize: 2,
	}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if open.Answered || !open.TimedOut || open.Elapsed < opts.Timeout {
		t.Fatalf("open stream: %+v; want no answer within the timeout", open)
	}
}

func TestSend_Refusals(t *testing.T) {
	// HTTP/1.1-only TLS server: ALPN never selects h2.
	h1 := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer h1.Close()
	pool := x509.NewCertPool()
	pool.AddCert(h1.Certificate())
	_, err := Send(context.Background(), addr(h1), Request{}, Options{TLSConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"}})
	if !errors.Is(err, ErrNoH2) {
		t.Fatalf("h1-only server: err = %v, want ErrNoH2", err)
	}
	if _, err := Send(context.Background(), "127.0.0.1:1", Request{Body: make([]byte, maxBodyBytes+1)}, Options{}); err == nil ||
		!strings.Contains(err.Error(), "WINDOW_UPDATE") {
		t.Fatalf("oversized body: err = %v", err)
	}
	if _, err := Send(context.Background(), "no-port", Request{}, Options{}); err == nil {
		t.Fatal("an address without a port is refused")
	}
}

func TestChunks(t *testing.T) {
	got := chunks([]byte("abcdefg"), 3)
	if len(got) != 3 || string(got[0].data) != "abc" || string(got[2].data) != "g" || len(got[2].rest) != 0 || len(got[0].rest) != 4 {
		t.Fatalf("chunks = %+v", got)
	}
	if len(chunks(nil, 3)) != 0 || len(chunks([]byte("ab"), 0)) != 1 {
		t.Fatal("empty body sends no DATA; size 0 sends one frame")
	}
}
