package http

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// A stored "Connection: close" must not force a new TLS handshake
// per probe on the net/http path; PreserveConnection keeps it.
func TestConnectionClose_DroppedSoConnectionsAreReused(t *testing.T) {
	var conns atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	defer srv.Close()

	r := newTestRequester(t)
	defer r.CloseIdleConnections()
	send := func(opts Options) {
		raw := "GET /x HTTP/1.1\r\nHost: " + srv.Listener.Addr().String() + "\r\nConnection: close\r\n\r\n"
		rr := httpmsg.NewRequestResponseRaw([]byte(raw), serviceFor(t, srv.URL))
		opts.NoClustering = true
		resp, _, err := r.Execute(rr, opts)
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		resp.Close()
	}
	for i := 0; i < 3; i++ {
		send(Options{})
	}
	if n := conns.Load(); n != 1 {
		t.Errorf("connections (TLS handshakes) = %d for 3 requests, want 1", n)
	}

	r.CloseIdleConnections()
	conns.Store(0)
	for i := 0; i < 2; i++ {
		send(Options{PreserveConnection: true})
	}
	if n := conns.Load(); n != 2 {
		t.Errorf("PreserveConnection: connections = %d, want 2 (one per request)", n)
	}
}
