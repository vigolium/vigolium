package provider

import (
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

// ConnectionResetter is the optional interface providers implement so the
// engine can drop idle conns on the failing provider between retry
// attempts — useful when an upstream proxy poisons a specific TCP+TLS
// conn (RST_STREAM after RST_STREAM) and a fresh handshake is the only
// escape. Providers without HTTP state can leave this unimplemented.
type ConnectionResetter interface {
	CloseIdleConnections()
}

// newHTTPClient returns an *http.Client whose HTTP/2 transport sends
// keepalive PING frames on idle connections. Bare http.DefaultTransport
// gets HTTP/2 auto-upgrade but leaves ReadIdleTimeout=0, so a stale conn
// surfaces as `stream error: stream ID N; INTERNAL_ERROR; received from
// peer` on the next request instead of being detected up front.
func newHTTPClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	if h2, err := http2.ConfigureTransports(t); err == nil && h2 != nil {
		h2.ReadIdleTimeout = 30 * time.Second
		h2.PingTimeout = 15 * time.Second
	}
	return &http.Client{Transport: t}
}
