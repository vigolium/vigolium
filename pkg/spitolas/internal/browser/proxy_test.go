package browser

import (
	"testing"

	"github.com/go-rod/rod/lib/launcher"
)

// TestApplyProxyForcesHTTP1 verifies that configuring a proxy also forces
// HTTP/1.1 (disable-http2) and disables QUIC, so traffic can't break or bypass
// an intercepting proxy that mishandles HTTP/2 (net::ERR_HTTP2_PROTOCOL_ERROR).
func TestApplyProxyForcesHTTP1(t *testing.T) {
	l := applyProxy(launcher.New(), "http://127.0.0.1:8080")

	if !l.Has("proxy-server") {
		t.Error("expected proxy-server flag to be set")
	}
	if !l.Has("disable-http2") {
		t.Error("expected disable-http2 flag to be set when proxying")
	}
	if !l.Has("disable-quic") {
		t.Error("expected disable-quic flag to be set when proxying")
	}
}

// TestApplyProxyNoopWithoutProxy verifies that without a proxy, HTTP/2 is left
// untouched so direct (non-proxied) scans keep full protocol fidelity.
func TestApplyProxyNoopWithoutProxy(t *testing.T) {
	l := applyProxy(launcher.New(), "")

	if l.Has("proxy-server") {
		t.Error("did not expect proxy-server flag without a proxy URL")
	}
	if l.Has("disable-http2") {
		t.Error("did not expect disable-http2 flag without a proxy URL")
	}
}
