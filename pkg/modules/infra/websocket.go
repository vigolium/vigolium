package infra

import (
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"strings"

	httputil "github.com/projectdiscovery/utils/http"
)

const webSocketMagicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// IsWebSocketHandshake reports whether resp is a genuine WebSocket upgrade
// (RFC 6455) rather than a bare 101 status. A module that confirms WebSocket
// support purely on `StatusCode == 101` can be fooled by a misconfigured
// reverse proxy or catch-all that returns 101 without actually speaking the
// WebSocket protocol — every downstream origin/CSWSH probe then "succeeds"
// against a non-WebSocket endpoint, producing a false positive.
//
// A compliant server completes the handshake with both `Upgrade: websocket`
// and a `Sec-WebSocket-Accept` header (the base64 SHA-1 of the client key plus
// the RFC magic GUID). Requiring all three — 101 + Upgrade + Accept — is the
// minimal proof that the server processed the handshake as WebSocket, and a
// conformant server always emits them, so it introduces no false negative.
func IsWebSocketHandshake(resp *httputil.ResponseChain) bool {
	if resp == nil || resp.Response() == nil {
		return false
	}
	r := resp.Response()
	if r.StatusCode != http.StatusSwitchingProtocols { // 101
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		return false
	}
	if !headerHasToken(r.Header.Get("Connection"), "upgrade") {
		return false
	}
	return strings.TrimSpace(r.Header.Get("Sec-WebSocket-Accept")) != ""
}

// IsWebSocketHandshakeForKey additionally proves the server processed the
// caller's fresh Sec-WebSocket-Key. A fixed or arbitrary non-empty Accept header
// from a 101 catch-all is not a WebSocket handshake.
func IsWebSocketHandshakeForKey(resp *httputil.ResponseChain, key string) bool {
	if !IsWebSocketHandshake(resp) || strings.TrimSpace(key) == "" {
		return false
	}
	want := WebSocketAccept(key)
	got := strings.TrimSpace(resp.Response().Header.Get("Sec-WebSocket-Accept"))
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// WebSocketAccept returns the RFC 6455 accept value for a Sec-WebSocket-Key.
func WebSocketAccept(key string) string {
	sum := sha1.Sum([]byte(strings.TrimSpace(key) + webSocketMagicGUID)) // #nosec G505 -- required by RFC 6455, not used for cryptographic security
	return base64.StdEncoding.EncodeToString(sum[:])
}

func headerHasToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}
