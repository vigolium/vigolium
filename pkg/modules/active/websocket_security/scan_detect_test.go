package websocket_security

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

// TestNew_Metadata verifies module identity and tags.
func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, ModuleTags, m.Tags())
}

// The module confirms WebSocket support by the upgrade HANDSHAKE — 101 plus
// `Upgrade: websocket` and a `Sec-WebSocket-Accept` header — not a bare 101, so
// the test handlers complete a realistic handshake via writeWSHandshake.

// writeWSHandshake emits a complete RFC 6455 upgrade response (the accept value
// is the canonical hash for the module's fixed Sec-WebSocket-Key).
func writeWSHandshake(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Upgrade", "websocket")
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set("Sec-WebSocket-Accept", infra.WebSocketAccept(r.Header.Get("Sec-WebSocket-Key")))
	w.WriteHeader(http.StatusSwitchingProtocols)
}

// TestScanPerRequest_DetectsPermissiveOrigin drives the real scan method against
// a server that accepts a WebSocket upgrade from any Origin. The module first
// confirms WS support with the matching origin, then probes the evil origin and
// must flag the missing origin check.
func TestScanPerRequest_DetectsPermissiveOrigin(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Accept any upgrade regardless of Origin.
		if r.Header.Get("Upgrade") == "websocket" {
			writeWSHandshake(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/chat")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, output.RecordKindCandidate, res[0].RecordKind)
	assert.Equal(t, "ws-cswsh", res[0].Metadata["canonical_module"])
}

// TestScanPerRequest_DetectsMissingOriginCheck drives the no-Origin branch: the
// server validates the evil origin (rejecting it) but still upgrades when the
// Origin header is absent — a missing-origin-check weakness.
func TestScanPerRequest_DetectsMissingOriginCheck(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			w.WriteHeader(http.StatusOK)
			return
		}
		origin := r.Header.Get("Origin")
		// Reject every non-matching origin; accept the legitimate origin and an
		// absent Origin so this exercises only the hardening observation.
		if origin != "" && origin != "http://"+r.Host {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		writeWSHandshake(w, r)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/chat")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, output.RecordKindObservation, res[0].RecordKind)
	assert.Equal(t, "WebSocket Origin Policy Observation", res[0].Info.Name)
}

// TestScanPerRequest_NoFalsePositive_Bare101 covers a reverse proxy / catch-all
// that returns 101 for every upgrade request WITHOUT completing the WebSocket
// handshake (no Sec-WebSocket-Accept). The status-only check used to treat this
// as an open WebSocket; the handshake gate must now reject it so no origin
// finding fires.
func TestScanPerRequest_NoFalsePositive_Bare101(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusSwitchingProtocols) // bare 101, no handshake headers
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/chat")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a bare 101 without a WebSocket handshake must not be flagged")
}

// TestScanPerRequest_NoFalsePositive ensures an endpoint that does not support
// WebSocket upgrades (never returns 101) yields no finding.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/chat")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-WebSocket endpoint must not yield a finding")
}
