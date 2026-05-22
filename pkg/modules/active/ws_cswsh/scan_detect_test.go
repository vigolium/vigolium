package ws_cswsh

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// TestNew_Metadata verifies module identity and tags.
func TestNew_Metadata(t *testing.T) {
	t.Parallel()
	m := New()
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
	assert.Equal(t, ModuleTags, m.Tags())
}

// The CSWSH module only inspects the upgrade status code (101), so a plain
// httptest handler that returns 101 for upgrade requests faithfully emulates a
// WebSocket server with no origin validation.

// TestScanPerRequest_DetectsCSWSH drives the real scan method against a server
// that upgrades any WebSocket handshake regardless of Origin. After confirming
// WS support with the legitimate origin, every malicious origin scenario (evil,
// null, subdomain, missing) should be flagged.
func TestScanPerRequest_DetectsCSWSH(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			w.WriteHeader(http.StatusSwitchingProtocols)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/ws")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected CSWSH findings when any origin is accepted")
	// All four malicious-origin scenarios should fire against a permissive server.
	assert.Len(t, res, len(originTests))
	for _, r := range res {
		assert.True(t, r.MatcherStatus)
	}
}

// TestScanPerRequest_NoFalsePositive ensures an endpoint that never upgrades
// (no WebSocket support) yields no finding — the module bails after the initial
// matching-origin probe fails.
func TestScanPerRequest_NoFalsePositive(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/ws")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "an endpoint with no WS support must not yield a finding")
}
