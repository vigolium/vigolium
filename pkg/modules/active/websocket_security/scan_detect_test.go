package websocket_security

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

// The module inspects only the HTTP upgrade status code (101 Switching
// Protocols), never the actual WebSocket frames — so a plain httptest handler
// that flips status based on the Origin header is a faithful stand-in for a WS
// server with (or without) origin validation.

// TestScanPerRequest_DetectsPermissiveOrigin drives the real scan method against
// a server that accepts a WebSocket upgrade from any Origin. The module first
// confirms WS support with the matching origin, then probes the evil origin and
// must flag the missing origin check.
func TestScanPerRequest_DetectsPermissiveOrigin(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Accept any upgrade regardless of Origin.
		if r.Header.Get("Upgrade") == "websocket" {
			w.WriteHeader(http.StatusSwitchingProtocols)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/chat")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a finding when the server upgrades from any origin")
	assert.Equal(t, "WebSocket Origin Not Validated", res[0].Info.Name)
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
		// Reject the cross-origin attacker but accept matching origin and absent origin.
		if origin == evilOrigin {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/chat")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected a missing-origin-check finding")
	assert.Equal(t, "WebSocket Missing Origin Check", res[0].Info.Name)
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
