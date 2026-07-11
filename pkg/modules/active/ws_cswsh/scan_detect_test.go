package ws_cswsh

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
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

// The CSWSH module confirms WS support by the upgrade HANDSHAKE — 101 plus
// `Upgrade: websocket` and a `Sec-WebSocket-Accept` header — not a bare 101, so
// the test handler completes a realistic handshake via writeWSHandshake.

// writeWSHandshake emits a complete RFC 6455 upgrade response (the accept value
// is the canonical hash for the module's fixed Sec-WebSocket-Key).
func writeWSHandshake(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Upgrade", "websocket")
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set("Sec-WebSocket-Accept", infra.WebSocketAccept(r.Header.Get("Sec-WebSocket-Key")))
	w.WriteHeader(http.StatusSwitchingProtocols)
}

// TestScanPerRequest_DetectsCSWSH drives the real scan method against a server
// that upgrades any WebSocket handshake regardless of Origin. After confirming
// WS support with the legitimate origin, every malicious origin scenario (evil,
// null, subdomain, missing) should be flagged.
func TestScanPerRequest_DetectsCSWSH(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			writeWSHandshake(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/ws")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1, "overlapping origin variants must consolidate into one result")
	assert.Equal(t, output.RecordKindCandidate, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, res[0].EvidenceGrade)
	assert.True(t, res[0].MatcherStatus)
	assert.False(t, res[0].IsFinding(), "a public credential-free socket must not be called authenticated CSWSH")
}

func TestCredentialDependentBrowserHandshakeIsFinding(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Header.Get("Cookie") != "session=secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeWSHandshake(w, r)
	}))
	defer srv.Close()

	base := modtest.Request(t, srv.URL+"/ws")
	raw, err := httpmsg.AddOrReplaceHeader(base.Request().Raw(), "Cookie", "session=secret")
	require.NoError(t, err)
	req := httpmsg.NewHttpRequestWithService(base.Service(), raw)
	resp := httpmsg.NewHttpResponse([]byte("HTTP/1.1 200 OK\r\nSet-Cookie: session=secret; Path=/; SameSite=None; Secure; HttpOnly\r\nContent-Length: 0\r\n\r\n"))
	ctx := httpmsg.NewHttpRequestResponse(req, resp)

	res, err := New().ScanPerRequest(ctx, modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, output.RecordKindFinding, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeBypass, res[0].EvidenceGrade)
	assert.NotEmpty(t, res[0].Metadata["browser_confirmed_variants"])
}

func TestWrongAcceptHashIsIgnored(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Upgrade", "websocket")
		w.Header().Set("Connection", "Upgrade")
		w.Header().Set("Sec-WebSocket-Accept", "not-derived-from-the-request-key")
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))
	defer srv.Close()

	res, err := New().ScanPerRequest(modtest.Request(t, srv.URL+"/ws"), modtest.Requester(t), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-empty but incorrect accept value must not confirm WebSocket support")
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

// TestScanPerRequest_NoFalsePositive_Bare101 covers a reverse proxy / catch-all
// that returns 101 for every upgrade request WITHOUT completing the WebSocket
// handshake (no Sec-WebSocket-Accept). The status-only Step-1 support check used
// to treat this as a WebSocket endpoint and then flag every origin; the
// handshake gate must now bail before any finding fires.
func TestScanPerRequest_NoFalsePositive_Bare101(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusSwitchingProtocols) // bare 101, no handshake headers
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/ws")

	res, err := New().ScanPerRequest(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a bare 101 without a WebSocket handshake must not be flagged")
}
