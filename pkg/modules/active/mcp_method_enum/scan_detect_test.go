package mcp_method_enum

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
	"github.com/vigolium/vigolium/pkg/output"
)

func rpcMethod(body []byte) string {
	var env struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal(body, &env)
	return env.Method
}

// vulnMethodHandler answers initialize, then returns a real result for the
// undocumented "debug/info" method (instead of method-not-found), exposing it.
func vulnMethodHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch rpcMethod(raw) {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-abc")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "debug/info":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":5000,"result":{"build":"deadbeef","uptime":123}}`)
		default:
			// Everything else is correctly reported as method-not-found.
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// strictMethodHandler answers initialize but reports method-not-found for every
// undocumented method, the secure behaviour.
func strictMethodHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch rpcMethod(raw) {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-abc")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// TestScanPerHost_DetectsUndocumentedMethod flags a reachable undocumented
// JSON-RPC method.
func TestScanPerHost_DetectsUndocumentedMethod(t *testing.T) {
	srv := httptest.NewServer(vulnMethodHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a reachable debug/* method must be flagged")
	assert.Contains(t, res[0].Info.Name, "debug/info")
	assert.Equal(t, output.RecordKindCandidate, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, res[0].EvidenceGrade)
	assert.Equal(t, false, res[0].Metadata["impact_confirmed"])
}

func TestMethodWordlistExcludesStandardMCPMethods(t *testing.T) {
	for _, standard := range []string{"ping", "logging/setLevel", "roots/list", "sampling/createMessage"} {
		assert.NotContains(t, methodWordlist, standard)
	}
}

// TestScanPerHost_StrictServerNoFinding ensures a server that returns -32601 for
// every undocumented method yields nothing.
func TestScanPerHost_StrictServerNoFinding(t *testing.T) {
	srv := httptest.NewServer(strictMethodHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a server that rejects undocumented methods must not be flagged")
}

// catchAllMethodHandler answers EVERY method (including unknown ones) with a
// successful result — a catch-all server. Without a negative control the module
// would flag every wordlist entry as "exposed".
func catchAllMethodHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch rpcMethod(raw) {
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-abc")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`)
		}
	}
}

// TestScanPerHost_CatchAllServerNoFinding is the regression for the negative
// control: a server that returns a result for any method (so the control probe
// also succeeds) must produce no findings instead of one per wordlist entry.
func TestScanPerHost_CatchAllServerNoFinding(t *testing.T) {
	srv := httptest.NewServer(catchAllMethodHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a catch-all server must not be flagged (negative control caught it)")
}

// TestCanProcess_RequiresResponse verifies the detection gate.
func TestCanProcess_RequiresResponse(t *testing.T) {
	rr := modtest.Request(t, "http://example.com/mcp")
	assert.False(t, New().CanProcess(rr))
	assert.False(t, New().CanProcess(nil))
}
