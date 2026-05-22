package mcp_server_probe

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/modules/modtest"
)

// rpcMethod pulls the JSON-RPC "method" out of a request body, returning "" for
// batches or unparseable bodies.
func rpcMethod(body []byte) string {
	var env struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal(body, &env)
	return env.Method
}

// vulnMCPHandler emulates a wide-open MCP server on /mcp: it answers the
// initialize handshake (minting a session id), enumerates one tool, and lets
// that tool be called without authentication.
func vulnMCPHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch rpcMethod(raw) {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1234567890")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"demo-mcp","version":"9.9.9"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","description":"echo back","inputSchema":{"type":"object","properties":{"msg":{"type":"string"}}}}]}}`)
		case "resources/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":3,"result":{"resources":[]}}`)
		case "prompts/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":5,"result":{"prompts":[]}}`)
		case "tools/call":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":100,"result":{"content":[{"type":"text","text":"echoed: test"}],"isError":false}}`)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// TestScanPerHost_DetectsExposedMCP drives the probe against an unauthenticated
// MCP server that enumerates and invokes tools, expecting a High finding.
func TestScanPerHost_DetectsExposedMCP(t *testing.T) {
	srv := httptest.NewServer(vulnMCPHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "expected an MCP-exposure finding for an unauthenticated server")
	if assert.NotEmpty(t, res[0].ExtractedResults) {
		joined := strings.Join(res[0].ExtractedResults, "\n")
		assert.Contains(t, joined, "demo-mcp", "evidence should carry the server name")
	}
}

// TestScanPerHost_NoMCPServer ensures a plain HTTP server that never speaks
// JSON-RPC yields no finding.
func TestScanPerHost_NoMCPServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html><body>not an mcp server</body></html>")
	}))
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a non-MCP server must not yield a finding")
}

// TestCanProcess_RequiresResponse checks the metadata gate: a request without a
// captured response is not processable.
func TestCanProcess_RequiresResponse(t *testing.T) {
	client := modtest.Requester(t)
	rr := modtest.Request(t, "http://example.com/mcp")
	_ = client

	assert.False(t, New().CanProcess(rr), "CanProcess must be false without a response")
	assert.False(t, New().CanProcess(nil), "CanProcess must be false for nil context")
}
