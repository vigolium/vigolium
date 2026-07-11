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
	"github.com/vigolium/vigolium/pkg/output"
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
		assert.NotContains(t, joined, "sess-1234567890", "session identifiers must be redacted")
	}
	assert.Equal(t, "MCP Credential-Free Tool Invocation Candidate", res[0].Info.Name)
	assert.Equal(t, output.RecordKindCandidate, res[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeDifferential, res[0].EvidenceGrade)
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

// toolErrorMCPHandler enumerates a tool but returns isError:true when it is
// called — the tool is reachable but the call did NOT execute.
func toolErrorMCPHandler() http.HandlerFunc {
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
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo-mcp","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object","properties":{"msg":{"type":"string"}}}}]}}`)
		case "resources/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":3,"result":{"resources":[]}}`)
		case "prompts/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":5,"result":{"prompts":[]}}`)
		case "tools/call":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":100,"result":{"content":[{"type":"text","text":"unauthorized"}],"isError":true}}`)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// TestScanPerHost_ToolErrorNotCallable is the regression for the callability
// over-claim: a tool whose call returns isError:true must NOT escalate the
// finding to "Unauthenticated Tool Invocation" — it stays at enumeration.
func TestScanPerHost_ToolErrorNotCallable(t *testing.T) {
	srv := httptest.NewServer(toolErrorMCPHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res)
	assert.Equal(t, "MCP Server Discovered", res[0].Info.Name,
		"a tool returning isError must not be reported as callable")
	assert.Equal(t, output.RecordKindObservation, res[0].RecordKind)
	joined := strings.Join(res[0].ExtractedResults, "\n")
	assert.NotContains(t, joined, "Callable:", "no tool should be listed as callable")
}

// destructiveToolMCPHandler enumerates a tool whose name suggests a
// state-changing operation; the probe must not invoke it.
func destructiveToolMCPHandler() http.HandlerFunc {
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
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo-mcp","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"delete_account","inputSchema":{"type":"object","properties":{"id":{"type":"string"}}}}]}}`)
		case "resources/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":3,"result":{"resources":[]}}`)
		case "prompts/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":5,"result":{"prompts":[]}}`)
		case "tools/call":
			t := "should-not-be-invoked"
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":100,"result":{"content":[{"type":"text","text":"`+t+`"}],"isError":false}}`)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// TestScanPerHost_SkipsStateChangingTool verifies the safety guard: a tool named
// like a destructive operation is enumerated but not invoked, and the evidence
// records that it was skipped.
func TestScanPerHost_SkipsStateChangingTool(t *testing.T) {
	srv := httptest.NewServer(destructiveToolMCPHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res)
	assert.Equal(t, "MCP Server Discovered", res[0].Info.Name)
	assert.Equal(t, output.RecordKindObservation, res[0].RecordKind)
	joined := strings.Join(res[0].ExtractedResults, "\n")
	assert.Contains(t, joined, "Not invoked", "skipped state-changing tool must be recorded")
	assert.Contains(t, joined, "delete_account")
	assert.NotContains(t, joined, "Callable:", "a skipped tool must not be listed callable")
}

// secretLeakingMCPHandler exposes a read tool whose output contains a live AWS
// access key — a credential leak via unauthenticated tool invocation.
func secretLeakingMCPHandler() http.HandlerFunc {
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
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo-mcp","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"get_config","inputSchema":{"type":"object","properties":{}}}]}}`)
		case "resources/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":3,"result":{"resources":[]}}`)
		case "prompts/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":5,"result":{"prompts":[]}}`)
		case "tools/call":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":100,"result":{"content":[{"type":"text","text":"github_token=ghp_012345` + `6789abcdef` + `ghijklmnop` + `qrstuvwxyz"}],"isError":false}}`)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// TestScanPerHost_DetectsSecretInToolOutput verifies a live credential returned
// by a tool is flagged as a distinct secret-leak finding.
func TestScanPerHost_DetectsSecretInToolOutput(t *testing.T) {
	srv := httptest.NewServer(secretLeakingMCPHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	found := false
	for _, e := range res {
		if e.Info.Name == "MCP Tool Output Leaks Secret" {
			found = true
			assert.Contains(t, strings.Join(e.ExtractedResults, "\n"), "GitHub token")
			assert.Equal(t, output.RecordKindFinding, e.RecordKind)
			assert.Equal(t, output.EvidenceGradeImpact, e.EvidenceGrade)
		}
	}
	assert.True(t, found, "an AWS key in tool output must produce a secret-leak finding")
}

// TestScanSecrets covers the high-precision secret matcher.
func TestScanSecrets(t *testing.T) {
	assert.Empty(t, scanSecrets("just a normal tool response with no secrets"))
	assert.Empty(t, scanSecrets("key AKIAIOSFODNN7EXAMPLE here"), "an AWS access-key ID is not the private secret")
	assert.Contains(t, scanSecrets("aws_secret_access_key=abcdefghijklmnopqrstuvwxyz1234567890ABCD"), "AWS secret access key")
	assert.Contains(t, scanSecrets("token ghp_0123456789abcdefghijABCDEFGHIJ012345"), "GitHub token")
	assert.Empty(t, scanSecrets("the aws documentation mentions AKIA but not a full key"))
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
