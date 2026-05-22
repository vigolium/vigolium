package mcp_tool_fuzz

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

func rpcMethod(body []byte) string {
	var env struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal(body, &env)
	return env.Method
}

// callArg extracts params.arguments[arg] from a tools/call body.
func callArg(body []byte, arg string) string {
	var env struct {
		Params struct {
			Arguments map[string]any `json:"arguments"`
		} `json:"params"`
	}
	_ = json.Unmarshal(body, &env)
	if v, ok := env.Params.Arguments[arg].(string); ok {
		return v
	}
	return ""
}

const passwdContent = "root:x:0:0:root:/root:/bin/bash"

// vulnToolHandler exposes a "readfile" tool with a string `path` argument and
// returns /etc/passwd content when the path looks like a traversal payload.
func vulnToolHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch rpcMethod(raw) {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"readfile","description":"reads a file","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}]}}`)
		case "tools/call":
			path := callArg(raw, "path")
			text := "ok: " + path
			if strings.Contains(path, "passwd") || strings.Contains(path, "..") {
				text = passwdContent // unrestricted read => LFI
			}
			out := map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"result": map[string]any{
					"content": []map[string]any{{"type": "text", "text": text}},
					"isError": false,
				},
			}
			b, _ := json.Marshal(out)
			_, _ = w.Write(b)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// safeToolHandler exposes the same tool but never honours a traversal payload,
// the secure behaviour.
func safeToolHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch rpcMethod(raw) {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"readfile","description":"reads a file","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}]}}`)
		case "tools/call":
			path := callArg(raw, "path")
			if strings.Contains(path, "passwd") || strings.Contains(path, "..") || strings.HasPrefix(path, "file://") {
				out := map[string]any{
					"jsonrpc": "2.0", "id": 1,
					"result": map[string]any{
						"content": []map[string]any{{"type": "text", "text": "access denied"}},
						"isError": true,
					},
				}
				b, _ := json.Marshal(out)
				_, _ = w.Write(b)
				return
			}
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}],"isError":false}}`)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// TestScanPerHost_DetectsToolLFI flags a tool whose argument leaks /etc/passwd
// via a path-traversal payload.
func TestScanPerHost_DetectsToolLFI(t *testing.T) {
	srv := httptest.NewServer(vulnToolHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "a tool leaking /etc/passwd must be flagged")
	assert.Equal(t, "MCP Tool Argument Local File Inclusion", res[0].Info.Name)
	assert.Equal(t, "path", res[0].FuzzingParameter)
}

// TestScanPerHost_SafeServerNoFinding ensures a tool that rejects traversal
// payloads yields nothing.
func TestScanPerHost_SafeServerNoFinding(t *testing.T) {
	srv := httptest.NewServer(safeToolHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "a tool rejecting traversal payloads must not be flagged")
}

// TestStringArgs keeps only string-typed (or untyped) argument names.
func TestStringArgs(t *testing.T) {
	args := map[string]any{"path": "x", "count": 1, "flag": true}
	types := map[string]string{"path": "string", "count": "integer", "flag": "boolean"}
	got := stringArgs(args, types)
	assert.Equal(t, []string{"path"}, got)
}

// TestCapitalise covers the vuln-tag label helper.
func TestCapitalise(t *testing.T) {
	assert.Equal(t, "Command Injection", capitalise("rce"))
	assert.Equal(t, "Local File Inclusion", capitalise("lfi"))
	assert.Equal(t, "SSRF", capitalise("ssrf"))
	assert.Equal(t, "", capitalise(""))
}

// TestCanProcess_RequiresResponse verifies the detection gate.
func TestCanProcess_RequiresResponse(t *testing.T) {
	rr := modtest.Request(t, "http://example.com/mcp")
	assert.False(t, New().CanProcess(rr))
	assert.False(t, New().CanProcess(nil))
}
