package mcp_prompt_fuzz

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

// promptArgValue extracts params.arguments[arg] from a prompts/get body.
func promptArgValue(body []byte, arg string) string {
	var env struct {
		Method string `json:"method"`
		Params struct {
			Arguments map[string]string `json:"arguments"`
		} `json:"params"`
	}
	_ = json.Unmarshal(body, &env)
	return env.Params.Arguments[arg]
}

func rpcMethod(body []byte) string {
	var env struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal(body, &env)
	return env.Method
}

// vulnPromptHandler exposes a prompt that is vulnerable to template injection:
// it "evaluates" ${7*7} / {{7*7}} in the supplied argument before reflecting it.
func vulnPromptHandler() http.HandlerFunc {
	evalTemplates := strings.NewReplacer("${7*7}", "49", "{{7*7}}", "49")
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch rpcMethod(raw) {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "prompts/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":5,"result":{"prompts":[{"name":"greet","arguments":[{"name":"username"}]}]}}`)
		case "prompts/get":
			rendered := evalTemplates.Replace(promptArgValue(raw, "username"))
			out := map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"result": map[string]any{
					"messages": []map[string]any{
						{"role": "user", "content": map[string]any{"type": "text", "text": "Hello " + rendered}},
					},
				},
			}
			b, _ := json.Marshal(out)
			_, _ = w.Write(b)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// safePromptHandler reflects the argument verbatim without evaluating templates,
// the secure behaviour.
func safePromptHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		switch rpcMethod(raw) {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-1")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"demo","version":"1"}}}`)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "prompts/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":5,"result":{"prompts":[{"name":"greet","arguments":[{"name":"username"}]}]}}`)
		case "prompts/get":
			out := map[string]any{
				"jsonrpc": "2.0",
				"id":      1,
				"result": map[string]any{
					"messages": []map[string]any{
						{"role": "user", "content": map[string]any{"type": "text", "text": "Hello " + promptArgValue(raw, "username")}},
					},
				},
			}
			b, _ := json.Marshal(out)
			_, _ = w.Write(b)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// TestScanPerHost_DetectsSSTI flags a prompt argument that evaluates a template
// expression (49 appears next to the SSTI marker).
func TestScanPerHost_DetectsSSTI(t *testing.T) {
	srv := httptest.NewServer(vulnPromptHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "template evaluation in a prompt argument must be flagged")
	assert.Equal(t, "MCP Prompt Argument SSTI", res[0].Info.Name)
}

// TestScanPerHost_SafeServerNoFinding ensures verbatim reflection (no template
// evaluation) yields nothing.
func TestScanPerHost_SafeServerNoFinding(t *testing.T) {
	srv := httptest.NewServer(safePromptHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "verbatim argument reflection must not be flagged")
}

// TestCapitalise covers the vuln-tag label helper.
func TestCapitalise(t *testing.T) {
	assert.Equal(t, "SSTI", capitalise("ssti"))
	assert.Equal(t, "Command Injection", capitalise("rce"))
	assert.Equal(t, "Prompt Injection", capitalise("prompt-injection"))
	assert.Equal(t, "", capitalise(""))
}

// TestCanProcess_RequiresResponse verifies the detection gate.
func TestCanProcess_RequiresResponse(t *testing.T) {
	rr := modtest.Request(t, "http://example.com/mcp")
	assert.False(t, New().CanProcess(rr))
	assert.False(t, New().CanProcess(nil))
}
