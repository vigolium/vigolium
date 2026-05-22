package mcp_completion_enum

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
)

func rpcMethod(body []byte) string {
	var env struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal(body, &env)
	return env.Method
}

// vulnCompletionHandler exposes a prompt with an argument and serves
// completion values for that argument, leaking enumerable data.
func vulnCompletionHandler() http.HandlerFunc {
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
		case "resources/templates/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":4,"result":{"resourceTemplates":[]}}`)
		case "completion/complete":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":3000,"result":{"completion":{"values":["alice","bob","carol"],"total":3}}}`)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// strictCompletionHandler exposes prompts but returns no completion values,
// the privacy-respecting behaviour.
func strictCompletionHandler() http.HandlerFunc {
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
		case "resources/templates/list":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":4,"result":{"resourceTemplates":[]}}`)
		case "completion/complete":
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":3000,"result":{"completion":{"values":[],"total":0}}}`)
		default:
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"method not found"}}`)
		}
	}
}

// TestScanPerHost_DetectsCompletionDisclosure flags a prompt argument that
// discloses completion values via completion/complete.
func TestScanPerHost_DetectsCompletionDisclosure(t *testing.T) {
	srv := httptest.NewServer(vulnCompletionHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, res, "completion values disclosed for a prompt argument must be flagged")
	assert.Equal(t, "MCP Prompt Argument Values Disclosed via completion/complete", res[0].Info.Name)
	assert.Contains(t, res[0].ExtractedResults, "alice")
}

// TestScanPerHost_NoValuesNoFinding ensures a server returning empty completion
// values yields nothing.
func TestScanPerHost_NoValuesNoFinding(t *testing.T) {
	srv := httptest.NewServer(strictCompletionHandler())
	defer srv.Close()

	client := modtest.Requester(t)
	rr := modtest.Request(t, srv.URL+"/mcp")

	res, err := New().ScanPerHost(rr, client, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, res, "empty completion values must not be flagged")
}

// TestExtractPlaceholders covers the URI-template placeholder parser.
func TestExtractPlaceholders(t *testing.T) {
	assert.Nil(t, extractPlaceholders("/static/path"))
	assert.Equal(t, []string{"id", "name"}, extractPlaceholders("/users/{id}/{name}"))
	assert.Equal(t, []string{"id"}, extractPlaceholders("/x/{id}/y/{id}"), "duplicates collapsed")
}

// TestCanProcess_RequiresResponse verifies the detection gate.
func TestCanProcess_RequiresResponse(t *testing.T) {
	rr := modtest.Request(t, "http://example.com/mcp")
	assert.False(t, New().CanProcess(rr))
	assert.False(t, New().CanProcess(nil))
}
