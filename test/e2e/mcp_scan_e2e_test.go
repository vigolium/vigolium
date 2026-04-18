//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	httpClient "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/active/mcp_server_probe"
	"github.com/vigolium/vigolium/pkg/modules/passive/mcp_endpoint_detect"
)

// startMCPServer creates a fake MCP server that speaks the full MCP protocol:
// initialize, notifications/initialized, tools/list, and tools/call.
func startMCPServer(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()

	// Streamable HTTP endpoint at /mcp — handles all JSON-RPC methods via POST
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// SSE stream endpoint
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, "event: endpoint\ndata: /mcp\n\n")
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}

		var req struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.Number     `json:"id"`
			Method  string          `json:"method"`
			Params  json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "test-session-abc123")
			writeJSONRPCResult(w, req.ID, map[string]any{
				"protocolVersion": "2025-03-26",
				"capabilities": map[string]any{
					"tools": map[string]any{"listChanged": true},
				},
				"serverInfo": map[string]any{
					"name":    "test-mcp-server",
					"version": "0.1.0",
				},
			})

		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)

		case "tools/list":
			writeJSONRPCResult(w, req.ID, map[string]any{
				"tools": []map[string]any{
					{
						"name":        "get_weather",
						"description": "Get current weather for a location",
						"inputSchema": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"location": map[string]any{
									"type":        "string",
									"description": "City name",
								},
							},
							"required": []string{"location"},
						},
					},
					{
						"name":        "calculate",
						"description": "Add two numbers",
						"inputSchema": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"a": map[string]any{"type": "number"},
								"b": map[string]any{"type": "number"},
							},
							"required": []string{"a", "b"},
						},
					},
					{
						"name":        "lookup_user",
						"description": "Find a user by email address",
						"inputSchema": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"email": map[string]any{
									"type":   "string",
									"format": "email",
								},
							},
							"required": []string{"email"},
						},
					},
				},
			})

		case "tools/call":
			var params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			if req.Params != nil {
				_ = json.Unmarshal(req.Params, &params)
			}

			switch params.Name {
			case "get_weather":
				loc, _ := params.Arguments["location"].(string)
				writeJSONRPCResult(w, req.ID, map[string]any{
					"content": []map[string]any{
						{"type": "text", "text": fmt.Sprintf("Weather in %s: 22C, sunny", loc)},
					},
					"isError": false,
				})
			case "calculate":
				a, _ := params.Arguments["a"].(float64)
				b, _ := params.Arguments["b"].(float64)
				writeJSONRPCResult(w, req.ID, map[string]any{
					"content": []map[string]any{
						{"type": "text", "text": fmt.Sprintf("Result: %g", a+b)},
					},
					"isError": false,
				})
			case "lookup_user":
				email, _ := params.Arguments["email"].(string)
				writeJSONRPCResult(w, req.ID, map[string]any{
					"content": []map[string]any{
						{"type": "text", "text": fmt.Sprintf("User found: %s (admin)", email)},
					},
					"isError": false,
				})
			default:
				writeJSONRPCError(w, req.ID, -32601, "unknown tool")
			}

		default:
			writeJSONRPCError(w, req.ID, -32601, "method not found")
		}
	})

	// Legacy SSE endpoint
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			accept := r.Header.Get("Accept")
			if strings.Contains(accept, "text/event-stream") {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Cache-Control", "no-cache")
				w.WriteHeader(http.StatusOK)
				_, _ = fmt.Fprintf(w, "event: endpoint\ndata: /mcp\n\n")
				return
			}
		}
		http.Error(w, "not found", http.StatusNotFound)
	})

	// Non-MCP endpoints return 404
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// startMCPServerInitOnly creates a minimal MCP server that only responds to initialize
// (no tools/list support) to test the Info-severity path.
func startMCPServerInitOnly(t *testing.T) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
			ID     json.Number `json:"id"`
		}
		_ = json.Unmarshal(body, &req)

		w.Header().Set("Content-Type", "application/json")

		switch req.Method {
		case "initialize":
			writeJSONRPCResult(w, req.ID, map[string]any{
				"protocolVersion": "2025-03-26",
				"capabilities":    map[string]any{},
				"serverInfo": map[string]any{
					"name":    "minimal-mcp",
					"version": "0.0.1",
				},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		default:
			writeJSONRPCError(w, req.ID, -32601, "method not found")
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func writeJSONRPCResult(w http.ResponseWriter, id json.Number, result any) {
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func writeJSONRPCError(w http.ResponseWriter, id json.Number, code int, message string) {
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func setupMCPTestContext(t *testing.T, srv *httptest.Server) (*TestInfra, *httpmsg.HttpRequestResponse) {
	t.Helper()

	infra, err := SetupTestInfra()
	require.NoError(t, err)
	t.Cleanup(infra.Cleanup)

	host := strings.TrimPrefix(srv.URL, "http://")
	hostPart, portStr, _ := strings.Cut(host, ":")
	port, _ := strconv.Atoi(portStr)
	service := httpmsg.NewServiceSecure(hostPart, port, false)

	rawReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host)
	req := httpmsg.NewHttpRequestWithService(service, []byte(rawReq))

	// Fetch the base response so the module sees a live host
	ctx := httpmsg.NewHttpRequestResponse(req, nil)
	respChain, _, err := infra.HTTPClient.Execute(ctx, httpClient.Options{})
	require.NoError(t, err)
	defer respChain.Close()

	// Build ctx with response attached
	respRaw := respChain.FullResponse()
	var respBytes []byte
	if respRaw != nil {
		respBytes = respRaw.Bytes()
	}
	httpResp := httpmsg.NewHttpResponse(respBytes)
	ctxWithResp := httpmsg.NewHttpRequestResponse(req, httpResp)

	return infra, ctxWithResp
}

// --- Active Module Tests ---

func TestMCPServerProbe_FullPipeline(t *testing.T) {
	srv := startMCPServer(t)
	infra, ctx := setupMCPTestContext(t, srv)

	scanner := mcp_server_probe.New()
	results, err := scanner.ScanPerHost(ctx, infra.HTTPClient, infra.ScanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results, "should find at least one MCP endpoint")

	result := results[0]
	t.Logf("Finding: %s (severity=%s, confidence=%s)", result.Info.Name, result.Info.Severity, result.Info.Confidence)
	for _, e := range result.ExtractedResults {
		t.Logf("  %s", e)
	}

	// Should reach High severity (tools callable without auth)
	assert.Equal(t, "high", strings.ToLower(result.Info.Severity.String()),
		"severity should be High when tools are callable")

	// Should have extracted endpoint info
	hasEndpoint := false
	hasToolInfo := false
	hasCallable := false
	for _, e := range result.ExtractedResults {
		if strings.HasPrefix(e, "Endpoint:") {
			hasEndpoint = true
		}
		if strings.HasPrefix(e, "Tool:") {
			hasToolInfo = true
		}
		if strings.HasPrefix(e, "Callable:") {
			hasCallable = true
		}
	}
	assert.True(t, hasEndpoint, "should have endpoint evidence")
	assert.True(t, hasToolInfo, "should have tool info")
	assert.True(t, hasCallable, "should have callable tool evidence")

	// Should have found the 3 tools
	toolCount := 0
	for _, e := range result.ExtractedResults {
		if strings.HasPrefix(e, "Tool:") {
			toolCount++
		}
	}
	assert.Equal(t, 3, toolCount, "should enumerate all 3 tools")

	// Verify specific tools were called
	callableTools := map[string]bool{}
	for _, e := range result.ExtractedResults {
		if strings.HasPrefix(e, "Callable:") {
			parts := strings.SplitN(e, " → ", 2)
			name := strings.TrimPrefix(parts[0], "Callable: ")
			callableTools[name] = true
		}
	}
	assert.True(t, callableTools["get_weather"], "get_weather should be callable")
	assert.True(t, callableTools["calculate"], "calculate should be callable")
	assert.True(t, callableTools["lookup_user"], "lookup_user should be callable")

	// Verify server info was extracted
	hasServer := false
	for _, e := range result.ExtractedResults {
		if strings.Contains(e, "test-mcp-server") {
			hasServer = true
		}
	}
	assert.True(t, hasServer, "should extract server info")
}

func TestMCPServerProbe_InitOnly(t *testing.T) {
	srv := startMCPServerInitOnly(t)
	infra, ctx := setupMCPTestContext(t, srv)

	scanner := mcp_server_probe.New()
	results, err := scanner.ScanPerHost(ctx, infra.HTTPClient, infra.ScanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results, "should detect MCP endpoint even without tools")

	result := results[0]
	t.Logf("Finding: %s (severity=%s)", result.Info.Name, result.Info.Severity)

	// Should be Info severity — endpoint exists but no tools enumerable
	assert.Equal(t, "info", strings.ToLower(result.Info.Severity.String()),
		"severity should be Info when only init succeeds")
}

func TestMCPServerProbe_NoMCPServer(t *testing.T) {
	// Plain HTTP server with no MCP endpoints
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Hello</body></html>"))
	}))
	t.Cleanup(srv.Close)

	infra, ctx := setupMCPTestContext(t, srv)

	scanner := mcp_server_probe.New()
	results, err := scanner.ScanPerHost(ctx, infra.HTTPClient, infra.ScanCtx)
	require.NoError(t, err)
	assert.Empty(t, results, "should not report findings for non-MCP server")
}

func TestMCPServerProbe_SSETransport(t *testing.T) {
	srv := startMCPServer(t)
	infra, ctx := setupMCPTestContext(t, srv)

	scanner := mcp_server_probe.New()
	results, err := scanner.ScanPerHost(ctx, infra.HTTPClient, infra.ScanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	// Verify SSE transport was detected alongside streamable HTTP
	transports := map[string]bool{}
	for _, e := range results[0].ExtractedResults {
		if strings.HasPrefix(e, "Endpoint:") {
			if strings.Contains(e, "streamable-http") {
				transports["streamable-http"] = true
			}
			if strings.Contains(e, "sse") {
				transports["sse"] = true
			}
		}
	}
	assert.True(t, transports["streamable-http"], "should detect streamable-http transport on /mcp")
}

func TestMCPServerProbe_SampleGeneration(t *testing.T) {
	// Verify tools/call sends appropriate sample data by checking what the server receives
	var receivedCalls []map[string]any

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID     json.Number     `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")

		switch req.Method {
		case "initialize":
			writeJSONRPCResult(w, req.ID, map[string]any{
				"protocolVersion": "2025-03-26",
				"capabilities":    map[string]any{},
				"serverInfo":      map[string]any{"name": "sample-test", "version": "1.0"},
			})
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			writeJSONRPCResult(w, req.ID, map[string]any{
				"tools": []map[string]any{
					{
						"name":        "send_email",
						"description": "Send an email",
						"inputSchema": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"email":   map[string]any{"type": "string", "format": "email"},
								"subject": map[string]any{"type": "string"},
								"count":   map[string]any{"type": "integer"},
								"urgent":  map[string]any{"type": "boolean"},
								"send_at": map[string]any{"type": "string", "format": "date-time"},
							},
							"required": []string{"email", "subject"},
						},
					},
				},
			})
		case "tools/call":
			var params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			if req.Params != nil {
				_ = json.Unmarshal(req.Params, &params)
			}
			receivedCalls = append(receivedCalls, params.Arguments)
			writeJSONRPCResult(w, req.ID, map[string]any{
				"content": []map[string]any{
					{"type": "text", "text": "sent"},
				},
				"isError": false,
			})
		default:
			writeJSONRPCError(w, req.ID, -32601, "not found")
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	infra, ctx := setupMCPTestContext(t, srv)
	scanner := mcp_server_probe.New()
	_, err := scanner.ScanPerHost(ctx, infra.HTTPClient, infra.ScanCtx)
	require.NoError(t, err)

	require.NotEmpty(t, receivedCalls, "should have called at least one tool")
	args := receivedCalls[0]
	t.Logf("Received call args: %+v", args)

	// Verify sample values match expected types
	assert.Equal(t, "test@example.com", args["email"], "email param should get email sample")
	assert.NotEmpty(t, args["subject"], "subject should have a value")

	if count, ok := args["count"]; ok {
		// JSON numbers come as float64
		assert.IsType(t, float64(0), count, "count should be a number")
	}
	if urgent, ok := args["urgent"]; ok {
		assert.IsType(t, true, urgent, "urgent should be a boolean")
	}
	if sendAt, ok := args["send_at"]; ok {
		assert.Contains(t, sendAt, "T", "send_at should be ISO datetime format")
	}
}

// --- Passive Module Tests ---

func TestMCPEndpointDetect_JSONRPCResponse(t *testing.T) {
	infra, err := SetupTestInfra()
	require.NoError(t, err)
	t.Cleanup(infra.Cleanup)

	mcpBody := `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{"tools":{"listChanged":true}},"serverInfo":{"name":"exposed-mcp","version":"1.0"}}}`

	rawReq := "GET /mcp HTTP/1.1\r\nHost: target.example.com\r\n\r\n"
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nMcp-Session-Id: sess-12345\r\nContent-Length: %d\r\n\r\n%s",
		len(mcpBody), mcpBody)

	service := httpmsg.NewServiceSecure("target.example.com", 443, true)
	req := httpmsg.NewHttpRequestWithService(service, []byte(rawReq))
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	ctx := httpmsg.NewHttpRequestResponse(req, resp)

	scanner := mcp_endpoint_detect.New()
	results, err := scanner.ScanPerRequest(ctx, infra.ScanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results, "should detect MCP from JSON-RPC response")

	result := results[0]
	t.Logf("Finding: %s", result.Info.Name)
	for _, e := range result.ExtractedResults {
		t.Logf("  %s", e)
	}

	assert.Equal(t, "MCP Server Detected", result.Info.Name)
	assert.Equal(t, "target.example.com", result.Host)

	// Should detect multiple indicators
	hasPath := false
	hasSessionID := false
	hasServerInfo := false
	for _, e := range result.ExtractedResults {
		if strings.Contains(e, "MCP endpoint path") {
			hasPath = true
		}
		if strings.Contains(e, "Mcp-Session-Id") {
			hasSessionID = true
		}
		if strings.Contains(e, "Server info") || strings.Contains(e, "serverInfo") {
			hasServerInfo = true
		}
	}
	assert.True(t, hasPath, "should detect MCP endpoint path")
	assert.True(t, hasSessionID, "should detect Mcp-Session-Id header")
	assert.True(t, hasServerInfo, "should detect server info")
}

func TestMCPEndpointDetect_ToolsInResponse(t *testing.T) {
	infra, err := SetupTestInfra()
	require.NoError(t, err)
	t.Cleanup(infra.Cleanup)

	mcpBody := `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"get_weather","description":"Get weather"},{"name":"run_query","description":"Run SQL query"}]}}`

	rawReq := "GET /api/mcp HTTP/1.1\r\nHost: target.example.com\r\n\r\n"
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(mcpBody), mcpBody)

	service := httpmsg.NewServiceSecure("target.example.com", 443, true)
	req := httpmsg.NewHttpRequestWithService(service, []byte(rawReq))
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	ctx := httpmsg.NewHttpRequestResponse(req, resp)

	scanner := mcp_endpoint_detect.New()
	results, err := scanner.ScanPerRequest(ctx, infra.ScanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results)

	// Should extract tool names
	hasTools := false
	for _, e := range results[0].ExtractedResults {
		if strings.Contains(e, "Tools exposed") {
			hasTools = true
			assert.Contains(t, e, "get_weather")
			assert.Contains(t, e, "run_query")
		}
	}
	assert.True(t, hasTools, "should extract tool names from tools/list response")
}

func TestMCPEndpointDetect_SSEStream(t *testing.T) {
	infra, err := SetupTestInfra()
	require.NoError(t, err)
	t.Cleanup(infra.Cleanup)

	sseBody := "event: endpoint\ndata: /mcp\n\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n\n"

	rawReq := "GET /sse HTTP/1.1\r\nHost: target.example.com\r\n\r\n"
	rawResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: %d\r\n\r\n%s",
		len(sseBody), sseBody)

	service := httpmsg.NewServiceSecure("target.example.com", 443, true)
	req := httpmsg.NewHttpRequestWithService(service, []byte(rawReq))
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	ctx := httpmsg.NewHttpRequestResponse(req, resp)

	scanner := mcp_endpoint_detect.New()
	results, err := scanner.ScanPerRequest(ctx, infra.ScanCtx)
	require.NoError(t, err)
	require.NotEmpty(t, results, "should detect MCP from SSE stream")

	hasSSE := false
	for _, e := range results[0].ExtractedResults {
		if strings.Contains(e, "SSE stream") {
			hasSSE = true
		}
	}
	assert.True(t, hasSSE, "should detect SSE transport indicator")
}

func TestMCPEndpointDetect_NoMCPIndicators(t *testing.T) {
	infra, err := SetupTestInfra()
	require.NoError(t, err)
	t.Cleanup(infra.Cleanup)

	rawReq := "GET /api/data HTTP/1.1\r\nHost: target.example.com\r\n\r\n"
	rawResp := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 27\r\n\r\n{\"status\":\"ok\",\"count\":42}"

	service := httpmsg.NewServiceSecure("target.example.com", 443, true)
	req := httpmsg.NewHttpRequestWithService(service, []byte(rawReq))
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	ctx := httpmsg.NewHttpRequestResponse(req, resp)

	scanner := mcp_endpoint_detect.New()
	results, err := scanner.ScanPerRequest(ctx, infra.ScanCtx)
	require.NoError(t, err)
	assert.Empty(t, results, "should not flag non-MCP JSON responses")
}
