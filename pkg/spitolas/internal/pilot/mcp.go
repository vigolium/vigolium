package pilot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"

	"go.uber.org/zap"
)

// mcpHTTPServer serves MCP tools over HTTP(SSE) transport.
// Runs as a goroutine in the same process — no subprocess needed.
type mcpHTTPServer struct {
	crawler  *PilotCrawler
	listener net.Listener
	server   *http.Server
	url      string // e.g. "http://127.0.0.1:PORT/mcp"

	// toolCtx is a server-owned context for tool execution. It is NOT tied to the
	// parent scan timeout or HTTP request lifecycle. It is cancelled only when
	// Stop() is called. This ensures in-flight browser operations complete even
	// when the ACP agent subprocess is killed between retries.
	toolCtx    context.Context
	toolCancel context.CancelFunc

	mu            sync.Mutex
	sseClients    map[string]chan []byte // sessionID → SSE channel
	nextSessionID int
}

// newMCPHTTPServer creates and starts an MCP HTTP server on a random port.
// The ctx parameter is NOT used for tool execution — tools use a server-owned
// context that is only cancelled by Stop(). This prevents the parent scan
// timeout or ACP subprocess death from interrupting browser operations.
func newMCPHTTPServer(_ context.Context, crawler *PilotCrawler) (*mcpHTTPServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	toolCtx, toolCancel := context.WithCancel(context.Background())
	s := &mcpHTTPServer{
		crawler:    crawler,
		listener:   ln,
		sseClients: make(map[string]chan []byte),
		url:        fmt.Sprintf("http://%s", ln.Addr().String()),
		toolCtx:    toolCtx,
		toolCancel: toolCancel,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/sse", s.handleSSE)
	mux.HandleFunc("/message", s.handleMessage)
	// Streamable HTTP: single endpoint handles both GET (SSE) and POST (messages)
	mux.HandleFunc("/mcp", s.handleStreamableHTTP)

	s.server = &http.Server{Handler: mux}
	go func() {
		if err := s.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			zap.L().Debug("mcp http server error", zap.Error(err))
		}
	}()

	zap.L().Debug("MCP HTTP server started", zap.String("url", s.url))
	return s, nil
}

// URL returns the base URL of the MCP server.
func (s *mcpHTTPServer) URL() string { return s.url }

// SSEURL returns the SSE endpoint URL.
func (s *mcpHTTPServer) SSEURL() string { return s.url + "/sse" }

// Stop shuts down the server and cancels all in-flight tool execution.
func (s *mcpHTTPServer) Stop() {
	s.toolCancel()
	_ = s.server.Close()
	s.mu.Lock()
	for _, ch := range s.sseClients {
		close(ch)
	}
	s.sseClients = make(map[string]chan []byte)
	s.mu.Unlock()
}

// handleStreamableHTTP handles the MCP Streamable HTTP transport (2025-03-26 spec).
// POST: receives JSON-RPC request, returns JSON-RPC response.
func (s *mcpHTTPServer) handleStreamableHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	// Use server-scoped context, NOT r.Context(). When the ACP agent subprocess
	// is killed between retries, the HTTP connection drops and r.Context() gets
	// cancelled. Using server context prevents in-flight tool execution from being
	// interrupted, keeping the browser in a consistent state.
	resp := s.processJSONRPC(s.toolCtx, body)
	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

// handleSSE handles the legacy SSE transport endpoint.
// GET: establishes SSE stream. Sends endpoint URL as first event.
func (s *mcpHTTPServer) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	s.mu.Lock()
	s.nextSessionID++
	sessionID := fmt.Sprintf("pilot-sse-%d", s.nextSessionID)
	ch := make(chan []byte, 64)
	s.sseClients[sessionID] = ch
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.sseClients, sessionID)
		s.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Send the message endpoint URL as the first SSE event
	fmt.Fprintf(w, "event: endpoint\ndata: %s/message?sessionId=%s\n\n", s.url, sessionID)
	flusher.Flush()

	// Stream responses back
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case data, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(data))
			flusher.Flush()
		}
	}
}

// handleMessage handles POST messages from the SSE transport.
func (s *mcpHTTPServer) handleMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("sessionId")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	resp := s.processJSONRPC(s.toolCtx, body)

	// For SSE transport: send response through SSE channel
	s.mu.Lock()
	ch, hasSSE := s.sseClients[sessionID]
	s.mu.Unlock()

	if hasSSE && ch != nil {
		select {
		case ch <- resp:
		default:
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// Fallback: direct response (Streamable HTTP mode)
	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

// processJSONRPC handles a single JSON-RPC request and returns the response.
func (s *mcpHTTPServer) processJSONRPC(ctx context.Context, body []byte) []byte {
	var msg struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id,omitempty"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params,omitempty"`
	}
	if err := json.Unmarshal(body, &msg); err != nil {
		return jsonRPCErr(nil, -32700, "Parse error")
	}

	switch msg.Method {
	case "initialize":
		return jsonRPCOK(msg.ID, map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":   map[string]any{"tools": map[string]any{}},
			"serverInfo":     map[string]any{"name": "vigolium-pilot", "version": "1.0.0"},
		})
	case "notifications/initialized":
		return nil // no response for notifications
	case "tools/list":
		return jsonRPCOK(msg.ID, map[string]any{"tools": allToolDefinitions()})
	case "tools/call":
		return s.handleToolCall(ctx, msg.ID, msg.Params)
	case "ping":
		return jsonRPCOK(msg.ID, map[string]any{})
	default:
		return jsonRPCErr(msg.ID, -32601, fmt.Sprintf("Method not found: %s", msg.Method))
	}
}

func (s *mcpHTTPServer) handleToolCall(ctx context.Context, id json.RawMessage, params json.RawMessage) []byte {
	var p struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return jsonRPCErr(id, -32602, fmt.Sprintf("Invalid params: %s", err))
	}

	s.crawler.reportProgress() // reset stall timer — agent is alive
	result, err := s.crawler.HandleTool(ctx, p.Name, p.Arguments)
	if err != nil {
		return jsonRPCOK(id, map[string]any{
			"content": []map[string]any{{"type": "text", "text": fmt.Sprintf("Error: %s", err)}},
			"isError": true,
		})
	}

	// Build content blocks — strip screenshot from text to avoid duplication
	var tr ToolResult
	if json.Unmarshal([]byte(result), &tr) == nil && tr.Screenshot != "" {
		// Send text without the base64 screenshot (saves ~4x tokens vs text encoding)
		screenshot := tr.Screenshot
		tr.Screenshot = ""
		textJSON, _ := json.Marshal(tr)
		content := []map[string]any{
			{"type": "text", "text": string(textJSON)},
			{"type": "image", "data": screenshot, "mimeType": "image/jpeg"},
		}
		return jsonRPCOK(id, map[string]any{"content": content})
	}

	content := []map[string]any{{"type": "text", "text": result}}
	return jsonRPCOK(id, map[string]any{"content": content})
}

// JSON-RPC helpers
func jsonRPCOK(id json.RawMessage, result any) []byte {
	resp := map[string]any{"jsonrpc": "2.0", "id": id, "result": result}
	data, _ := json.Marshal(resp)
	return data
}

func jsonRPCErr(id json.RawMessage, code int, message string) []byte {
	resp := map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message}}
	data, _ := json.Marshal(resp)
	return data
}

// mcpToolDef describes a single tool for the MCP tools/list response.
type mcpToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema mcpInputSchema `json:"inputSchema"`
}

type mcpInputSchema struct {
	Type       string                    `json:"type"`
	Properties map[string]mcpPropertyDef `json:"properties"`
	Required   []string                  `json:"required,omitempty"`
}

type mcpPropertyDef struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

// allToolDefinitions returns all tool definitions for the MCP tools/list response.
func allToolDefinitions() []mcpToolDef {
	str := func(desc string) mcpPropertyDef { return mcpPropertyDef{Type: "string", Description: desc} }
	obj := func(props map[string]mcpPropertyDef, req ...string) mcpInputSchema {
		return mcpInputSchema{Type: "object", Properties: props, Required: req}
	}

	return []mcpToolDef{
		// Action tools
		{Name: "click", Description: "Click element at XPath. Returns full page state.", InputSchema: obj(map[string]mcpPropertyDef{"xpath": str("XPath of element")}, "xpath")},
		{Name: "type_text", Description: "Type text into input. Clears existing value first.", InputSchema: obj(map[string]mcpPropertyDef{"xpath": str("XPath of input"), "value": str("Text to type")}, "xpath", "value")},
		{Name: "select_option", Description: "Select dropdown option.", InputSchema: obj(map[string]mcpPropertyDef{"xpath": str("XPath of select"), "value": str("Option to select")}, "xpath", "value")},
		{Name: "check", Description: "Set checkbox/radio state.", InputSchema: obj(map[string]mcpPropertyDef{"xpath": str("XPath of checkbox/radio"), "checked": str("true or false")}, "xpath")},
		{Name: "navigate", Description: "Navigate to URL directly.", InputSchema: obj(map[string]mcpPropertyDef{"url": str("URL to navigate to")}, "url")},
		{Name: "go_back", Description: "Browser back button.", InputSchema: obj(map[string]mcpPropertyDef{})},
		{Name: "submit_form", Description: "Submit form via requestSubmit().", InputSchema: obj(map[string]mcpPropertyDef{"form_xpath": str("XPath of form")}, "form_xpath")},
		{Name: "scroll", Description: "Scroll page.", InputSchema: obj(map[string]mcpPropertyDef{"direction": str("up or down"), "amount": str("Pixels (default 500)")})},
		// Investigative tools
		{Name: "get_page_text", Description: "Full page innerText (max 8K chars).", InputSchema: obj(map[string]mcpPropertyDef{})},
		{Name: "get_element_text", Description: "Text content of element.", InputSchema: obj(map[string]mcpPropertyDef{"xpath": str("XPath of element")}, "xpath")},
		{Name: "screenshot", Description: "Capture screenshot as base64 PNG.", InputSchema: obj(map[string]mcpPropertyDef{})},
		{Name: "execute_js", Description: "Run JavaScript, return result.", InputSchema: obj(map[string]mcpPropertyDef{"code": str("JavaScript code")}, "code")},
		{Name: "get_state_graph", Description: "All states + edges + current position.", InputSchema: obj(map[string]mcpPropertyDef{})},
		// Checkpoint tools
		{Name: "create_checkpoint", Description: "Create a checkpoint for a discovered feature. One checkpoint per form/interaction flow, not per page. Write test_plan as numbered actions with expected outcomes.", InputSchema: obj(map[string]mcpPropertyDef{
			"name":        str("Checkpoint name (e.g. 'User Management')"),
			"description": str("What this feature area does"),
			"test_plan":   str("What to test: specific actions to perform (e.g. 'Create user, edit role, delete')"),
			"entry_xpath": str("Optional: XPath of the element to click to enter this feature from the current page"),
			"priority":    str("Priority 1-1000 (higher=first). Purchase/checkout=900+, Account/auth=700+, Content=500+, Static/other=300+. Default: 500"),
		}, "name")},
		{Name: "go_to_checkpoint", Description: "Navigate to a checkpoint by replaying its navigation steps from root. If a step fails, returns needs_help — fix it manually then call resume_replay().", InputSchema: obj(map[string]mcpPropertyDef{
			"checkpoint_id": str("Checkpoint ID (e.g. cp_1)"),
		}, "checkpoint_id")},
		{Name: "resume_replay", Description: "Continue replaying navigation steps after you fixed the broken step. Call this after handling a needs_help response from go_to_checkpoint.", InputSchema: obj(map[string]mcpPropertyDef{})},
		{Name: "abort_replay", Description: "Cancel navigation to checkpoint. Use when you cannot reach it.", InputSchema: obj(map[string]mcpPropertyDef{})},
		{Name: "complete_checkpoint", Description: "Mark checkpoint as explored/completed. Checkpoint MUST be active first (via go_to_checkpoint or activate_checkpoint).", InputSchema: obj(map[string]mcpPropertyDef{
			"checkpoint_id": str("Checkpoint ID"),
			"notes":         str("What was tested and found"),
		}, "checkpoint_id")},
		{Name: "activate_checkpoint", Description: "Mark a checkpoint as active for exploration. Use when you arrived at a checkpoint's page naturally (without go_to_checkpoint). Required before complete_checkpoint.", InputSchema: obj(map[string]mcpPropertyDef{
			"checkpoint_id": str("Checkpoint ID to activate"),
		}, "checkpoint_id")},
		{Name: "get_checkpoint_list", Description: "All checkpoints with status and tree structure.", InputSchema: obj(map[string]mcpPropertyDef{})},
		{Name: "get_next_checkpoint", Description: "Highest-priority discovered (unexplored) checkpoint.", InputSchema: obj(map[string]mcpPropertyDef{})},
		{Name: "update_checkpoint", Description: "Update checkpoint metadata.", InputSchema: obj(map[string]mcpPropertyDef{
			"checkpoint_id": str("Checkpoint ID"),
			"name":          str("New name"),
			"description":   str("New description"),
			"test_plan":     str("New test plan"),
			"priority":      str("New priority 1-1000 (higher=first)"),
		}, "checkpoint_id")},
		// Entity tools
		{Name: "register_entity", Description: "Register created entity for create-then-delete.", InputSchema: obj(map[string]mcpPropertyDef{"type": str("Entity type"), "identifier": str("How to identify it")}, "type", "identifier")},
		{Name: "get_created_entities", Description: "List all created entities.", InputSchema: obj(map[string]mcpPropertyDef{})},
		{Name: "mark_entity_deleted", Description: "Record entity deletion.", InputSchema: obj(map[string]mcpPropertyDef{"entity_id": str("Entity ID")}, "entity_id")},
		// Session tools
		{Name: "store_credentials", Description: "Store auth credentials.", InputSchema: obj(map[string]mcpPropertyDef{"username": str("Username"), "password": str("Password")}, "username", "password")},
		{Name: "get_credentials", Description: "Get stored credentials.", InputSchema: obj(map[string]mcpPropertyDef{})},
		{Name: "blacklist_element", Description: "Blacklist element from clicking.", InputSchema: obj(map[string]mcpPropertyDef{"xpath": str("XPath"), "reason": str("Why blocked")}, "xpath")},
		{Name: "get_blacklist", Description: "View blacklisted elements.", InputSchema: obj(map[string]mcpPropertyDef{})},
		{Name: "log_finding", Description: "Record security finding.", InputSchema: obj(map[string]mcpPropertyDef{"description": str("Finding"), "severity": str("low/medium/high/critical"), "url": str("URL"), "evidence": str("Evidence")}, "description")},
		{Name: "terminate_crawl", Description: "End the crawl. Only call after BOTH breadth and depth phases are complete. Will be rejected if there are pending or needs_revisit checkpoints.", InputSchema: obj(map[string]mcpPropertyDef{"reason": str("Why terminating")})},
	}
}

