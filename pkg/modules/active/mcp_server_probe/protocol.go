package mcp_server_probe

import (
	"encoding/json"
	"fmt"
	"strings"
)

// JSON-RPC 2.0 message types for MCP protocol

type jsonRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type jsonRPCNotification struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.Number     `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// MCP initialize types

type initializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ClientInfo      clientInfo     `json:"clientInfo"`
}

type clientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type initializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ServerInfo      *serverInfo    `json:"serverInfo,omitempty"`
}

type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// MCP tools/list types

type toolsListResult struct {
	Tools      []mcpTool `json:"tools"`
	NextCursor string    `json:"nextCursor,omitempty"`
}

type mcpTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

// MCP tools/call types

type toolsCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

type toolsCallResult struct {
	Content []toolContent `json:"content"`
	IsError bool          `json:"isError"`
}

type toolContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// JSON schema types for parsing inputSchema

type jsonSchema struct {
	Type       string                `json:"type"`
	Properties map[string]jsonSchema `json:"properties,omitempty"`
	Required   []string              `json:"required,omitempty"`
	Items      *jsonSchema           `json:"items,omitempty"`
	Format     string                `json:"format,omitempty"`
	Enum       []any                 `json:"enum,omitempty"`
}

// Request builders

func buildInitializeRequest() []byte {
	req := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
		Params: initializeParams{
			ProtocolVersion: "2025-03-26",
			Capabilities:    map[string]any{},
			ClientInfo: clientInfo{
				Name:    "vigolium-scanner",
				Version: "1.0.0",
			},
		},
	}
	data, _ := json.Marshal(req)
	return data
}

func buildInitializedNotification() []byte {
	n := jsonRPCNotification{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}
	data, _ := json.Marshal(n)
	return data
}

func buildToolsListRequest() []byte {
	req := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}
	data, _ := json.Marshal(req)
	return data
}

func buildToolsCallRequest(id int, toolName string, args map[string]any) []byte {
	req := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      id,
		Method:  "tools/call",
		Params: toolsCallParams{
			Name:      toolName,
			Arguments: args,
		},
	}
	data, _ := json.Marshal(req)
	return data
}

// Response parsers

func parseInitializeResponse(body string) (*initializeResult, error) {
	body = extractJSONFromSSE(body)

	var resp jsonRPCResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("JSON-RPC error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	if resp.Result == nil {
		return nil, fmt.Errorf("no result in response")
	}

	var result initializeResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func parseToolsListResponse(body string) (*toolsListResult, error) {
	body = extractJSONFromSSE(body)

	var resp jsonRPCResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("JSON-RPC error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	if resp.Result == nil {
		return nil, fmt.Errorf("no result in response")
	}

	var result toolsListResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func parseToolsCallResponse(body string) (*toolsCallResult, error) {
	body = extractJSONFromSSE(body)

	var resp jsonRPCResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("JSON-RPC error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	if resp.Result == nil {
		return nil, fmt.Errorf("no result in response")
	}

	var result toolsCallResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// extractJSONFromSSE handles SSE-wrapped responses by extracting the JSON data line.
func extractJSONFromSSE(body string) string {
	body = strings.TrimSpace(body)
	if len(body) == 0 {
		return body
	}
	// If it looks like normal JSON, return as-is
	if body[0] == '{' || body[0] == '[' {
		return body
	}
	// Parse SSE: look for data: lines containing JSON
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "data:") {
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if len(data) > 0 && (data[0] == '{' || data[0] == '[') {
				return data
			}
		}
	}
	return body
}
