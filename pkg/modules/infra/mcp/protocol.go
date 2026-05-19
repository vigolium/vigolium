// Package mcp provides shared helpers for Model Context Protocol (MCP) scanner
// modules and the vigolium.mcp jsext API. It owns the JSON-RPC 2.0 envelope
// types, request builders, response parsers, and the SSE-extraction logic
// that all MCP-aware modules need.
package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ProtocolVersion is the MCP protocol version vigolium negotiates by default.
const ProtocolVersion = "2025-03-26"

// ClientName/ClientVersion identify vigolium during the initialize handshake.
const (
	ClientName    = "vigolium-scanner"
	ClientVersion = "1.0.0"
)

// Default JSON-RPC IDs used by built-in helpers.
const (
	IDInitialize       = 1
	IDToolsList        = 2
	IDResourcesList    = 3
	IDResourceTemplate = 4
	IDPromptsList      = 5
	IDComplete         = 6
)

// KnownMethods is the canonical set of MCP JSON-RPC methods used for passive
// detection and basic request shaping.
var KnownMethods = []string{
	"initialize",
	"notifications/initialized",
	"tools/list",
	"tools/call",
	"resources/list",
	"resources/read",
	"resources/templates/list",
	"prompts/list",
	"prompts/get",
	"completion/complete",
	"logging/setLevel",
	"sampling/createMessage",
	"roots/list",
	"ping",
}

// CommonPaths are URL paths frequently used by MCP server implementations.
// Used by probe modules to enumerate likely endpoints.
var CommonPaths = []string{
	"/mcp",
	"/sse",
	"/messages",
	"/rpc",
	"/api/mcp",
	"/v1/mcp",
}

// JSONRPC envelope ----------------------------------------------------------

type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int         `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type JSONRPCNotification struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Initialize ----------------------------------------------------------------

type InitializeParams struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ClientInfo      ClientInfo     `json:"clientInfo"`
}

type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type InitializeResult struct {
	ProtocolVersion string         `json:"protocolVersion"`
	Capabilities    map[string]any `json:"capabilities"`
	ServerInfo      *ServerInfo    `json:"serverInfo,omitempty"`
	Instructions    string         `json:"instructions,omitempty"`
}

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Tools ---------------------------------------------------------------------

type ToolsListResult struct {
	Tools      []Tool `json:"tools"`
	NextCursor string `json:"nextCursor,omitempty"`
}

type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

type ToolsCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

type ToolsCallResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError"`
}

type ContentBlock struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
}

// Resources -----------------------------------------------------------------

type ResourcesListResult struct {
	Resources  []Resource `json:"resources"`
	NextCursor string     `json:"nextCursor,omitempty"`
}

type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type ResourceTemplatesListResult struct {
	ResourceTemplates []ResourceTemplate `json:"resourceTemplates"`
}

type ResourceTemplate struct {
	URITemplate string `json:"uriTemplate"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type ResourcesReadParams struct {
	URI string `json:"uri"`
}

type ResourcesReadResult struct {
	Contents []ResourceContent `json:"contents"`
}

type ResourceContent struct {
	URI      string `json:"uri,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"`
}

// Prompts -------------------------------------------------------------------

type PromptsListResult struct {
	Prompts    []Prompt `json:"prompts"`
	NextCursor string   `json:"nextCursor,omitempty"`
}

type Prompt struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

type PromptsGetParams struct {
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

type PromptsGetResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

type PromptMessage struct {
	Role    string         `json:"role"`
	Content map[string]any `json:"content"`
}

// Completion ----------------------------------------------------------------

type CompleteParams struct {
	Ref      CompleteRef      `json:"ref"`
	Argument CompleteArgument `json:"argument"`
}

type CompleteRef struct {
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
	URI  string `json:"uri,omitempty"`
}

type CompleteArgument struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type CompleteResult struct {
	Completion CompletionPayload `json:"completion"`
}

type CompletionPayload struct {
	Values  []string `json:"values"`
	Total   int      `json:"total,omitempty"`
	HasMore bool     `json:"hasMore,omitempty"`
}

// JSON Schema (subset) ------------------------------------------------------

type JSONSchema struct {
	Type       string                `json:"type"`
	Properties map[string]JSONSchema `json:"properties,omitempty"`
	Required   []string              `json:"required,omitempty"`
	Items      *JSONSchema           `json:"items,omitempty"`
	Format     string                `json:"format,omitempty"`
	Enum       []any                 `json:"enum,omitempty"`
}

// JSONSchemaProps is a convenience alias used when only the parameter list is
// of interest.
type JSONSchemaProps = map[string]JSONSchema

// Builders ------------------------------------------------------------------

func MarshalRequest(id int, method string, params interface{}) []byte {
	req := JSONRPCRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params}
	data, _ := json.Marshal(req)
	return data
}

func MarshalNotification(method string, params interface{}) []byte {
	n := JSONRPCNotification{JSONRPC: "2.0", Method: method, Params: params}
	data, _ := json.Marshal(n)
	return data
}

func BuildInitializeRequest() []byte {
	return MarshalRequest(IDInitialize, "initialize", InitializeParams{
		ProtocolVersion: ProtocolVersion,
		Capabilities:    map[string]any{},
		ClientInfo:      ClientInfo{Name: ClientName, Version: ClientVersion},
	})
}

func BuildInitializedNotification() []byte {
	return MarshalNotification("notifications/initialized", nil)
}

func BuildToolsListRequest() []byte {
	return MarshalRequest(IDToolsList, "tools/list", nil)
}

func BuildToolsCallRequest(id int, name string, args map[string]any) []byte {
	return MarshalRequest(id, "tools/call", ToolsCallParams{Name: name, Arguments: args})
}

func BuildResourcesListRequest() []byte {
	return MarshalRequest(IDResourcesList, "resources/list", nil)
}

func BuildResourceTemplatesListRequest() []byte {
	return MarshalRequest(IDResourceTemplate, "resources/templates/list", nil)
}

func BuildResourcesReadRequest(id int, uri string) []byte {
	return MarshalRequest(id, "resources/read", ResourcesReadParams{URI: uri})
}

func BuildPromptsListRequest() []byte {
	return MarshalRequest(IDPromptsList, "prompts/list", nil)
}

func BuildPromptsGetRequest(id int, name string, args map[string]string) []byte {
	return MarshalRequest(id, "prompts/get", PromptsGetParams{Name: name, Arguments: args})
}

func BuildCompletePromptRequest(id int, promptName, argName, partial string) []byte {
	return MarshalRequest(id, "completion/complete", CompleteParams{
		Ref:      CompleteRef{Type: "ref/prompt", Name: promptName},
		Argument: CompleteArgument{Name: argName, Value: partial},
	})
}

func BuildCompleteResourceRequest(id int, uri, argName, partial string) []byte {
	return MarshalRequest(id, "completion/complete", CompleteParams{
		Ref:      CompleteRef{Type: "ref/resource", URI: uri},
		Argument: CompleteArgument{Name: argName, Value: partial},
	})
}

// Parsers -------------------------------------------------------------------

// ParseResponse decodes a single JSON-RPC response, transparently extracting
// the JSON envelope from an SSE-wrapped body when needed.
func ParseResponse(body string) (*JSONRPCResponse, error) {
	body = ExtractJSONFromSSE(body)
	var resp JSONRPCResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ParseInitializeResponse parses the result of an `initialize` call.
func ParseInitializeResponse(body string) (*InitializeResult, error) {
	resp, err := ParseResponse(body)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("JSON-RPC error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	if len(resp.Result) == 0 {
		return nil, fmt.Errorf("no result in response")
	}
	var out InitializeResult
	if err := json.Unmarshal(resp.Result, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func ParseToolsListResponse(body string) (*ToolsListResult, error) {
	return parseTyped[ToolsListResult](body)
}

func ParseToolsCallResponse(body string) (*ToolsCallResult, error) {
	return parseTyped[ToolsCallResult](body)
}

func ParseResourcesListResponse(body string) (*ResourcesListResult, error) {
	return parseTyped[ResourcesListResult](body)
}

func ParseResourceTemplatesListResponse(body string) (*ResourceTemplatesListResult, error) {
	return parseTyped[ResourceTemplatesListResult](body)
}

func ParseResourcesReadResponse(body string) (*ResourcesReadResult, error) {
	return parseTyped[ResourcesReadResult](body)
}

func ParsePromptsListResponse(body string) (*PromptsListResult, error) {
	return parseTyped[PromptsListResult](body)
}

func ParsePromptsGetResponse(body string) (*PromptsGetResult, error) {
	return parseTyped[PromptsGetResult](body)
}

func ParseCompleteResponse(body string) (*CompleteResult, error) {
	return parseTyped[CompleteResult](body)
}

func parseTyped[T any](body string) (*T, error) {
	resp, err := ParseResponse(body)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("JSON-RPC error %d: %s", resp.Error.Code, resp.Error.Message)
	}
	if len(resp.Result) == 0 {
		return nil, fmt.Errorf("no result in response")
	}
	var out T
	if err := json.Unmarshal(resp.Result, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SSE handling --------------------------------------------------------------

// SSEEvent represents a single Server-Sent Event line group.
type SSEEvent struct {
	Event string
	ID    string
	Data  string
}

// ParseSSE parses a body containing one or more SSE event blocks. It is
// tolerant of stray whitespace and missing trailing newlines.
func ParseSSE(body string) []SSEEvent {
	var events []SSEEvent
	var current SSEEvent
	flush := func() {
		if current.Event != "" || current.Data != "" || current.ID != "" {
			events = append(events, current)
		}
		current = SSEEvent{}
	}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			flush()
			continue
		}
		switch {
		case strings.HasPrefix(line, "event:"):
			current.Event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "id:"):
			current.ID = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
		case strings.HasPrefix(line, "data:"):
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if current.Data == "" {
				current.Data = data
			} else {
				current.Data += "\n" + data
			}
		}
	}
	flush()
	return events
}

// ExtractJSONFromSSE returns either the body unchanged (if it looks like
// JSON already) or the first SSE `data:` line that looks like JSON.
func ExtractJSONFromSSE(body string) string {
	body = strings.TrimSpace(body)
	if len(body) == 0 {
		return body
	}
	if body[0] == '{' || body[0] == '[' {
		return body
	}
	for _, ev := range ParseSSE(body) {
		d := strings.TrimSpace(ev.Data)
		if len(d) > 0 && (d[0] == '{' || d[0] == '[') {
			return d
		}
	}
	return body
}

// ExtractEndpointFromSSE parses an SSE stream looking for the legacy
// "endpoint" event used by the original SSE transport, returning the message
// path/URL the client should POST to. Returns "" when nothing is found.
func ExtractEndpointFromSSE(body string) string {
	for _, ev := range ParseSSE(body) {
		data := strings.TrimSpace(ev.Data)
		if data == "" {
			continue
		}
		if strings.HasPrefix(data, "/") {
			return data
		}
		if data[0] == '{' && (strings.Contains(data, `"url"`) || strings.Contains(data, `"endpoint"`)) {
			var obj map[string]any
			if err := json.Unmarshal([]byte(data), &obj); err == nil {
				for _, k := range []string{"url", "endpoint"} {
					if v, ok := obj[k].(string); ok && v != "" {
						return v
					}
				}
			}
		}
	}
	return ""
}
