package vigtool

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/tool"
)

const (
	defaultBurpBridgeURL = "http://127.0.0.1:9009"
	maxBridgeResponse    = 2 * 1024 * 1024
)

var burpBridgeHTTPClient = &http.Client{Timeout: 30 * time.Second}

func NewSearchBurpItemsTool(ctx *SessionsContext) tool.Tool {
	return &searchBurpItemsTool{ctx: ctx}
}

type searchBurpItemsTool struct{ ctx *SessionsContext }

func (*searchBurpItemsTool) Name() string     { return "search_burp_items" }
func (*searchBurpItemsTool) Label() string    { return "Search live Burp traffic" }
func (*searchBurpItemsTool) Category() string { return tool.CategoryVigolium }
func (*searchBurpItemsTool) IsReadOnly() bool { return true }
func (*searchBurpItemsTool) Description() string {
	return "Search the live Burp Target site map or Proxy history through an operator-enabled read-only bridge listener. Returns compact summaries and temporary refs; call inspect_burp_item for raw messages."
}
func (*searchBurpItemsTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"location":      map[string]any{"type": "string", "enum": []string{"sitemap", "proxy_history"}},
			"host":          map[string]any{"type": "string"},
			"methods":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
			"path":          map[string]any{"type": "string"},
			"status":        map[string]any{"type": "array", "items": map[string]any{"type": "integer"}},
			"mime_type":     map[string]any{"type": "string"},
			"text":          map[string]any{"type": "string"},
			"in_scope_only": map[string]any{"type": "boolean"},
			"limit":         map[string]any{"type": "integer", "minimum": 1, "maximum": 100},
		},
	}
}
func (t *searchBurpItemsTool) Execute(ctx context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	return executeBurpCommand(ctx, t.ctx, "search_burp_items", args)
}

func NewInspectBurpItemTool(ctx *SessionsContext) tool.Tool {
	return &inspectBurpItemTool{ctx: ctx}
}

type inspectBurpItemTool struct{ ctx *SessionsContext }

func (*inspectBurpItemTool) Name() string     { return "inspect_burp_item" }
func (*inspectBurpItemTool) Label() string    { return "Inspect live Burp item" }
func (*inspectBurpItemTool) Category() string { return tool.CategoryVigolium }
func (*inspectBurpItemTool) IsReadOnly() bool { return true }
func (*inspectBurpItemTool) Description() string {
	return "Inspect one temporary ref returned by search_burp_items. Returns size-capped raw request and response text without modifying Burp."
}
func (*inspectBurpItemTool) Schema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"ref":       map[string]any{"type": "string"},
			"max_bytes": map[string]any{"type": "integer", "minimum": 1024, "maximum": 65536},
		},
		"required": []string{"ref"},
	}
}
func (t *inspectBurpItemTool) Execute(ctx context.Context, args map[string]any, _ tool.UpdateFn) (tool.Result, error) {
	return executeBurpCommand(ctx, t.ctx, "inspect_burp_item", args)
}

func executeBurpCommand(ctx context.Context, _ *SessionsContext, commandType string, args map[string]any) (tool.Result, error) {
	baseURL, err := burpBridgeBaseURL()
	if err != nil {
		return bridgeToolError(commandType, err), nil
	}
	endpoint := ""
	switch commandType {
	case "search_burp_items":
		endpoint = "/api/burp-bridge/search"
	case "inspect_burp_item":
		endpoint = "/api/burp-bridge/inspect"
	default:
		return bridgeToolError(commandType, fmt.Errorf("unsupported command")), nil
	}

	payload, err := json.Marshal(args)
	if err != nil {
		return bridgeToolError(commandType, err), nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+endpoint, bytes.NewReader(payload))
	if err != nil {
		return bridgeToolError(commandType, err), nil
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := burpBridgeHTTPClient.Do(req)
	if err != nil {
		return bridgeToolError(commandType, fmt.Errorf("burp bridge at %s is unavailable: %w", baseURL, err)), nil
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBridgeResponse+1))
	if err != nil {
		return bridgeToolError(commandType, err), nil
	}
	if len(body) > maxBridgeResponse {
		return bridgeToolError(commandType, fmt.Errorf("response exceeds 2 MiB")), nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = resp.Status
		}
		return bridgeToolError(commandType, fmt.Errorf("HTTP %d: %s", resp.StatusCode, message)), nil
	}
	if !json.Valid(body) {
		return bridgeToolError(commandType, fmt.Errorf("bridge returned invalid JSON")), nil
	}
	return tool.Result{Content: string(body)}, nil
}

func burpBridgeBaseURL() (string, error) {
	value := strings.TrimSpace(os.Getenv("VIGOLIUM_BURP_BRIDGE_URL"))
	if value == "" {
		value = defaultBurpBridgeURL
	}
	value = strings.TrimRight(value, "/")
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.Hostname() == "" || parsed.Port() == "" {
		return "", fmt.Errorf("VIGOLIUM_BURP_BRIDGE_URL must be an http:// loopback URL with a port")
	}
	host := strings.ToLower(parsed.Hostname())
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return "", fmt.Errorf("VIGOLIUM_BURP_BRIDGE_URL must use a loopback host")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", fmt.Errorf("VIGOLIUM_BURP_BRIDGE_URL must not include a path")
	}
	return value, nil
}

func bridgeToolError(commandType string, err error) tool.Result {
	return tool.Result{Content: fmt.Sprintf("%s: %v", commandType, err), IsError: true}
}
