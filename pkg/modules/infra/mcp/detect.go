package mcp

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// DetectionFlags captures which MCP-shaped indicators were found in an HTTP
// transaction. A non-empty flags set is enough to flag the endpoint as MCP.
type DetectionFlags struct {
	HasSessionHeader bool
	HasJSONRPC       bool
	HasSSEStream     bool
	MatchedMethods   []string
	HasServerInfo    bool
	HasMCPPath       bool
	SessionID        string
}

// Any reports whether the flags carry at least one strong indicator.
func (f DetectionFlags) Any() bool {
	return f.HasSessionHeader || f.HasJSONRPC || f.HasSSEStream || len(f.MatchedMethods) > 0 ||
		f.HasServerInfo || f.HasMCPPath
}

// Strong reports whether at least one high-confidence indicator was found.
// "Strong" means we're confident this is an MCP endpoint, not just a
// JSON-RPC endpoint that happens to contain "jsonrpc".
func (f DetectionFlags) Strong() bool {
	if f.HasSessionHeader {
		return true
	}
	if len(f.MatchedMethods) > 0 {
		return true
	}
	return f.HasJSONRPC && (f.HasMCPPath || f.HasSSEStream || f.HasServerInfo)
}

// Detect inspects a request/response pair for MCP indicators. The request and
// response may be nil; missing pieces simply produce fewer flags.
func Detect(ctx *httpmsg.HttpRequestResponse) DetectionFlags {
	flags := DetectionFlags{}
	if ctx == nil {
		return flags
	}

	// Path heuristic
	if urlx, err := ctx.URL(); err == nil {
		p := strings.ToLower(urlx.Path)
		for _, mp := range CommonPaths {
			if p == mp || strings.HasPrefix(p, mp+"/") {
				flags.HasMCPPath = true
				break
			}
		}
	}

	// Headers
	if req := ctx.Request(); req != nil {
		if v := req.Header("Mcp-Session-Id"); v != "" {
			flags.HasSessionHeader = true
			flags.SessionID = v
		}
	}

	resp := ctx.Response()
	if resp == nil {
		return flags
	}

	for _, h := range resp.Headers() {
		name := strings.ToLower(h.Name)
		if name == "mcp-session-id" && h.Value != "" {
			flags.HasSessionHeader = true
			flags.SessionID = h.Value
		}
		if name == "content-type" && strings.Contains(strings.ToLower(h.Value), "text/event-stream") {
			flags.HasSSEStream = true
		}
	}

	body := resp.BodyToString()
	if body == "" {
		return flags
	}

	flags = inspectBody(body, flags)
	return flags
}

// DetectFromParts is the same as Detect but works directly on raw pieces, used
// by the jsext API where the caller may not have a full HttpRequestResponse.
func DetectFromParts(reqHeaders map[string]string, urlPath string, respHeaders map[string]string, respBody string) DetectionFlags {
	flags := DetectionFlags{}
	pl := strings.ToLower(urlPath)
	for _, mp := range CommonPaths {
		if pl == mp || strings.HasPrefix(pl, mp+"/") {
			flags.HasMCPPath = true
			break
		}
	}
	for k, v := range reqHeaders {
		if strings.EqualFold(k, "mcp-session-id") && v != "" {
			flags.HasSessionHeader = true
			flags.SessionID = v
		}
	}
	for k, v := range respHeaders {
		lk := strings.ToLower(k)
		if lk == "mcp-session-id" && v != "" {
			flags.HasSessionHeader = true
			flags.SessionID = v
		}
		if lk == "content-type" && strings.Contains(strings.ToLower(v), "text/event-stream") {
			flags.HasSSEStream = true
		}
	}
	flags = inspectBody(respBody, flags)
	return flags
}

func inspectBody(body string, flags DetectionFlags) DetectionFlags {
	if body == "" {
		return flags
	}
	if strings.Contains(body, `"jsonrpc"`) && strings.Contains(body, `"2.0"`) {
		flags.HasJSONRPC = true
	}
	for _, m := range KnownMethods {
		needle := `"` + m + `"`
		if strings.Contains(body, needle) {
			flags.MatchedMethods = append(flags.MatchedMethods, m)
		}
	}
	if strings.Contains(body, `"serverInfo"`) {
		flags.HasServerInfo = true
	}
	return flags
}
