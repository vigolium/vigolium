package mcp_endpoint_detect

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/pkg/errors"
)

var mcpMethods = []string{
	`"initialize"`,
	`"tools/list"`,
	`"tools/call"`,
	`"resources/list"`,
	`"resources/read"`,
	`"prompts/list"`,
	`"prompts/get"`,
	`"notifications/initialized"`,
}

var mcpPaths = []string{
	"/mcp", "/sse", "/messages", "/rpc",
	"/api/mcp", "/v1/mcp",
}

type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("passive_mcp_endpoint_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if ctx.Response() == nil {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := urlx.Host + urlx.Path
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	if len(body) == 0 {
		return nil, nil
	}

	var indicators []string

	// Check if the request path matches a known MCP endpoint
	pathLower := strings.ToLower(urlx.Path)
	for _, p := range mcpPaths {
		if pathLower == p || strings.HasPrefix(pathLower, p+"/") {
			indicators = append(indicators, fmt.Sprintf("MCP endpoint path: %s", urlx.Path))
			break
		}
	}

	// Check for JSON-RPC 2.0 structure with MCP methods
	if strings.Contains(body, `"jsonrpc"`) && strings.Contains(body, `"2.0"`) {
		for _, method := range mcpMethods {
			if strings.Contains(body, method) {
				indicators = append(indicators, fmt.Sprintf("JSON-RPC method: %s", method))
			}
		}

		// Extract server info if present
		if idx := strings.Index(body, `"serverInfo"`); idx >= 0 {
			snippet := safeSubstring(body, idx, 200)
			indicators = append(indicators, fmt.Sprintf("Server info: %s", snippet))
		}

		// Extract tool names from tools/list responses
		if strings.Contains(body, `"tools"`) {
			toolNames := extractToolNames(body)
			if len(toolNames) > 0 {
				indicators = append(indicators, fmt.Sprintf("Tools exposed: %s", strings.Join(toolNames, ", ")))
			}
		}
	}

	// Check for SSE content type with MCP data
	ct := ""
	for _, h := range ctx.Response().Headers() {
		nameLower := strings.ToLower(h.Name)
		if nameLower == "content-type" {
			ct = strings.ToLower(h.Value)
		}
		if nameLower == "mcp-session-id" {
			indicators = append(indicators, fmt.Sprintf("Mcp-Session-Id header: %s", h.Value))
		}
	}

	if strings.Contains(ct, "text/event-stream") {
		if strings.Contains(body, "jsonrpc") || strings.Contains(body, "endpoint") {
			indicators = append(indicators, "SSE stream with MCP event data")
		}
	}

	if len(indicators) == 0 {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: indicators,
			MatcherStatus:    true,
			Info: output.Info{
				Name:        "MCP Server Detected",
				Description: fmt.Sprintf("MCP (Model Context Protocol) server detected at %s. Indicators: %s", urlx.Host, strings.Join(indicators, "; ")),
				Severity:    severity.Medium,
				Confidence:  severity.Firm,
				Tags:        []string{"mcp", "api-security"},
				Reference:   []string{"https://modelcontextprotocol.io/specification/2025-11-25"},
			},
		},
	}, nil
}

func extractToolNames(body string) []string {
	var names []string
	search := body
	for i := 0; i < 50; i++ {
		idx := strings.Index(search, `"name"`)
		if idx < 0 {
			break
		}
		// Move past `"name"`
		rest := search[idx+6:]
		// Find the colon then the opening quote
		colonIdx := strings.Index(rest, `"`)
		if colonIdx < 0 || colonIdx > 10 {
			search = rest
			continue
		}
		rest = rest[colonIdx+1:]
		endIdx := strings.Index(rest, `"`)
		if endIdx < 0 || endIdx > 100 {
			search = rest
			continue
		}
		name := rest[:endIdx]
		if len(name) > 0 && !strings.Contains(name, " ") && len(name) < 64 {
			names = append(names, name)
		}
		search = rest[endIdx:]
	}
	return names
}

func safeSubstring(s string, start, maxLen int) string {
	if start >= len(s) {
		return ""
	}
	end := start + maxLen
	if end > len(s) {
		end = len(s)
	}
	snippet := s[start:end]
	if nl := strings.IndexByte(snippet, '\n'); nl >= 0 {
		snippet = snippet[:nl]
	}
	return strings.TrimSpace(snippet)
}
