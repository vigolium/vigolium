package mcp_endpoint_detect

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	mcpinfra "github.com/vigolium/vigolium/pkg/modules/infra/mcp"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

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

	flags := mcpinfra.Detect(ctx)
	if !flags.Any() {
		return nil, nil
	}

	var indicators []string
	if flags.HasMCPPath {
		indicators = append(indicators, fmt.Sprintf("MCP endpoint path: %s", urlx.Path))
	}
	if flags.HasSessionHeader {
		indicators = append(indicators, fmt.Sprintf("Mcp-Session-Id header: %s", flags.SessionID))
	}
	if flags.HasJSONRPC {
		indicators = append(indicators, "JSON-RPC 2.0 envelope")
	}
	for _, mth := range flags.MatchedMethods {
		indicators = append(indicators, fmt.Sprintf("JSON-RPC method: %q", mth))
	}
	if flags.HasServerInfo {
		body := ctx.Response().BodyToString()
		if idx := strings.Index(body, `"serverInfo"`); idx >= 0 {
			indicators = append(indicators, fmt.Sprintf("Server info: %s", safeSubstring(body, idx, 200)))
		}
	}
	if flags.HasSSEStream {
		indicators = append(indicators, "SSE stream with MCP event data")
	}

	// Tool name extraction (only when this looks like a tools/list response)
	body := ctx.Response().BodyToString()
	if strings.Contains(body, `"tools"`) && (flags.HasJSONRPC || flags.HasMCPPath) {
		if names := extractToolNames(body); len(names) > 0 {
			indicators = append(indicators, fmt.Sprintf("Tools exposed: %s", strings.Join(names, ", ")))
		}
	}

	if len(indicators) == 0 {
		return nil, nil
	}

	sev := severity.Info
	if flags.Strong() {
		sev = severity.Medium
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
				Severity:    sev,
				Confidence:  severity.Firm,
				Tags:        []string{"mcp", "api-security"},
				Reference:   []string{"https://modelcontextprotocol.io/specification/2025-11-25"},
			},
		},
	}, nil
}

// extractToolNames pulls a few "name" string values out of a tools/list-shaped
// response without parsing the whole envelope (which may be SSE-wrapped).
func extractToolNames(body string) []string {
	var names []string
	search := body
	for i := 0; i < 50; i++ {
		idx := strings.Index(search, `"name"`)
		if idx < 0 {
			break
		}
		rest := search[idx+6:]
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
