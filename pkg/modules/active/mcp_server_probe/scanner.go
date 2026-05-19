package mcp_server_probe

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	mcpinfra "github.com/vigolium/vigolium/pkg/modules/infra/mcp"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeHost,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("mcp_server_probe"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return ctx.Response() != nil
}

// mcpEndpoint holds state for a discovered MCP endpoint.
type mcpEndpoint struct {
	path       string
	transport  string // "streamable-http" or "sse"
	serverInfo *mcpinfra.ServerInfo
	sessionID  string
	tools      []mcpinfra.Tool
	resources  []mcpinfra.Resource
	prompts    []mcpinfra.Prompt
	callables  []toolCallEvidence
}

type toolCallEvidence struct {
	toolName string
	response string
}

func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	var endpoints []mcpEndpoint

	for _, path := range mcpinfra.CommonPaths {
		if ep := m.tryStreamableHTTP(ctx, httpClient, path); ep != nil {
			m.enumerateAndInvoke(ctx, httpClient, ep)
			endpoints = append(endpoints, *ep)
			continue
		}
		if ep := m.trySSETransport(ctx, httpClient, path); ep != nil {
			m.enumerateAndInvoke(ctx, httpClient, ep)
			endpoints = append(endpoints, *ep)
		}
	}

	if len(endpoints) == 0 {
		return nil, nil
	}

	return m.buildResults(ctx, endpoints), nil
}

func (m *Module) tryStreamableHTTP(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	path string,
) *mcpEndpoint {
	client := mcpinfra.NewClient(ctx, httpClient, path)
	initResult, err := client.Initialize()
	if err != nil {
		return nil
	}
	_ = client.SendInitializedNotification()

	return &mcpEndpoint{
		path:       path,
		transport:  "streamable-http",
		serverInfo: initResult.ServerInfo,
		sessionID:  client.SessionID(),
	}
}

func (m *Module) trySSETransport(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	path string,
) *mcpEndpoint {
	client := mcpinfra.NewClient(ctx, httpClient, path)
	resp, err := client.Get(path, "text/event-stream")
	if err != nil || resp == nil {
		return nil
	}

	var body string
	if resp.Response() != nil {
		body = resp.Body().String()
	}
	isSSE := mcpinfra.HasSSEContentType(resp)
	resp.Close()

	if !isSSE {
		return nil
	}

	hasEndpointEvent := false
	hasJSONRPC := false
	for _, ev := range mcpinfra.ParseSSE(body) {
		if ev.Event == "endpoint" || ev.Data != "" {
			hasEndpointEvent = hasEndpointEvent || ev.Event == "endpoint"
			if !hasJSONRPC {
				if d := ev.Data; d != "" && (containsRune(d, '{') || containsRune(d, '[')) {
					hasJSONRPC = true
				}
			}
		}
	}
	if !hasEndpointEvent && !hasJSONRPC {
		return nil
	}

	if msgPath := mcpinfra.ExtractEndpointFromSSE(body); msgPath != "" {
		client.SetPath(msgPath)
	}

	initResult, err := client.Initialize()
	if err != nil {
		return &mcpEndpoint{path: path, transport: "sse"}
	}

	return &mcpEndpoint{
		path:       path,
		transport:  "sse",
		serverInfo: initResult.ServerInfo,
		sessionID:  client.SessionID(),
	}
}

// enumerateAndInvoke performs tools/list (and resources/list, prompts/list)
// and then invokes the first few tools to verify unauthenticated callability.
func (m *Module) enumerateAndInvoke(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ep *mcpEndpoint,
) {
	client := mcpinfra.NewClient(ctx, httpClient, ep.path)
	if ep.sessionID != "" {
		client.SetSessionID(ep.sessionID)
	}

	if tools, err := client.ListTools(); err == nil && tools != nil {
		ep.tools = tools.Tools
	}
	if resources, err := client.ListResources(); err == nil && resources != nil {
		ep.resources = resources.Resources
	}
	if prompts, err := client.ListPrompts(); err == nil && prompts != nil {
		ep.prompts = prompts.Prompts
	}

	maxTools := 10
	if len(ep.tools) < maxTools {
		maxTools = len(ep.tools)
	}
	for i := 0; i < maxTools; i++ {
		tool := ep.tools[i]
		args := mcpinfra.GenerateSampleArgs(tool.InputSchema)
		callResult, _, err := client.CallTool(100+i, tool.Name, args)
		if err != nil || callResult == nil {
			continue
		}
		var respText string
		for _, c := range callResult.Content {
			if c.Type == "text" && c.Text != "" {
				respText = c.Text
				break
			}
		}
		ep.callables = append(ep.callables, toolCallEvidence{
			toolName: tool.Name,
			response: truncate(respText, 200),
		})
	}
}

// buildResults creates ResultEvent findings from discovered endpoints.
func (m *Module) buildResults(ctx *httpmsg.HttpRequestResponse, endpoints []mcpEndpoint) []*output.ResultEvent {
	urlx, _ := ctx.URL()
	baseURL := urlx.Scheme + "://" + urlx.Host

	highestSev := severity.Info
	var evidence []string
	var toolNames []string
	var callableNames []string

	for _, ep := range endpoints {
		evidence = append(evidence, fmt.Sprintf("Endpoint: %s (transport: %s)", ep.path, ep.transport))
		if ep.serverInfo != nil {
			evidence = append(evidence, fmt.Sprintf("Server: %s %s", ep.serverInfo.Name, ep.serverInfo.Version))
		}
		if ep.sessionID != "" {
			evidence = append(evidence, fmt.Sprintf("Session ID: %s", ep.sessionID))
		}

		if (len(ep.tools) > 0 || len(ep.resources) > 0 || len(ep.prompts) > 0) && highestSev < severity.Medium {
			highestSev = severity.Medium
		}
		for _, t := range ep.tools {
			desc := t.Description
			if len(desc) > 80 {
				desc = desc[:80] + "..."
			}
			entry := fmt.Sprintf("Tool: %s", t.Name)
			if desc != "" {
				entry += fmt.Sprintf(" - %s", desc)
			}
			toolNames = append(toolNames, entry)
		}
		for _, r := range ep.resources {
			toolNames = append(toolNames, fmt.Sprintf("Resource: %s (%s)", r.Name, r.URI))
		}
		for _, p := range ep.prompts {
			toolNames = append(toolNames, fmt.Sprintf("Prompt: %s", p.Name))
		}

		if len(ep.callables) > 0 && highestSev < severity.High {
			highestSev = severity.High
		}
		for _, c := range ep.callables {
			callableNames = append(callableNames, fmt.Sprintf("Callable: %s -> %s", c.toolName, c.response))
		}
	}

	confidence := severity.Firm
	if highestSev >= severity.High {
		confidence = severity.Certain
	}

	extracted := append(evidence, toolNames...)
	extracted = append(extracted, callableNames...)

	name := "MCP Server Exposed"
	if highestSev >= severity.High {
		name = "MCP Server Exposed - Unauthenticated Tool Invocation"
	} else if highestSev >= severity.Medium {
		name = "MCP Server Exposed - Unauthenticated Tool Enumeration"
	}

	desc := fmt.Sprintf(
		"MCP (Model Context Protocol) server detected at %s. %d endpoint(s) found, %d capability item(s) enumerated, %d tool(s) callable without authentication.",
		urlx.Host, len(endpoints), len(toolNames), len(callableNames),
	)

	return []*output.ResultEvent{
		{
			Host:             urlx.Host,
			URL:              baseURL,
			Matched:          baseURL,
			MatcherStatus:    true,
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        name,
				Description: desc,
				Severity:    highestSev,
				Confidence:  confidence,
				Tags:        []string{"mcp", "api-security", "misconfiguration"},
				Reference: []string{
					"https://modelcontextprotocol.io/specification/2025-11-25",
					"https://modelcontextprotocol.io/specification/2025-11-25/server/tools",
				},
			},
		},
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}
