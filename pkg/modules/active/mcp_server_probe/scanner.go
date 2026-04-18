package mcp_server_probe

import (
	"fmt"
	"strings"

	httpUtils "github.com/projectdiscovery/utils/http"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

var probePaths = []string{
	"/mcp",
	"/sse",
	"/messages",
	"/rpc",
	"/api/mcp",
	"/v1/mcp",
}

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
	serverInfo *serverInfo
	sessionID  string
	tools      []mcpTool
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

	for _, path := range probePaths {
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

// tryStreamableHTTP attempts MCP handshake via Streamable HTTP transport (POST).
func (m *Module) tryStreamableHTTP(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	path string,
) *mcpEndpoint {
	initBody := buildInitializeRequest()

	resp, _, err := m.sendPOST(ctx, httpClient, path, string(initBody),
		"application/json",
		"application/json, text/event-stream",
	)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Close()

	body := resp.Body().String()
	initResult, err := parseInitializeResponse(body)
	if err != nil {
		return nil
	}

	ep := &mcpEndpoint{
		path:       path,
		transport:  "streamable-http",
		serverInfo: initResult.ServerInfo,
	}

	// Extract Mcp-Session-Id if present
	if resp.Response() != nil {
		ep.sessionID = resp.Response().Header.Get("Mcp-Session-Id")
	}

	// Send initialized notification
	notifBody := buildInitializedNotification()
	notifResp, _, err := m.sendPOST(ctx, httpClient, path, string(notifBody),
		"application/json",
		"application/json, text/event-stream",
	)
	if err == nil && notifResp != nil {
		notifResp.Close()
	}

	return ep
}

// trySSETransport attempts MCP discovery via legacy SSE transport (GET then POST).
func (m *Module) trySSETransport(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	path string,
) *mcpEndpoint {
	// GET the SSE endpoint
	resp, _, err := m.sendGET(ctx, httpClient, path, "text/event-stream")
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Close()

	body := resp.Body().String()
	ct := ""
	if resp.Response() != nil {
		ct = strings.ToLower(resp.Response().Header.Get("Content-Type"))
	}

	if !strings.Contains(ct, "text/event-stream") {
		return nil
	}

	// Look for endpoint event or jsonrpc data in the SSE stream
	hasEndpointEvent := strings.Contains(body, "event:") && strings.Contains(body, "endpoint")
	hasJSONRPC := strings.Contains(body, "jsonrpc")

	if !hasEndpointEvent && !hasJSONRPC {
		return nil
	}

	// Try to find the message endpoint from SSE data
	messagePath := extractEndpointFromSSE(body)
	if messagePath == "" {
		messagePath = path
	}

	// Attempt initialize via POST to the discovered/same endpoint
	initBody := buildInitializeRequest()
	initResp, _, err := m.sendPOST(ctx, httpClient, messagePath, string(initBody),
		"application/json",
		"application/json, text/event-stream",
	)
	if err != nil || initResp == nil {
		// SSE endpoint exists but can't initialize — still worth reporting
		return &mcpEndpoint{
			path:      path,
			transport: "sse",
		}
	}
	defer initResp.Close()

	initResult, err := parseInitializeResponse(initResp.Body().String())
	if err != nil {
		return &mcpEndpoint{
			path:      path,
			transport: "sse",
		}
	}

	ep := &mcpEndpoint{
		path:       path,
		transport:  "sse",
		serverInfo: initResult.ServerInfo,
	}

	if initResp.Response() != nil {
		ep.sessionID = initResp.Response().Header.Get("Mcp-Session-Id")
	}

	return ep
}

// enumerateAndInvoke performs tools/list and then tools/call for each discovered tool.
func (m *Module) enumerateAndInvoke(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ep *mcpEndpoint,
) {
	// Phase 2: tools/list
	listBody := buildToolsListRequest()
	resp, _, err := m.sendPOST(ctx, httpClient, ep.path, string(listBody),
		"application/json",
		"application/json, text/event-stream",
	)
	if err != nil || resp == nil {
		return
	}

	body := resp.Body().String()
	resp.Close()

	toolsResult, err := parseToolsListResponse(body)
	if err != nil || len(toolsResult.Tools) == 0 {
		return
	}

	ep.tools = toolsResult.Tools

	// Phase 3: tools/call for each tool (limit to first 10 to avoid excessive requests)
	maxTools := 10
	if len(ep.tools) < maxTools {
		maxTools = len(ep.tools)
	}

	for i := 0; i < maxTools; i++ {
		tool := ep.tools[i]
		args := generateSampleArgs(tool.InputSchema)
		callBody := buildToolsCallRequest(100+i, tool.Name, args)

		callResp, _, err := m.sendPOST(ctx, httpClient, ep.path, string(callBody),
			"application/json",
			"application/json, text/event-stream",
		)
		if err != nil || callResp == nil {
			continue
		}

		callBodyStr := callResp.Body().String()
		callResp.Close()

		callResult, err := parseToolsCallResponse(callBodyStr)
		if err != nil {
			continue
		}

		// Even isError=true from the tool means the tool was invoked (auth passed)
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
// One finding per host with all endpoints aggregated.
func (m *Module) buildResults(ctx *httpmsg.HttpRequestResponse, endpoints []mcpEndpoint) []*output.ResultEvent {
	urlx, _ := ctx.URL()
	baseURL := urlx.Scheme + "://" + urlx.Host

	// Determine highest severity across all endpoints
	highestSev := severity.Info
	var evidence []string
	var toolNames []string
	var callableNames []string

	for _, ep := range endpoints {
		transport := ep.transport
		evidence = append(evidence, fmt.Sprintf("Endpoint: %s (transport: %s)", ep.path, transport))

		if ep.serverInfo != nil {
			evidence = append(evidence, fmt.Sprintf("Server: %s %s", ep.serverInfo.Name, ep.serverInfo.Version))
		}
		if ep.sessionID != "" {
			evidence = append(evidence, fmt.Sprintf("Session ID: %s", ep.sessionID))
		}

		if len(ep.tools) > 0 && highestSev < severity.Medium {
			highestSev = severity.Medium
		}
		for _, t := range ep.tools {
			desc := t.Description
			if len(desc) > 80 {
				desc = desc[:80] + "..."
			}
			entry := fmt.Sprintf("Tool: %s", t.Name)
			if desc != "" {
				entry += fmt.Sprintf(" — %s", desc)
			}
			toolNames = append(toolNames, entry)
		}

		if len(ep.callables) > 0 && highestSev < severity.High {
			highestSev = severity.High
		}
		for _, c := range ep.callables {
			callableNames = append(callableNames, fmt.Sprintf("Callable: %s → %s", c.toolName, c.response))
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
		name = "MCP Server Exposed — Unauthenticated Tool Invocation"
	} else if highestSev >= severity.Medium {
		name = "MCP Server Exposed — Unauthenticated Tool Enumeration"
	}

	desc := fmt.Sprintf(
		"MCP (Model Context Protocol) server detected at %s. %d endpoint(s) found, %d tool(s) enumerated, %d tool(s) callable without authentication.",
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

// HTTP helpers

func (m *Module) sendPOST(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	path, body, contentType, accept string,
) (*httpUtils.ResponseChain, []byte, error) {
	raw := ctx.Request().Raw()

	raw, err := httpmsg.SetMethod(raw, "POST")
	if err != nil {
		return nil, nil, err
	}
	raw, err = httpmsg.SetPath(raw, path)
	if err != nil {
		return nil, nil, err
	}
	raw, err = httpmsg.SetBodyString(raw, body)
	if err != nil {
		return nil, nil, err
	}
	raw, err = httpmsg.AddOrReplaceHeader(raw, "Content-Type", contentType)
	if err != nil {
		return nil, nil, err
	}
	raw, err = httpmsg.AddOrReplaceHeader(raw, "Accept", accept)
	if err != nil {
		return nil, nil, err
	}

	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return nil, nil, err
	}
	req = req.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		return nil, nil, err
	}

	if resp.Response() == nil {
		resp.Close()
		return nil, nil, fmt.Errorf("no response")
	}

	status := resp.Response().StatusCode
	if status < 200 || status >= 300 {
		resp.Close()
		return nil, nil, fmt.Errorf("HTTP %d", status)
	}

	return resp, raw, nil
}

func (m *Module) sendGET(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	path, accept string,
) (*httpUtils.ResponseChain, []byte, error) {
	raw := ctx.Request().Raw()

	raw, err := httpmsg.SetMethod(raw, "GET")
	if err != nil {
		return nil, nil, err
	}
	raw, err = httpmsg.SetPath(raw, path)
	if err != nil {
		return nil, nil, err
	}
	raw, err = httpmsg.AddOrReplaceHeader(raw, "Accept", accept)
	if err != nil {
		return nil, nil, err
	}
	// Clear body for GET requests
	raw, err = httpmsg.ClearBody(raw)
	if err != nil {
		return nil, nil, err
	}

	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return nil, nil, err
	}
	req = req.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		return nil, nil, err
	}

	return resp, raw, nil
}

// extractEndpointFromSSE parses SSE event data for an endpoint URL.
func extractEndpointFromSSE(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		// Could be a JSON object with url field or a plain URL/path
		if strings.HasPrefix(data, "/") {
			return data
		}
		if strings.Contains(data, `"url"`) || strings.Contains(data, `"endpoint"`) {
			// Simple extraction — look for a path value
			for _, part := range strings.Split(data, `"`) {
				if strings.HasPrefix(part, "/") {
					return part
				}
			}
		}
	}
	return ""
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
