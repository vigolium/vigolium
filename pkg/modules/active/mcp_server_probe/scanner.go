package mcp_server_probe

import (
	"fmt"
	"regexp"
	"strings"

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
	// skipped names tools that were NOT invoked because their name suggests a
	// state-changing/destructive operation — surfaced so an operator can verify
	// callability by hand rather than have the scanner trigger side effects.
	skipped []string
	// secretLeaks records "<tool> -> <secret kind>" where a tool's output leaked
	// a high-confidence credential.
	secretLeaks []string
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

	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	// All exposure claims must come from a credential-free client and request.
	// Reusing the captured authenticated seed was the source of false
	// "unauthenticated" enumeration/invocation findings.
	probeCtx, err := anonymousProbeContext(ctx)
	if err != nil {
		return nil, nil
	}
	probeHTTP, err := httpClient.CloneWithoutCredentials()
	if err != nil {
		return nil, nil
	}

	var endpoints []mcpEndpoint

	for _, path := range mcpinfra.CommonPaths {
		if ep := m.tryStreamableHTTP(probeCtx, probeHTTP, path); ep != nil {
			m.enumerateAndInvoke(probeCtx, probeHTTP, ep)
			endpoints = append(endpoints, *ep)
			continue
		}
		if ep := m.trySSETransport(probeCtx, probeHTTP, path); ep != nil {
			m.enumerateAndInvoke(probeCtx, probeHTTP, ep)
			endpoints = append(endpoints, *ep)
		}
	}

	if len(endpoints) == 0 {
		return nil, nil
	}

	return m.buildResults(ctx, endpoints, true), nil
}

func anonymousProbeContext(ctx *httpmsg.HttpRequestResponse) (*httpmsg.HttpRequestResponse, error) {
	if ctx == nil || ctx.Request() == nil || ctx.Service() == nil {
		return nil, fmt.Errorf("missing seed request or service")
	}
	raw, err := modkit.StripCredentialHeaders(ctx.Request().Raw())
	if err != nil {
		return nil, err
	}
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return nil, err
	}
	return req.WithService(ctx.Service()), nil
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
		// Safety guard: never invoke a tool whose name suggests a state-changing
		// or destructive operation. Probing callability must not delete/send/exec
		// anything on an unauthenticated server.
		if looksStateChanging(tool.Name) {
			ep.skipped = append(ep.skipped, tool.Name)
			continue
		}
		args := mcpinfra.GenerateSampleArgs(tool.InputSchema)
		callResult, _, err := client.CallTool(100+i, tool.Name, args)
		if err != nil || callResult == nil {
			continue
		}
		// A tool that returns an application-level error (isError) was reachable
		// but did NOT successfully execute — it must not escalate the finding to
		// "callable/invocable". Only a non-error result proves the call ran.
		if callResult.IsError {
			continue
		}
		var respText string
		for _, c := range callResult.Content {
			if c.Type == "text" && c.Text != "" {
				respText = c.Text
				break
			}
		}
		// A tool that returns a live credential in its output is a direct data
		// leak — scan the (unauthenticated) response for high-confidence secrets.
		secretKinds := scanSecrets(respText)
		for _, kind := range secretKinds {
			ep.secretLeaks = append(ep.secretLeaks, fmt.Sprintf("%s -> %s", tool.Name, kind))
		}
		ep.callables = append(ep.callables, toolCallEvidence{
			toolName: tool.Name,
			response: truncate(redactSecrets(respText), 200),
		})
	}
}

// secretPatterns are high-precision, structurally-prefixed credential formats —
// chosen so a benign tool output can't false-positive on a generic token shape.
var secretPatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"AWS secret access key", regexp.MustCompile(`(?i)aws[_ -]?secret[_ -]?access[_ -]?key\s*[:=]\s*[A-Za-z0-9/+=]{40}`)},
	{"private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`)},
	{"GitHub token", regexp.MustCompile(`\bghp_[0-9A-Za-z]{36}\b`)},
	{"GitHub fine-grained PAT", regexp.MustCompile(`\bgithub_pat_[0-9A-Za-z_]{60,}`)},
	{"Slack token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}`)},
	{"Stripe secret key", regexp.MustCompile(`\bsk_live_[0-9A-Za-z]{24,}`)},
}

// scanSecrets returns the distinct kinds of high-confidence secret found in s.
func scanSecrets(s string) []string {
	if s == "" {
		return nil
	}
	var kinds []string
	seen := map[string]bool{}
	for _, p := range secretPatterns {
		for _, match := range p.re.FindAllString(s, -1) {
			lower := strings.ToLower(match)
			if strings.Contains(lower, "example") || strings.Contains(lower, "dummy") || strings.Contains(lower, "redacted") || strings.Contains(lower, "placeholder") {
				continue
			}
			if !seen[p.kind] {
				seen[p.kind] = true
				kinds = append(kinds, p.kind)
			}
		}
	}
	return kinds
}

func redactSecrets(s string) string {
	redacted := s
	for _, pattern := range secretPatterns {
		redacted = pattern.re.ReplaceAllString(redacted, "<"+pattern.kind+" redacted>")
	}
	return redacted
}

// stateChangingVerbs are substrings in a tool name that indicate a
// side-effecting operation the probe must not trigger blindly.
var stateChangingVerbs = []string{
	"delete", "remove", "destroy", "drop", "purge", "wipe", "clear",
	"create", "insert", "add", "write", "update", "edit", "modify", "patch",
	"send", "email", "post", "publish", "upload", "deploy", "push",
	"exec", "run", "eval", "shell", "command",
	"shutdown", "restart", "reboot", "reset", "kill", "stop", "terminate",
	"grant", "revoke", "install", "uninstall", "rename", "move",
	"pay", "transfer", "charge", "refund", "order", "checkout",
}

func looksStateChanging(name string) bool {
	n := strings.ToLower(name)
	for _, v := range stateChangingVerbs {
		if strings.Contains(n, v) {
			return true
		}
	}
	return false
}

// buildResults creates ResultEvent findings from discovered endpoints.
func (m *Module) buildResults(ctx *httpmsg.HttpRequestResponse, endpoints []mcpEndpoint, anonymousTested bool) []*output.ResultEvent {
	urlx, _ := ctx.URL()
	baseURL := urlx.Scheme + "://" + urlx.Host

	var evidence []string
	var toolNames []string
	var callableNames []string
	var secretLeaks []string

	for _, ep := range endpoints {
		secretLeaks = append(secretLeaks, ep.secretLeaks...)
		evidence = append(evidence, fmt.Sprintf("Endpoint: %s (transport: %s)", ep.path, ep.transport))
		if ep.serverInfo != nil {
			evidence = append(evidence, fmt.Sprintf("Server: %s %s", ep.serverInfo.Name, ep.serverInfo.Version))
		}
		if ep.sessionID != "" {
			evidence = append(evidence, fmt.Sprintf("Session ID issued (%d characters; value redacted)", len(ep.sessionID)))
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

		for _, c := range ep.callables {
			callableNames = append(callableNames, fmt.Sprintf("Callable: %s -> %s", c.toolName, c.response))
		}
		if len(ep.skipped) > 0 {
			evidence = append(evidence, fmt.Sprintf("Not invoked (name suggests state change, verify manually): %s", strings.Join(ep.skipped, ", ")))
		}
	}

	extracted := append(evidence, toolNames...)
	extracted = append(extracted, callableNames...)

	kind := output.RecordKindObservation
	grade := output.EvidenceGradeObservation
	sev := severity.Info
	confidence := severity.Firm
	name := "MCP Server Discovered"
	desc := fmt.Sprintf("Credential-free probing confirmed %d MCP endpoint(s) at %s and enumerated %d capability item(s). Endpoint and catalog visibility are protocol observations, not vulnerabilities.", len(endpoints), urlx.Host, len(toolNames))
	if len(callableNames) > 0 {
		kind = output.RecordKindCandidate
		grade = output.EvidenceGradeDifferential
		sev = severity.Medium
		confidence = severity.Certain
		name = "MCP Credential-Free Tool Invocation Candidate"
		desc = fmt.Sprintf("Credential-free probing invoked %d non-state-changing MCP tool(s) successfully at %s. Public tools may be intentional; privileged data access or harmful side effects were not established.", len(callableNames), urlx.Host)
	}

	results := []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			RecordKind:       kind,
			EvidenceGrade:    grade,
			Host:             urlx.Host,
			URL:              baseURL,
			Matched:          baseURL,
			Request:          string(ctx.Request().Raw()),
			MatcherStatus:    true,
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        name,
				Description: desc,
				Severity:    sev,
				Confidence:  confidence,
				Tags:        []string{"mcp", "api-security", "misconfiguration"},
				Reference: []string{
					"https://modelcontextprotocol.io/specification/2025-11-25",
					"https://modelcontextprotocol.io/specification/2025-11-25/server/tools",
				},
			},
			Metadata: map[string]any{"anonymous_tested": anonymousTested, "endpoint_count": len(endpoints), "capability_count": len(toolNames), "callable_count": len(callableNames), "privileged_impact_confirmed": false},
		},
	}

	// A tool that returned a live credential in its (unauthenticated) output is
	// a distinct, higher-signal data-leak finding.
	if len(secretLeaks) > 0 {
		results = append(results, &output.ResultEvent{
			ModuleID:         ModuleID,
			RecordKind:       output.RecordKindFinding,
			EvidenceGrade:    output.EvidenceGradeImpact,
			Host:             urlx.Host,
			URL:              baseURL,
			Matched:          baseURL,
			Request:          string(ctx.Request().Raw()),
			MatcherStatus:    true,
			ExtractedResults: secretLeaks,
			Info: output.Info{
				Name:        "MCP Tool Output Leaks Secret",
				Description: fmt.Sprintf("Credential-free MCP tool invocation at %s returned private credential material (%s). Public credential identifiers are excluded from this oracle and secret values are redacted.", urlx.Host, strings.Join(secretLeaks, "; ")),
				Severity:    severity.High,
				Confidence:  severity.Firm,
				Tags:        []string{"mcp", "secret-leak", "info-disclosure"},
				Reference:   []string{"https://modelcontextprotocol.io/specification/2025-11-25/server/tools"},
			},
			Metadata: map[string]any{"anonymous_tested": anonymousTested, "secret_values_redacted": true, "private_secret_format_confirmed": true},
		})
	}

	return results
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
