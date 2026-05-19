package mcp_method_enum

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

// methodWordlist is intentionally short - we keep the false-positive risk
// low and the request count manageable. Add to it deliberately.
var methodWordlist = []string{
	"debug/info",
	"debug/dump",
	"debug/state",
	"debug/eval",
	"admin/users",
	"admin/sessions",
	"admin/reload",
	"admin/shutdown",
	"_internal/diagnostics",
	"_internal/echo",
	"system/info",
	"system/exec",
	"sampling/createMessage",
	"logging/setLevel",
	"logging/getLevel",
	"roots/list",
	"experimental/echo",
	"experimental/run",
	"server/restart",
	"ping",
}

// JSON-RPC standard "method not found" error code.
const errMethodNotFound = -32601

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
		ds: dedup.LazyDiskSet("mcp_method_enum"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil || ctx.Response() == nil {
		return false
	}
	return mcpinfra.Detect(ctx).Strong()
}

func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	if ctx.Service() == nil {
		return nil, nil
	}
	host := ctx.Service().Host()
	if ds := m.ds.Get(scanCtx.DedupMgr()); ds != nil && ds.IsSeen(host) {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, err
	}

	client := mcpinfra.NewClient(ctx, httpClient, urlx.Path)
	if _, err := client.Initialize(); err != nil {
		return nil, nil
	}
	_ = client.SendInitializedNotification()

	var findings []*output.ResultEvent
	for i, method := range methodWordlist {
		body, _, err := client.PostRaw(mcpinfra.MarshalRequest(5000+i, method, map[string]any{}))
		if err != nil || body == "" {
			continue
		}
		resp, err := mcpinfra.ParseResponse(body)
		if err != nil || resp == nil {
			continue
		}
		isError := resp.Error != nil
		if isError && resp.Error.Code == errMethodNotFound {
			continue
		}
		if !isError && len(resp.Result) == 0 {
			continue
		}

		evidence := "JSON-RPC result returned"
		sev := severity.Medium
		if !isError && len(resp.Result) > 0 {
			evidence = "JSON-RPC result returned (method exposed)"
		} else if isError {
			evidence = fmt.Sprintf("JSON-RPC error code %d (method recognised but rejected)", resp.Error.Code)
			sev = severity.Low
		}

		findings = append(findings, &output.ResultEvent{
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: []string{method, evidence, truncate(body, 200)},
			Info: output.Info{
				Name:        fmt.Sprintf("MCP Undocumented Method Reachable: %s", method),
				Description: fmt.Sprintf("MCP server at %s exposes JSON-RPC method %q. %s.", urlx.Host, method, evidence),
				Severity:    sev,
				Confidence:  severity.Firm,
				Tags:        []string{"mcp", "enumeration", "info-disclosure"},
				Reference:   []string{"https://modelcontextprotocol.io/specification/2025-11-25"},
			},
		})
	}
	return findings, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
