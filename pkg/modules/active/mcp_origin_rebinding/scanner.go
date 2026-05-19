package mcp_origin_rebinding

import (
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	mcpinfra "github.com/vigolium/vigolium/pkg/modules/infra/mcp"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const foreignOrigin = "https://attacker.example"

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
		ds: dedup.LazyDiskSet("mcp_origin_rebinding"),
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
	client.SetExtraHeaders(map[string]string{"Origin": foreignOrigin})
	res, err := client.Initialize()
	if err != nil || res == nil {
		return nil, nil
	}

	desc := "MCP server accepted an `initialize` carrying a foreign Origin header. " +
		"For local/private MCP transports this is a DNS-rebinding sink: a victim's browser, " +
		"resolving an attacker-controlled domain to 127.0.0.1, can speak to the local MCP server " +
		"on behalf of the user."

	return []*output.ResultEvent{
		{
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: []string{"Origin: " + foreignOrigin, "initialize succeeded"},
			Info: output.Info{
				Name:        "MCP Missing Origin Validation (DNS Rebinding Sink)",
				Description: desc,
				Severity:    severity.High,
				Confidence:  severity.Firm,
				Tags:        []string{"mcp", "dns-rebinding", "origin"},
				Reference:   []string{"https://modelcontextprotocol.io/specification/2025-11-25/basic/transports"},
			},
		},
	}, nil
}
