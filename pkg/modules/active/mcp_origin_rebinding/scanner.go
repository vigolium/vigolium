package mcp_origin_rebinding

import (
	"net"
	"strings"

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
	if !modkit.BeginHostProbeFor(scanCtx, httpClient, &m.ds, ctx) {
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

	// DNS rebinding only matters when the MCP server is bound to a loopback or
	// private address a victim's browser can be tricked into reaching. A public,
	// internet-facing MCP server that ignores Origin for non-browser clients is
	// expected behaviour, not a rebinding sink — so it is reported at low
	// severity/confidence rather than High.
	local := isRebindingRelevantHost(urlx.Host)

	sev, conf := severity.Low, severity.Tentative
	name := "MCP Origin Header Not Validated"
	desc := "MCP server accepted an `initialize` carrying a foreign Origin header without rejecting it. " +
		"For an internet-facing server reached by non-browser clients this has limited impact, but it " +
		"indicates the server performs no Origin validation."
	if local {
		sev, conf = severity.High, severity.Firm
		name = "MCP Missing Origin Validation (DNS Rebinding Sink)"
		desc = "MCP server bound to a loopback/private address accepted an `initialize` carrying a foreign " +
			"Origin header. This is a DNS-rebinding sink: a victim's browser, resolving an attacker-controlled " +
			"domain to the local address, can speak to the local MCP server on behalf of the user."
	}

	return []*output.ResultEvent{
		{
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: []string{"Origin: " + foreignOrigin, "initialize succeeded", "host: " + urlx.Host},
			Info: output.Info{
				Name:        name,
				Description: desc,
				Severity:    sev,
				Confidence:  conf,
				Tags:        []string{"mcp", "dns-rebinding", "origin"},
				Reference:   []string{"https://modelcontextprotocol.io/specification/2025-11-25/basic/transports"},
			},
		},
	}, nil
}

// isRebindingRelevantHost reports whether host is a loopback/private/link-local
// address (or a local hostname) where DNS rebinding against a local MCP server
// is actually exploitable.
func isRebindingRelevantHost(host string) bool {
	h := host
	if hp, _, err := net.SplitHostPort(host); err == nil {
		h = hp
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	lower := strings.ToLower(h)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") || strings.HasSuffix(lower, ".local") {
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
	}
	return false
}
