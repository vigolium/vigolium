package security_headers_missing

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// securityHeader defines a security header to check.
type securityHeader struct {
	name string
	desc string
}

var requiredHeaders = []securityHeader{
	{
		name: "X-Content-Type-Options",
		desc: "Prevents MIME type sniffing attacks. Should be set to 'nosniff'.",
	},
	{
		name: "X-Frame-Options",
		desc: "Prevents clickjacking attacks by controlling iframe embedding. Should be 'DENY' or 'SAMEORIGIN'.",
	},
	{
		name: "Strict-Transport-Security",
		desc: "Enforces HTTPS connections. Prevents SSL stripping attacks.",
	},
	{
		name: "Content-Security-Policy",
		desc: "Prevents XSS, data injection, and other code injection attacks by controlling resource loading.",
	},
	{
		name: "Permissions-Policy",
		desc: "Controls browser features and APIs available to the page (formerly Feature-Policy).",
	},
}

// Module implements the Security Headers Missing passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Security Headers Missing module.
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
			modkit.ScanScopeHost,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("passive_security_headers_missing"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerHost checks response headers for missing security headers once per host.
func (m *Module) ScanPerHost(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	if ctx.Response() == nil {
		return nil, nil
	}

	// Only check HTML responses to reduce noise
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "text/html") {
		return nil, nil
	}

	var missing []string
	for _, h := range requiredHeaders {
		val := ctx.Response().Header(h.name)
		if val == "" {
			missing = append(missing, fmt.Sprintf("%s: %s", h.name, h.desc))
		}
	}

	// If CSP contains frame-ancestors, X-Frame-Options is redundant — remove it
	csp := strings.ToLower(ctx.Response().Header("Content-Security-Policy"))
	if strings.Contains(csp, "frame-ancestors") {
		filtered := missing[:0]
		for _, entry := range missing {
			if !strings.HasPrefix(entry, "X-Frame-Options:") {
				filtered = append(filtered, entry)
			}
		}
		missing = filtered
	}

	if len(missing) == 0 {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			Host:             host,
			URL:              urlx.String(),
			Request:          string(ctx.Request().Raw()),
			ExtractedResults: missing,
			Info: output.Info{
				Description: fmt.Sprintf("Missing %d security header(s)", len(missing)),
			},
		},
	}, nil
}
