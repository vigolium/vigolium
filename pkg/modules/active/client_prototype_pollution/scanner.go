package client_prototype_pollution

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// maxExternalScripts limits external JS fetches to avoid excessive requests.
const maxExternalScripts = 10

// ppProbe defines a prototype pollution URL probe.
type ppProbe struct {
	Suffix string
	Source string
	Desc   string
}

var ppProbes = []ppProbe{
	{
		Suffix: "__proto__[vgm_pp_test]=polluted",
		Source: "query string (__proto__)",
		Desc:   "__proto__ bracket notation via query string",
	},
	{
		Suffix: "__proto__.vgm_pp_test=polluted",
		Source: "query string (__proto__ dot)",
		Desc:   "__proto__ dot notation via query string",
	},
	{
		Suffix: "constructor[prototype][vgm_pp_test]=polluted",
		Source: "query string (constructor.prototype)",
		Desc:   "constructor.prototype via query string",
	},
}

// ppFinding holds evidence from the static analysis.
type ppFinding struct {
	Source     ppSourcePattern
	SourceFile string
	SourceLine string
	Gadgets    []ppGadgetPattern
}

// Module implements the Client-Side Prototype Pollution active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Client-Side Prototype Pollution module.
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
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("client_prototype_pollution"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess limits to HTML responses.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if !m.BaseActiveModule.CanProcess(ctx) {
		return false
	}
	if ctx.HasResponse() {
		ct := strings.ToLower(ctx.Response().Header("Content-Type"))
		if ct != "" && !strings.Contains(ct, "text/html") {
			return false
		}
	}
	return true
}

// ScanPerRequest analyzes the page's JavaScript for prototype pollution sources and gadgets.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	// Host-level deduplication
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(urlx.Host) {
		return nil, nil
	}

	// Get baseline response
	entry, err := scanCtx.GetOrFetchBaseline(ctx, httpClient)
	if err != nil {
		return nil, nil
	}

	ct := strings.ToLower(entry.Response.Header("Content-Type"))
	if !strings.Contains(ct, "text/html") {
		return nil, nil
	}

	htmlBody := entry.Response.BodyToString()

	// Collect all JavaScript content to analyze
	type jsBlock struct {
		content string
		source  string // "inline" or script URL
	}
	var blocks []jsBlock

	// Extract inline scripts
	for _, script := range extractInlineScripts(htmlBody) {
		blocks = append(blocks, jsBlock{content: script, source: "inline <script>"})
	}

	// Extract and fetch external scripts
	pageURLStr := urlx.String()
	externalURLs := extractExternalScriptURLs(htmlBody)
	fetched := 0
	for _, scriptSrc := range externalURLs {
		if fetched >= maxExternalScripts {
			break
		}
		resolved := resolveScriptURL(pageURLStr, scriptSrc)
		if isCDNURL(resolved) {
			continue
		}
		jsContent := fetchScript(resolved, httpClient, ctx)
		if jsContent != "" {
			blocks = append(blocks, jsBlock{content: jsContent, source: resolved})
			fetched++
		}
	}

	// Match source and gadget patterns
	var findings []ppFinding
	var allGadgets []ppGadgetPattern

	// Detect gadgets across all JS blocks (enrichment)
	for _, block := range blocks {
		for _, gp := range ppGadgetPatterns {
			if gp.Pattern.MatchString(block.content) {
				allGadgets = append(allGadgets, gp)
			}
		}
	}

	// Detect source patterns
	for _, block := range blocks {
		for _, sp := range ppSourcePatterns {
			loc := sp.Pattern.FindStringIndex(block.content)
			if loc == nil {
				continue
			}
			// Extract matching line for evidence
			matchLine := extractMatchLine(block.content, loc[0])
			findings = append(findings, ppFinding{
				Source:     sp,
				SourceFile: block.source,
				SourceLine: matchLine,
				Gadgets:    allGadgets,
			})
		}
	}

	if len(findings) == 0 {
		return nil, nil
	}

	// Send probe requests to verify URL parameter acceptance
	var probeRaw string
	var probeResp string
	for _, probe := range ppProbes {
		pURL := buildProbeURL(pageURLStr, probe.Suffix)
		raw, resp, ok := sendProbe(pURL, httpClient, ctx)
		if ok {
			probeRaw = raw
			probeResp = resp
			break
		}
	}

	// Build result from the first (strongest) finding
	f := findings[0]

	gadgetDesc := ""
	if len(f.Gadgets) > 0 {
		var gadgetNames []string
		for _, g := range f.Gadgets {
			gadgetNames = append(gadgetNames, fmt.Sprintf("%s (%s)", g.Name, g.Impact))
		}
		gadgetDesc = "\n\nDetected gadgets:\n- " + strings.Join(gadgetNames, "\n- ")
	}

	description := fmt.Sprintf(
		"The page at %s contains JavaScript that parses URL parameters into objects "+
			"using a pattern vulnerable to prototype pollution: **%s**.\n\n"+
			"Matching code: `%s`\n"+
			"Source file: %s\n\n"+
			"An attacker can craft a URL like:\n```\n%s?__proto__[polluted]=true\n```\n"+
			"When a victim visits this URL, the browser's `Object.prototype` is polluted, "+
			"which can lead to XSS, authentication bypass, or denial of service depending "+
			"on the gadgets available on the page.%s",
		urlx.String(),
		f.Source.Name,
		f.SourceLine,
		f.SourceFile,
		urlx.String(),
		gadgetDesc,
	)

	result := &output.ResultEvent{
		URL:              urlx.String(),
		Request:          probeRaw,
		Response:         probeResp,
		ExtractedResults: []string{f.Source.Name, f.SourceLine},
		Info: output.Info{
			Name:        "Client-Side Prototype Pollution",
			Description: description,
			Reference: []string{
				"https://portswigger.net/web-security/prototype-pollution",
				"https://portswigger.net/web-security/prototype-pollution/client-side",
				"https://portswigger.net/research/widespread-prototype-pollution-gadgets",
			},
		},
	}

	return []*output.ResultEvent{result}, nil
}

// fetchScript fetches a JavaScript file and returns its content.
func fetchScript(scriptURL string, httpClient *http.Requester, ctx *httpmsg.HttpRequestResponse) string {
	rawReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: placeholder\r\n\r\n", scriptURL)
	req, err := httpmsg.ParseRawRequest(rawReq)
	if err != nil {
		return ""
	}
	req = req.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		return ""
	}
	defer resp.Close()

	if resp.Response() != nil && resp.Response().StatusCode != 200 {
		return ""
	}
	return resp.Body().String()
}

// buildProbeURL appends a prototype pollution probe parameter to the URL.
func buildProbeURL(pageURL, suffix string) string {
	if strings.Contains(pageURL, "?") {
		return pageURL + "&" + suffix
	}
	return pageURL + "?" + suffix
}

// sendProbe sends a probe request and returns whether the server accepted it (2xx).
func sendProbe(probeURL string, httpClient *http.Requester, ctx *httpmsg.HttpRequestResponse) (rawReq string, fullResp string, ok bool) {
	raw := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: placeholder\r\n\r\n", probeURL)
	req, err := httpmsg.ParseRawRequest(raw)
	if err != nil {
		return "", "", false
	}
	req = req.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		return "", "", false
	}
	defer resp.Close()

	if resp.Response() == nil {
		return "", "", false
	}
	sc := resp.Response().StatusCode
	if sc >= 200 && sc < 400 {
		return raw, resp.FullResponseString(), true
	}
	return "", "", false
}

// extractMatchLine extracts the line containing the match position from the JS content.
func extractMatchLine(content string, pos int) string {
	// Find line start
	start := pos
	for start > 0 && content[start-1] != '\n' {
		start--
	}
	// Find line end
	end := pos
	for end < len(content) && content[end] != '\n' {
		end++
	}
	line := content[start:end]
	// Trim and limit length
	line = strings.TrimSpace(line)
	if len(line) > 200 {
		line = line[:200] + "..."
	}
	return line
}
