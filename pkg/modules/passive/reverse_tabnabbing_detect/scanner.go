package reverse_tabnabbing_detect

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/anomaly/htmlutils"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"golang.org/x/net/html"
)

// maxExamples bounds how many offending links are listed in one result.
const maxExamples = 8

// Module implements the Reverse Tabnabbing passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new module instance.
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
		ds: dedup.LazyDiskSet("reverse_tabnabbing_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest reports cross-origin target=_blank links that explicitly opt
// back into an opener with rel=opener. The HTML Standard gives ordinary
// target=_blank links implicit noopener behavior, so absence of rel=noopener is
// not itself a vulnerability in modern browsers.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if ctx.Response() == nil || !strings.Contains(strings.ToLower(ctx.Response().Header("Content-Type")), "text/html") {
		return nil, nil
	}
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	pageURL, err := url.Parse(urlx.String())
	if err != nil {
		return nil, nil
	}

	// The shared, memoised parse: the other HTML passives reuse it.
	doc, err := ctx.Response().HTMLDocument()
	if err != nil || doc == nil {
		return nil, nil
	}
	offenders := explicitOpenerLinks(doc, pageURL)
	if len(offenders) == 0 {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	key := strings.ToLower(pageURL.Host) + pageURL.EscapedPath()
	if diskSet != nil && diskSet.IsSeen(key) {
		return nil, nil
	}

	extracted := make([]string, 0, len(offenders)+1)
	extracted = append(extracted, fmt.Sprintf("%d cross-origin target=_blank link(s) explicitly use rel=opener", len(offenders)))
	for _, offender := range offenders {
		extracted = append(extracted, "link="+offender)
	}

	return []*output.ResultEvent{{
		ModuleID:         ModuleID,
		RecordKind:       output.RecordKindCandidate,
		EvidenceGrade:    output.EvidenceGradeCandidate,
		Host:             urlx.Host,
		URL:              urlx.String(),
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        "Cross-Origin Link Explicitly Enables window.opener",
			Description: "A cross-origin target=\"_blank\" link explicitly declares rel=\"opener\", overriding the modern implicit-noopener default. If the destination is compromised or attacker-controlled, it can navigate the opening tab. Remove the opener token unless this relationship is required.",
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		},
		Metadata: map[string]any{
			"semantic":          "explicit-opener-opt-in",
			"standard_behavior": "target=_blank is implicitly noopener unless rel=opener is present",
		},
	}}, nil
}

// explicitOpenerLinks lists, in document order, the cross-origin
// target=_blank <a>/<area> links of the (shared, read-only) document that opt
// back into an opener.
func explicitOpenerLinks(doc *html.Node, pageURL *url.URL) []string {
	seen := make(map[string]struct{})
	var offenders []string
	for _, node := range htmlutils.GetElementsByTagName(doc, "*") {
		if node.Data != "a" && node.Data != "area" {
			continue
		}
		href, ok := openerOffender(node, pageURL)
		if !ok {
			continue
		}
		if _, duplicate := seen[href]; duplicate {
			continue
		}
		seen[href] = struct{}{}
		offenders = append(offenders, href)
		if len(offenders) == maxExamples {
			break
		}
	}
	return offenders
}

// openerOffender reports the href of a cross-origin target=_blank link that
// explicitly declares rel=opener without noopener/noreferrer.
func openerOffender(node *html.Node, pageURL *url.URL) (string, bool) {
	if !strings.EqualFold(htmlutils.GetAttributeTrimSpace(node, "target"), "_blank") {
		return "", false
	}
	relTokens := tokenSet(htmlutils.GetAttribute(node, "rel"))
	if !relTokens["opener"] || relTokens["noopener"] || relTokens["noreferrer"] {
		return "", false
	}
	href := htmlutils.GetAttributeTrimSpace(node, "href")
	if !isCrossOriginHTTP(href, pageURL) {
		return "", false
	}
	return href, true
}

func tokenSet(raw string) map[string]bool {
	result := make(map[string]bool)
	for _, token := range strings.Fields(strings.ToLower(raw)) {
		result[token] = true
	}
	return result
}

func isCrossOriginHTTP(href string, pageURL *url.URL) bool {
	if href == "" || pageURL == nil {
		return false
	}
	reference, err := url.Parse(href)
	if err != nil {
		return false
	}
	resolved := pageURL.ResolveReference(reference)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return false
	}
	return canonicalOrigin(resolved) != canonicalOrigin(pageURL)
}

func canonicalOrigin(u *url.URL) string {
	if u == nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	return strings.ToLower(u.Scheme) + "://" + host + ":" + port
}
