package reverse_tabnabbing_detect

import (
	"fmt"
	"net/url"
	"strings"

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

	offenders := explicitOpenerLinks(ctx.Response().BodyToString(), pageURL)
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

func explicitOpenerLinks(body string, pageURL *url.URL) []string {
	tokenizer := html.NewTokenizer(strings.NewReader(body))
	seen := make(map[string]struct{})
	var offenders []string

	for {
		typeToken := tokenizer.Next()
		if typeToken == html.ErrorToken {
			return offenders
		}
		if typeToken != html.StartTagToken && typeToken != html.SelfClosingTagToken {
			continue
		}
		token := tokenizer.Token()
		if token.Data != "a" && token.Data != "area" {
			continue
		}

		attrs := attributeMap(token.Attr)
		if !strings.EqualFold(strings.TrimSpace(attrs["target"]), "_blank") {
			continue
		}
		relTokens := tokenSet(attrs["rel"])
		if !relTokens["opener"] || relTokens["noopener"] || relTokens["noreferrer"] {
			continue
		}
		href := strings.TrimSpace(attrs["href"])
		if !isCrossOriginHTTP(href, pageURL) {
			continue
		}
		if _, duplicate := seen[href]; duplicate {
			continue
		}
		seen[href] = struct{}{}
		offenders = append(offenders, href)
		if len(offenders) == maxExamples {
			return offenders
		}
	}
}

func attributeMap(attrs []html.Attribute) map[string]string {
	result := make(map[string]string, len(attrs))
	for _, attr := range attrs {
		result[strings.ToLower(attr.Key)] = attr.Val
	}
	return result
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
