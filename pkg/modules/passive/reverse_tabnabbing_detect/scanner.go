package reverse_tabnabbing_detect

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

var (
	anchorRe    = regexp.MustCompile(`(?is)<a\b[^>]*>`)
	targetReVal = regexp.MustCompile(`(?is)\btarget\s*=\s*["']?_blank\b`)
	hrefRe      = regexp.MustCompile(`(?is)\bhref\s*=\s*["']([^"']+)["']`)
	relRe       = regexp.MustCompile(`(?is)\brel\s*=\s*["']([^"']*)["']`)
)

// maxExamples bounds how many offending links are listed in one finding.
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

// ScanPerRequest flags cross-origin target=_blank links without rel=noopener.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if ctx.Response() == nil {
		return nil, nil
	}
	if !strings.Contains(strings.ToLower(ctx.Response().Header("Content-Type")), "text/html") {
		return nil, nil
	}
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	pageHost := strings.ToLower(urlx.Hostname())

	body := ctx.Response().BodyToString()
	var offenders []string
	seen := map[string]struct{}{}
	for _, tag := range anchorRe.FindAllString(body, -1) {
		if !targetReVal.MatchString(tag) {
			continue
		}
		href := firstGroup(hrefRe, tag)
		if href == "" || !isCrossOrigin(href, pageHost) {
			continue
		}
		rel := strings.ToLower(firstGroup(relRe, tag))
		if strings.Contains(rel, "noopener") || strings.Contains(rel, "noreferrer") {
			continue
		}
		if _, dup := seen[href]; dup {
			continue
		}
		seen[href] = struct{}{}
		offenders = append(offenders, href)
		if len(offenders) >= maxExamples {
			break
		}
	}

	if len(offenders) == 0 {
		return nil, nil
	}

	// Dedup one finding per host+path so a repeated page isn't reported repeatedly.
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	key := pageHost + urlx.Path
	if diskSet != nil && diskSet.IsSeen(key) {
		return nil, nil
	}

	extracted := make([]string, 0, len(offenders)+1)
	extracted = append(extracted, fmt.Sprintf("%d cross-origin target=_blank link(s) without rel=noopener", len(offenders)))
	for _, o := range offenders {
		extracted = append(extracted, "link="+o)
	}

	return []*output.ResultEvent{{
		ModuleID:         ModuleID,
		Host:             urlx.Host,
		URL:              urlx.String(),
		ExtractedResults: extracted,
		Info: output.Info{
			Name:        "Reverse Tabnabbing (target=_blank without rel=noopener)",
			Description: "The page links to cross-origin URLs with target=\"_blank\" but no rel=\"noopener\"/\"noreferrer\", so the opened page gets a window.opener reference and can silently navigate this tab to a phishing clone. Add rel=\"noopener noreferrer\" to these links.",
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		},
	}}, nil
}

// isCrossOrigin reports whether href has an explicit host that differs from
// pageHost. Relative URLs (no host) are same-origin and ignored; javascript:/
// mailto:/tel: and fragment links are not navigations and are ignored.
func isCrossOrigin(href, pageHost string) bool {
	h := strings.TrimSpace(href)
	if h == "" || strings.HasPrefix(h, "#") {
		return false
	}
	lower := strings.ToLower(h)
	for _, skip := range []string{"javascript:", "mailto:", "tel:", "data:"} {
		if strings.HasPrefix(lower, skip) {
			return false
		}
	}
	u, err := url.Parse(h)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false // relative URL — same origin
	}
	return host != pageHost
}

// firstGroup returns the first capture group of re in s, or "".
func firstGroup(re *regexp.Regexp, s string) string {
	if mm := re.FindStringSubmatch(s); len(mm) > 1 {
		return mm[1]
	}
	return ""
}
