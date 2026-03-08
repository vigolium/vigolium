package wp_fingerprint

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/pkg/errors"
)

var (
	// Version extraction patterns
	generatorMetaRe = regexp.MustCompile(`<meta\s+name=["']generator["']\s+content=["']WordPress\s+([\d.]+)["']`)
	rssGeneratorRe  = regexp.MustCompile(`<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>`)

	// Plugin/theme slug extraction
	pluginSlugRe = regexp.MustCompile(`/wp-content/plugins/([a-zA-Z0-9_-]+)/`)
	themeSlugRe  = regexp.MustCompile(`/wp-content/themes/([a-zA-Z0-9_-]+)/`)

	// Version from ?ver= query strings on wp-content assets
	pluginVerRe = regexp.MustCompile(`/wp-content/plugins/([a-zA-Z0-9_-]+)/[^"']*\?ver=([\d.]+)`)
	themeVerRe  = regexp.MustCompile(`/wp-content/themes/([a-zA-Z0-9_-]+)/[^"']*\?ver=([\d.]+)`)
)

// WordPress detection signals
var wpSignals = []struct {
	check  func(body string, headers func(string) string) bool
	strong bool
}{
	{check: func(body string, _ func(string) string) bool {
		return strings.Contains(body, "/wp-content/")
	}, strong: true},
	{check: func(body string, _ func(string) string) bool {
		return strings.Contains(body, "/wp-includes/")
	}, strong: true},
	{check: func(_ string, hdr func(string) string) bool {
		return strings.Contains(hdr("Link"), "wp-json")
	}, strong: true},
	{check: func(_ string, hdr func(string) string) bool {
		return strings.Contains(hdr("X-Pingback"), "xmlrpc.php")
	}, strong: true},
	{check: func(body string, _ func(string) string) bool {
		return generatorMetaRe.MatchString(body)
	}, strong: true},
}

type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

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
		ds: dedup.LazyDiskSet("wp_fingerprint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	isHTML := strings.Contains(ct, "text/html")
	isXML := strings.Contains(ct, "text/xml") || strings.Contains(ct, "application/xml") || strings.Contains(ct, "application/rss+xml")
	if !isHTML && !isXML {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	host := urlx.Host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	hdr := func(name string) string { return ctx.Response().Header(name) }

	// Check for WordPress signals
	detected := false
	for _, sig := range wpSignals {
		if sig.check(body, hdr) && sig.strong {
			detected = true
			break
		}
	}
	if !detected {
		return nil, nil
	}

	// Extract version
	version := ""
	if m := generatorMetaRe.FindStringSubmatch(body); len(m) > 1 {
		version = m[1]
	} else if m := rssGeneratorRe.FindStringSubmatch(body); len(m) > 1 {
		version = m[1]
	}

	// Extract plugins
	pluginSlugs := uniqueMatches(pluginSlugRe, body)
	pluginVersions := extractVersionedSlugs(pluginVerRe, body)

	// Extract themes
	themeSlugs := uniqueMatches(themeSlugRe, body)
	themeVersions := extractVersionedSlugs(themeVerRe, body)

	var extracted []string
	if version != "" {
		extracted = append(extracted, fmt.Sprintf("WordPress %s", version))
	} else {
		extracted = append(extracted, "WordPress (version unknown)")
	}
	for _, slug := range pluginSlugs {
		if ver, ok := pluginVersions[slug]; ok {
			extracted = append(extracted, fmt.Sprintf("Plugin: %s v%s", slug, ver))
		} else {
			extracted = append(extracted, fmt.Sprintf("Plugin: %s", slug))
		}
	}
	for _, slug := range themeSlugs {
		if ver, ok := themeVersions[slug]; ok {
			extracted = append(extracted, fmt.Sprintf("Theme: %s v%s", slug, ver))
		} else {
			extracted = append(extracted, fmt.Sprintf("Theme: %s", slug))
		}
	}

	desc := "WordPress installation detected"
	if version != "" {
		desc = fmt.Sprintf("WordPress %s detected", version)
	}
	if len(pluginSlugs) > 0 {
		desc += fmt.Sprintf(" with %d plugin(s)", len(pluginSlugs))
	}
	if len(themeSlugs) > 0 {
		desc += fmt.Sprintf(" and %d theme(s)", len(themeSlugs))
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "WordPress Installation Detected",
				Description: desc,
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"wordpress", "fingerprint", "cms"},
			},
			Metadata: map[string]any{
				"cms":            "wordpress",
				"version":        version,
				"plugins":        pluginSlugs,
				"themes":         themeSlugs,
				"pluginVersions": pluginVersions,
				"themeVersions":  themeVersions,
			},
		},
	}, nil
}

func uniqueMatches(re *regexp.Regexp, body string) []string {
	matches := re.FindAllStringSubmatch(body, -1)
	seen := make(map[string]struct{})
	var result []string
	for _, m := range matches {
		if len(m) > 1 {
			slug := m[1]
			if _, ok := seen[slug]; !ok {
				seen[slug] = struct{}{}
				result = append(result, slug)
			}
		}
	}
	return result
}

func extractVersionedSlugs(re *regexp.Regexp, body string) map[string]string {
	matches := re.FindAllStringSubmatch(body, -1)
	result := make(map[string]string)
	for _, m := range matches {
		if len(m) > 2 {
			result[m[1]] = m[2]
		}
	}
	return result
}
