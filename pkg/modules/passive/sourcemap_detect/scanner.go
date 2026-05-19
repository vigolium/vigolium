package sourcemap_detect

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// maxSourcesOutput caps the number of source paths included in finding output.
const maxSourcesOutput = 20

// Module detects exposed JavaScript sourcemaps in production responses.
type Module struct {
	modkit.BasePassiveModule
	ds              dedup.Lazy[dedup.DiskSet]
	sourceMappingRe *regexp.Regexp
}

// New creates a new sourcemap exposure detection passive module.
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
		ds:              dedup.LazyDiskSet("passive_sourcemap_detect"),
		sourceMappingRe: regexp.MustCompile(`(?m)(?://|/\*)#\s*sourceMappingURL=(\S+)`),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess accepts JS/CSS responses (for SourceMappingURL detection) and
// URLs ending in .map (for sourcemap file validation).
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	if len(ctx.Response().Body()) == 0 {
		return false
	}

	if u, err := ctx.URL(); err == nil && isMapFileURL(u.Path) {
		return true
	}

	ct := ctx.Response().Header("Content-Type")
	return isJSOrCSSContentType(ct)
}

// ScanPerRequest analyzes the response for sourcemap indicators.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	// Detection 2: .map file response with valid sourcemap JSON
	if isMapFileURL(urlx.Path) {
		return m.detectMapFile(ctx, urlx.String(), urlx.Host)
	}

	// Detection 1: SourceMappingURL reference in JS/CSS body
	return m.detectSourceMappingURL(ctx, urlx.String(), urlx.Host)
}

// detectSourceMappingURL scans JS/CSS response bodies for sourceMappingURL comments.
func (m *Module) detectSourceMappingURL(ctx *httpmsg.HttpRequestResponse, urlStr, host string) ([]*output.ResultEvent, error) {
	body := ctx.Response().BodyToString()
	matches := m.sourceMappingRe.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return nil, nil
	}

	var results []*output.ResultEvent
	for _, match := range matches {
		mapURL := match[1]
		// Trim trailing */ from block comment style
		mapURL = strings.TrimSuffix(mapURL, "*/")
		mapURL = strings.TrimSpace(mapURL)

		meta := map[string]any{
			"map_url": mapURL,
		}

		inline := isInlineSourcemap(mapURL)
		if inline {
			meta["has_inline"] = true
		}

		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Info: output.Info{
				Name:        "SourceMappingURL Reference",
				Description: "JavaScript/CSS response contains a sourceMappingURL reference: " + mapURL,
				Severity:    severity.Low,
				Confidence:  severity.Firm,
				Tags:        []string{"sourcemap", "information-disclosure", "javascript"},
			},
			Host:             host,
			URL:              urlStr,
			Matched:          urlStr,
			ExtractedResults: []string{mapURL},
			Metadata:         meta,
		})
	}

	return results, nil
}

// sourcemapJSON is a minimal struct for validating sourcemap JSON.
type sourcemapJSON struct {
	Version        int      `json:"version"`
	Sources        []string `json:"sources"`
	Mappings       string   `json:"mappings"`
	SourcesContent []string `json:"sourcesContent"`
}

// detectMapFile validates that a .map response contains valid sourcemap JSON.
func (m *Module) detectMapFile(ctx *httpmsg.HttpRequestResponse, urlStr, host string) ([]*output.ResultEvent, error) {
	body := ctx.Response().Body()

	var sm sourcemapJSON
	if err := json.Unmarshal(body, &sm); err != nil {
		return nil, nil
	}

	if sm.Version <= 0 || len(sm.Sources) == 0 || sm.Mappings == "" {
		return nil, nil
	}

	sev := severity.Medium
	conf := severity.Certain
	tags := []string{"sourcemap", "information-disclosure", "javascript"}

	hasSourceContent := false
	for _, sc := range sm.SourcesContent {
		if sc != "" {
			hasSourceContent = true
			break
		}
	}
	if hasSourceContent {
		sev = severity.High
		tags = append(tags, "source-code")
	}

	// Cap extracted sources
	sources := sm.Sources
	if len(sources) > maxSourcesOutput {
		sources = sources[:maxSourcesOutput]
	}

	desc := fmt.Sprintf("Accessible sourcemap file with %d source entries", len(sm.Sources))
	if hasSourceContent {
		desc += " (includes full source code)"
	}

	return []*output.ResultEvent{
		{
			ModuleID: ModuleID,
			Info: output.Info{
				Name:        "Sourcemap File Exposed",
				Description: desc,
				Severity:    sev,
				Confidence:  conf,
				Tags:        tags,
			},
			Host:             host,
			URL:              urlStr,
			Matched:          urlStr,
			ExtractedResults: sources,
			Metadata: map[string]any{
				"version":            sm.Version,
				"source_count":       len(sm.Sources),
				"has_source_content": hasSourceContent,
			},
		},
	}, nil
}

// isMapFileURL checks if the URL path ends with .map.
func isMapFileURL(path string) bool {
	return strings.HasSuffix(strings.ToLower(path), ".map")
}

// isJSOrCSSContentType checks if the content type indicates JavaScript or CSS.
func isJSOrCSSContentType(ct string) bool {
	if ct == "" {
		return false
	}
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "ecmascript") ||
		strings.Contains(ct, "text/css")
}

// isInlineSourcemap checks if the sourcemap URL is a data: URI.
func isInlineSourcemap(url string) bool {
	return strings.HasPrefix(strings.ToLower(url), "data:")
}
