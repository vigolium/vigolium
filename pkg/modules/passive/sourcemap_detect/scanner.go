package sourcemap_detect

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
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

	if ctx.Response() == nil || modkit.IsEdgeBlockedResponse(ctx.Response()) {
		return nil, nil
	}
	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
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
			"map_url":                    safeMapReference(mapURL),
			"map_retrieved":              false,
			"unauthorized_access_tested": false,
		}

		inline := isInlineSourcemap(mapURL)
		if inline {
			meta["has_inline"] = true
			if decoded, ok := decodeInlineSourcemap(mapURL); ok {
				if sm, valid := parseSourcemap(decoded); valid {
					return m.mapResult(ctx, urlStr, host, sm, true), nil
				}
			}
		}
		extracted := safeMapReference(mapURL)
		if inline {
			extracted = fmt.Sprintf("inline source map data URI (%d bytes; structure not validated)", len(mapURL))
		}

		results = append(results, &output.ResultEvent{
			ModuleID:      ModuleID,
			RecordKind:    output.RecordKindObservation,
			EvidenceGrade: output.EvidenceGradeObservation,
			Info: output.Info{
				Name:        "SourceMappingURL Reference",
				Description: "JavaScript/CSS contains a sourceMappingURL reference. An external map was not fetched by this passive module, so source availability and sensitive content are unconfirmed.",
				Severity:    severity.Low,
				Confidence:  severity.Firm,
				Tags:        []string{"sourcemap", "information-disclosure", "javascript"},
			},
			Host:             host,
			URL:              urlStr,
			Matched:          urlStr,
			Request:          string(ctx.Request().Raw()),
			Response:         string(ctx.Response().Raw()),
			ExtractedResults: []string{extracted},
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
	if status := ctx.Response().StatusCode(); status < 200 || status >= 300 {
		return nil, nil
	}
	sm, valid := parseSourcemap(ctx.Response().Body())
	if !valid {
		return nil, nil
	}
	return m.mapResult(ctx, urlStr, host, sm, false), nil
}

func parseSourcemap(body []byte) (sourcemapJSON, bool) {
	var sm sourcemapJSON
	if err := json.Unmarshal(body, &sm); err != nil {
		return sourcemapJSON{}, false
	}
	if sm.Version <= 0 || len(sm.Sources) == 0 || sm.Mappings == "" {
		return sourcemapJSON{}, false
	}
	return sm, true
}

func (m *Module) mapResult(ctx *httpmsg.HttpRequestResponse, urlStr, host string, sm sourcemapJSON, inline bool) []*output.ResultEvent {

	sev := severity.Low
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
		sev = severity.Medium
		tags = append(tags, "source-code")
	}

	// Cap extracted sources
	sources := sm.Sources
	if len(sources) > maxSourcesOutput {
		sources = sources[:maxSourcesOutput]
	}

	desc := fmt.Sprintf("A structurally valid source map with %d source entries was delivered to this client", len(sm.Sources))
	if hasSourceContent {
		desc += " and includes embedded source text"
	}
	desc += ". This is a source-exposure candidate; production intent, anonymous access, and sensitive content were not established."
	name := "Sourcemap File Accessible"
	if inline {
		name = "Inline Sourcemap Embedded"
	}

	return []*output.ResultEvent{
		{
			ModuleID:      ModuleID,
			RecordKind:    output.RecordKindCandidate,
			EvidenceGrade: output.EvidenceGradeCandidate,
			Info: output.Info{
				Name:        name,
				Description: desc,
				Severity:    sev,
				Confidence:  conf,
				Tags:        tags,
			},
			Host:             host,
			URL:              urlStr,
			Matched:          urlStr,
			Request:          string(ctx.Request().Raw()),
			Response:         string(ctx.Response().Raw()),
			ExtractedResults: sources,
			Metadata: map[string]any{
				"version":                    sm.Version,
				"source_count":               len(sm.Sources),
				"has_source_content":         hasSourceContent,
				"inline":                     inline,
				"anonymous_access_tested":    false,
				"sensitive_content_detected": false,
			},
		},
	}
}

func decodeInlineSourcemap(value string) ([]byte, bool) {
	if len(value) > 3<<20 || !isInlineSourcemap(value) {
		return nil, false
	}
	comma := strings.IndexByte(value, ',')
	if comma < 0 {
		return nil, false
	}
	metadata, payload := strings.ToLower(value[:comma]), value[comma+1:]
	if strings.Contains(metadata, ";base64") {
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(payload)
		}
		return decoded, err == nil && len(decoded) <= 2<<20
	}
	decoded, err := url.QueryUnescape(payload)
	if err != nil || len(decoded) > 2<<20 {
		return nil, false
	}
	return []byte(decoded), true
}

func safeMapReference(value string) string {
	if isInlineSourcemap(value) {
		return "<inline source map data URI>"
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return modkit.Truncate(value, 160)
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return modkit.Truncate(parsed.String(), 160)
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
