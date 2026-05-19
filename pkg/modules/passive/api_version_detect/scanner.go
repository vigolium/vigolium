package api_version_detect

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// urlVersionPattern matches API version patterns in URL paths.
var urlVersionPattern = regexp.MustCompile(`(?i)/(?:api/)?v(\d+)(?:\.\d+)?/`)

// bodyVersionPattern matches version fields in JSON response bodies.
var bodyVersionPattern = regexp.MustCompile(`(?i)"(?:version|api_version)"\s*:\s*"([^"]+)"`)

// versionHeaders lists HTTP headers that indicate API versioning.
var versionHeaders = []string{"API-Version", "X-API-Version", "Accept-Version"}

// Module implements the API Version Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new API Version Detect module.
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
		ds: dedup.LazyDiskSet("passive_api_version_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes request URLs, response headers, and response bodies for API version indicators.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if ctx.Response() == nil {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())

	var results []*output.ResultEvent

	// Detection 1: URL path version pattern
	if match := urlVersionPattern.FindStringSubmatch(urlx.Path); len(match) > 0 {
		version := match[0]
		dedupKey := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, version))
		if diskSet == nil || !diskSet.IsSeen(dedupKey) {
			results = append(results, &output.ResultEvent{
				ModuleID:         ModuleID,
				Host:             urlx.Host,
				URL:              urlx.String(),
				Matched:          urlx.String(),
				ExtractedResults: []string{fmt.Sprintf("URL path version: %s", version)},
				Info: output.Info{
					Name:        "API Version in URL Path",
					Description: fmt.Sprintf("API version pattern detected in URL path: %s", version),
					Tags:        []string{"api-version", "api-enumeration"},
				},
			})
		}
	}

	// Detection 2: Version headers
	for _, header := range versionHeaders {
		val := ctx.Response().Header(header)
		if val == "" {
			continue
		}
		dedupKey := utils.Sha1(fmt.Sprintf("%s%s:%s", urlx.Host, header, val))
		if diskSet != nil && diskSet.IsSeen(dedupKey) {
			continue
		}
		results = append(results, &output.ResultEvent{
			ModuleID:         ModuleID,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: []string{fmt.Sprintf("%s: %s", header, val)},
			Info: output.Info{
				Name:        "API Version Header",
				Description: fmt.Sprintf("API version header detected: %s: %s", header, val),
				Tags:        []string{"api-version", "api-enumeration"},
			},
		})
	}

	// Detection 3: Version field in JSON response body
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if strings.Contains(ct, "json") {
		body := ctx.Response().BodyToString()
		if body != "" {
			matches := bodyVersionPattern.FindAllStringSubmatch(body, 5)
			for _, match := range matches {
				fullMatch := match[0]
				version := match[1]
				dedupKey := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, version))
				if diskSet != nil && diskSet.IsSeen(dedupKey) {
					continue
				}
				results = append(results, &output.ResultEvent{
					ModuleID:         ModuleID,
					Host:             urlx.Host,
					URL:              urlx.String(),
					Matched:          urlx.String(),
					ExtractedResults: []string{fmt.Sprintf("Body version field: %s", fullMatch)},
					Info: output.Info{
						Name:        "API Version in Response Body",
						Description: fmt.Sprintf("API version field detected in JSON response: %s", version),
						Tags:        []string{"api-version", "api-enumeration"},
					},
				})
			}
		}
	}

	return results, nil
}
