package subresource_integrity_detect

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

// scriptTagRe matches <script> tags with a src attribute.
var scriptTagRe = regexp.MustCompile(`(?i)<script\s[^>]*src\s*=\s*["']([^"']+)["'][^>]*>`)

// linkTagRe matches <link> tags with rel="stylesheet" and an href attribute.
var linkTagRe = regexp.MustCompile(`(?i)<link\s[^>]*rel\s*=\s*["']stylesheet["'][^>]*href\s*=\s*["']([^"']+)["'][^>]*>`)

// linkTagReverseRe handles <link href="..." ... rel="stylesheet"> ordering.
var linkTagReverseRe = regexp.MustCompile(`(?i)<link\s[^>]*href\s*=\s*["']([^"']+)["'][^>]*rel\s*=\s*["']stylesheet["'][^>]*>`)

// integrityRe checks if a tag contains an integrity attribute.
var integrityRe = regexp.MustCompile(`(?i)\bintegrity\s*=`)

// Module implements the Subresource Integrity Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Subresource Integrity Detect module.
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
		ds: dedup.LazyDiskSet("passive_subresource_integrity_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess accepts only HTML responses.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// ScanPerRequest analyzes HTML for external resources without SRI.
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

	body := ctx.Response().BodyToString()
	if body == "" {
		return nil, nil
	}

	var missing []string
	seen := make(map[string]struct{})

	// Check <script src="..."> tags
	for _, match := range scriptTagRe.FindAllStringSubmatch(body, -1) {
		fullTag := match[0]
		src := match[1]
		if isExternalResource(src) && !integrityRe.MatchString(fullTag) {
			if _, ok := seen[src]; !ok {
				seen[src] = struct{}{}
				missing = append(missing, fmt.Sprintf("script: %s", src))
			}
		}
	}

	// Check <link rel="stylesheet" href="..."> tags (both attribute orderings)
	for _, re := range []*regexp.Regexp{linkTagRe, linkTagReverseRe} {
		for _, match := range re.FindAllStringSubmatch(body, -1) {
			fullTag := match[0]
			href := match[1]
			if isExternalResource(href) && !integrityRe.MatchString(fullTag) {
				if _, ok := seen[href]; !ok {
					seen[href] = struct{}{}
					missing = append(missing, fmt.Sprintf("stylesheet: %s", href))
				}
			}
		}
	}

	if len(missing) == 0 {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			Host:             urlx.Host,
			URL:              urlx.String(),
			Request:          string(ctx.Request().Raw()),
			ExtractedResults: missing,
			Info: output.Info{
				Description: fmt.Sprintf("Found %d external resource(s) without subresource integrity", len(missing)),
			},
		},
	}, nil
}

// isExternalResource checks if a URL points to an external origin.
func isExternalResource(url string) bool {
	if url == "" {
		return false
	}

	// Skip data: URIs
	if strings.HasPrefix(strings.ToLower(url), "data:") {
		return false
	}

	// Protocol-relative URLs are external
	if strings.HasPrefix(url, "//") {
		return true
	}

	// Absolute URLs with http(s):// are external
	lower := strings.ToLower(url)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return true
	}

	// Relative URLs are same-origin
	return false
}
