package cacheable_https_detect

import (
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
)

var passwordFieldRe = regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*["']?password["']?[^>]*>`)

// Module implements the Cacheable HTTPS Response Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Cacheable HTTPS Response Detect module.
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
		ds: dedup.LazyDiskSet("passive_cacheable_https_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest checks if sensitive HTTPS responses have proper cache-control.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	// Only check HTTPS URLs
	if !strings.EqualFold(urlx.Scheme, "https") {
		return nil, nil
	}

	if ctx.Response() == nil {
		return nil, nil
	}

	// Gate: response must be "sensitive"
	hasCookie := false
	for _, h := range ctx.Response().Headers() {
		if strings.EqualFold(h.Name, "Set-Cookie") {
			hasCookie = true
			break
		}
	}

	hasPasswordField := false
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if strings.Contains(ct, "text/html") {
		hasPasswordField = passwordFieldRe.MatchString(ctx.Response().BodyToString())
	}

	if !hasCookie && !hasPasswordField {
		return nil, nil
	}

	// Dedup by host+path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := utils.Sha1(urlx.Host + urlx.Path)
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	// Check cache-control directives
	cacheControl := strings.ToLower(ctx.Response().Header("Cache-Control"))
	pragma := strings.ToLower(ctx.Response().Header("Pragma"))

	hasSafeDirective := strings.Contains(cacheControl, "no-store") ||
		strings.Contains(cacheControl, "no-cache") ||
		strings.Contains(cacheControl, "private") ||
		strings.Contains(pragma, "no-cache")

	if hasSafeDirective {
		return nil, nil
	}

	var reasons []string
	if hasCookie {
		reasons = append(reasons, "Response sets cookies")
	}
	if hasPasswordField {
		reasons = append(reasons, "Response contains password field(s)")
	}
	reasons = append(reasons, "Cache-Control: "+cacheControl)

	return []*output.ResultEvent{
		{
			Host:             urlx.Host,
			URL:              urlx.String(),
			Request:          string(ctx.Request().Raw()),
			ExtractedResults: reasons,
			Info: output.Info{
				Description: "Sensitive HTTPS response without proper cache-control directives",
			},
		},
	}, nil
}
