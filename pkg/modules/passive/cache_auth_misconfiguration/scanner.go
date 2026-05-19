package cache_auth_misconfiguration

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// staticExtensions are file extensions to skip.
var staticExtensions = []string{
	".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
	".woff", ".woff2", ".ttf", ".eot", ".otf", ".map",
	".mp4", ".webm", ".mp3", ".ogg", ".wav",
	".pdf", ".zip", ".gz", ".br",
}

// Module implements the cache-auth misconfiguration passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Cache-Auth Misconfiguration module.
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
			modkit.PassiveScanScopeBoth,
		),
		ds: dedup.LazyDiskSet("cache_auth_misconfiguration"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest checks for cacheable responses missing Vary headers.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Skip static assets
	pathLower := strings.ToLower(urlx.Path)
	for _, ext := range staticExtensions {
		if strings.HasSuffix(pathLower, ext) {
			return nil, nil
		}
	}

	// Dedup by host+path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	dedupKey := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	// Parse response headers
	var cacheControl, vary string
	hasSetCookie := false
	for _, hdr := range ctx.Response().Headers() {
		nameLower := strings.ToLower(hdr.Name)
		switch nameLower {
		case "cache-control":
			cacheControl = strings.ToLower(hdr.Value)
		case "vary":
			vary = strings.ToLower(hdr.Value)
		case "set-cookie":
			hasSetCookie = true
		}
	}

	// Check if response is cacheable
	if !isCacheable(cacheControl) {
		return nil, nil
	}

	// Check for Authorization in request
	hasAuthReq := ctx.Request().Header("Authorization") != ""

	// No user-specific indicators
	if !hasSetCookie && !hasAuthReq {
		return nil, nil
	}

	// Check for missing Vary headers
	var issues []string
	if hasSetCookie && !strings.Contains(vary, "cookie") {
		issues = append(issues, "Set-Cookie present but missing Vary: Cookie")
	}
	if hasAuthReq && !strings.Contains(vary, "authorization") {
		issues = append(issues, "Authorization in request but missing Vary: Authorization")
	}

	if len(issues) == 0 {
		return nil, nil
	}

	extracted := append(issues, fmt.Sprintf("Cache-Control: %s", cacheControl))
	if vary != "" {
		extracted = append(extracted, fmt.Sprintf("Vary: %s", vary))
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             urlx.Host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "Cache-Auth Misconfiguration",
				Description: fmt.Sprintf("Cacheable response at %s has user-specific data without proper Vary headers: %s", urlx.Path, strings.Join(issues, "; ")),
				Severity:    ModuleSeverity,
				Confidence:  ModuleConfidence,
				Tags:        []string{"cache", "authentication", "vary", "misconfiguration"},
				Reference:   []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary"},
			},
		},
	}, nil
}

// isCacheable checks if the Cache-Control header indicates the response is publicly cacheable.
func isCacheable(cc string) bool {
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
		return false
	}
	return strings.Contains(cc, "public") || strings.Contains(cc, "s-maxage")
}
