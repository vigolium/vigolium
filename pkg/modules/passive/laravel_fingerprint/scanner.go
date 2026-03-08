package laravel_fingerprint

import (
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/pkg/errors"
)

// Module implements the Laravel Fingerprint passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Laravel Fingerprint module.
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
		ds: dedup.LazyDiskSet("laravel_fingerprint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
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

	hdr := func(name string) string { return ctx.Response().Header(name) }
	body := ctx.Response().BodyToString()

	var extracted []string
	meta := map[string]any{
		"platform": "laravel",
	}

	// Cookie signals
	hasLaravelSession := false
	hasXSRFToken := false
	for _, h := range ctx.Response().Headers() {
		if !strings.EqualFold(h.Name, "Set-Cookie") {
			continue
		}
		cookieLower := strings.ToLower(h.Value)
		if strings.HasPrefix(cookieLower, "laravel_session=") {
			hasLaravelSession = true
			extracted = append(extracted, "Cookie: laravel_session")
		}
		if strings.HasPrefix(cookieLower, "xsrf-token=") {
			hasXSRFToken = true
			extracted = append(extracted, "Cookie: XSRF-TOKEN")
		}
	}

	// Body signals (HTML only)
	ct := strings.ToLower(hdr("Content-Type"))
	hasCsrfMeta := false
	if strings.Contains(ct, "text/html") {
		if strings.Contains(body, `name="csrf-token"`) || strings.Contains(body, `name='csrf-token'`) {
			hasCsrfMeta = true
			extracted = append(extracted, "Body: csrf-token meta tag")
		}
	}

	// Error page signals
	hasIlluminate := false
	illuminatePatterns := []string{"Illuminate\\", "vendor/laravel/framework"}
	for _, pat := range illuminatePatterns {
		if strings.Contains(body, pat) {
			hasIlluminate = true
			extracted = append(extracted, "Body: "+pat)
		}
	}

	// Error handler signals
	if strings.Contains(body, "Spatie\\LaravelIgnition") || strings.Contains(body, "facade\\ignition") {
		extracted = append(extracted, "Body: Ignition error handler")
		meta["errorHandler"] = "ignition"
	}
	if strings.Contains(body, "Whoops\\") || strings.Contains(body, "filp/whoops") {
		extracted = append(extracted, "Body: Whoops error handler")
		meta["errorHandler"] = "whoops"
	}

	// Sanctum indicator
	hasSanctum := false
	if strings.Contains(strings.ToLower(urlx.Path), "/sanctum/csrf-cookie") {
		hasSanctum = true
		extracted = append(extracted, "Path: /sanctum/csrf-cookie")
		meta["hasSanctum"] = true
	}

	// Passport indicator
	if strings.Contains(body, "Laravel\\Passport") {
		extracted = append(extracted, "Body: Laravel\\Passport")
		meta["hasPassport"] = true
	}

	// X-Powered-By header
	poweredBy := hdr("X-Powered-By")
	if strings.Contains(poweredBy, "PHP") {
		extracted = append(extracted, "Header: X-Powered-By: "+poweredBy)
	}

	// Count independent signal categories for confidence
	signalCount := 0
	if hasLaravelSession {
		signalCount++
	}
	if hasXSRFToken {
		signalCount++
	}
	if hasCsrfMeta {
		signalCount++
	}
	if hasIlluminate {
		signalCount++
	}
	if hasSanctum {
		signalCount++
	}

	// Require 2+ signals to report (per document guidance)
	if signalCount < 2 {
		return nil, nil
	}

	desc := "Laravel installation detected"
	if _, ok := meta["errorHandler"]; ok {
		desc += " with " + meta["errorHandler"].(string) + " error handler"
	}
	if hasSanctum {
		desc += " (Sanctum SPA auth)"
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: extracted,
			Info: output.Info{
				Name:        "Laravel Installation Detected",
				Description: desc,
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"php", "laravel", "fingerprint"},
				Reference:   []string{"https://laravel.com/docs"},
			},
			Metadata: meta,
		},
	}, nil
}
