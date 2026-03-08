package hsts_preload_audit

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

const minMaxAge = 31536000 // 1 year in seconds

// Module implements the HSTS Preload Audit passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new HSTS Preload Audit module.
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
			modkit.ScanScopeHost,
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("passive_hsts_preload_audit"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerHost checks HSTS header for preload readiness once per host.
func (m *Module) ScanPerHost(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	if ctx.Response() == nil {
		return nil, nil
	}

	// Only check HTTPS responses
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}
	if !strings.EqualFold(urlx.Scheme, "https") {
		return nil, nil
	}

	// Only check HTML responses
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "text/html") {
		return nil, nil
	}

	hsts := ctx.Response().Header("Strict-Transport-Security")

	var issues []string

	if hsts == "" {
		issues = append(issues, "Strict-Transport-Security header is missing on HTTPS response")
	} else {
		lower := strings.ToLower(hsts)
		directives := strings.Split(lower, ";")

		// Check max-age
		maxAgeFound := false
		maxAgeSufficient := false
		for _, d := range directives {
			d = strings.TrimSpace(d)
			if strings.HasPrefix(d, "max-age") {
				maxAgeFound = true
				parts := strings.SplitN(d, "=", 2)
				if len(parts) == 2 {
					val, err := strconv.Atoi(strings.TrimSpace(parts[1]))
					if err == nil && val >= minMaxAge {
						maxAgeSufficient = true
					}
				}
			}
		}

		if !maxAgeFound {
			issues = append(issues, "HSTS max-age directive is missing")
		} else if !maxAgeSufficient {
			issues = append(issues, fmt.Sprintf("HSTS max-age is below %d (1 year), required for preload", minMaxAge))
		}

		// Check includeSubDomains
		if !strings.Contains(lower, "includesubdomains") {
			issues = append(issues, "HSTS includeSubDomains directive is missing (required for preload)")
		}

		// Check preload
		if !strings.Contains(lower, "preload") {
			issues = append(issues, "HSTS preload directive is missing")
		}
	}

	if len(issues) == 0 {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			Host:             host,
			URL:              urlx.String(),
			Request:          string(ctx.Request().Raw()),
			ExtractedResults: issues,
			Info: output.Info{
				Description: fmt.Sprintf("HSTS preload audit: %d issue(s) found", len(issues)),
			},
		},
	}, nil
}
