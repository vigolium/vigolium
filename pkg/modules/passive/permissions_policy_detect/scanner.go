package permissions_policy_detect

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// sensitiveFeatures lists browser features that should not be granted to all origins.
var sensitiveFeatures = []string{
	"camera",
	"microphone",
	"geolocation",
	"payment",
	"usb",
}

// Module implements the Permissions Policy Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Permissions Policy Detect module.
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
		ds: dedup.LazyDiskSet("passive_permissions_policy_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerHost checks Permissions-Policy and Feature-Policy headers once per host.
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

	// Only check HTML responses
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "text/html") {
		return nil, nil
	}

	permissionsPolicy := ctx.Response().Header("Permissions-Policy")
	featurePolicy := ctx.Response().Header("Feature-Policy")

	var issues []string

	if permissionsPolicy == "" && featurePolicy == "" {
		issues = append(issues, "Neither Permissions-Policy nor Feature-Policy header is present")
	}

	// Check Permissions-Policy for overly permissive directives
	// Format: camera=*, microphone=(self "https://example.com"), etc.
	if permissionsPolicy != "" {
		lower := strings.ToLower(permissionsPolicy)
		for _, feature := range sensitiveFeatures {
			pattern := feature + "=*"
			if strings.Contains(lower, pattern) {
				issues = append(issues, fmt.Sprintf("Permissions-Policy: %s=* grants %s access to all origins", feature, feature))
			}
		}
	}

	// Check legacy Feature-Policy for overly permissive directives
	// Format: camera *; microphone 'self' https://example.com
	if featurePolicy != "" {
		issues = append(issues, "Legacy Feature-Policy header detected (superseded by Permissions-Policy)")
		lower := strings.ToLower(featurePolicy)
		directives := strings.Split(lower, ";")
		for _, directive := range directives {
			directive = strings.TrimSpace(directive)
			for _, feature := range sensitiveFeatures {
				if strings.HasPrefix(directive, feature) {
					// Check if wildcard is present after the feature name
					rest := strings.TrimPrefix(directive, feature)
					rest = strings.TrimSpace(rest)
					if rest == "*" || strings.HasPrefix(rest, " *") {
						issues = append(issues, fmt.Sprintf("Feature-Policy: %s * grants %s access to all origins", feature, feature))
					}
				}
			}
		}
	}

	if len(issues) == 0 {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	return []*output.ResultEvent{
		{
			Host:             host,
			URL:              urlx.String(),
			Request:          string(ctx.Request().Raw()),
			ExtractedResults: issues,
			Info: output.Info{
				Description: fmt.Sprintf("Permissions policy audit: %d issue(s) found", len(issues)),
			},
		},
	}, nil
}
