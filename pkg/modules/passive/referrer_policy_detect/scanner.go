package referrer_policy_detect

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// weakPolicies maps weak Referrer-Policy values to their risk description.
var weakPolicies = map[string]string{
	"unsafe-url":                 "Sends full URL as referrer to all origins, leaking path and query parameters",
	"no-referrer-when-downgrade": "Sends full URL on same-protocol requests, may leak sensitive path and query data",
}

// Module implements the Referrer Policy Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Referrer Policy Detect module.
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
		ds: dedup.LazyDiskSet("passive_referrer_policy_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerHost checks Referrer-Policy header once per host.
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

	policy := strings.TrimSpace(ctx.Response().Header("Referrer-Policy"))

	var issues []string

	if policy == "" {
		issues = append(issues, "Referrer-Policy header is missing; browser will use default policy which may leak URL information")
	} else {
		// Referrer-Policy can contain a comma-separated fallback list; check the last (effective) value
		parts := strings.Split(policy, ",")
		effective := strings.TrimSpace(parts[len(parts)-1])
		lower := strings.ToLower(effective)

		if desc, weak := weakPolicies[lower]; weak {
			issues = append(issues, fmt.Sprintf("Weak Referrer-Policy value '%s': %s", effective, desc))
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
				Description: strings.Join(issues, "; "),
			},
		},
	}, nil
}
