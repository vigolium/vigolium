package powerpages_fingerprint

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	ppinfra "github.com/vigolium/vigolium/pkg/modules/infra/powerpages"
	"github.com/vigolium/vigolium/pkg/modules/infra/saasprobe"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Module fingerprints Microsoft Power Pages portals and marks the tech registry
// with "powerpages"/"dataverse" so the active powerpages_* family gates onto
// real portals.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Power Pages Fingerprint module.
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
		ds: dedup.LazyDiskSet("powerpages_fingerprint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes the response to identify Power Pages installations.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	host := urlx.Host

	resp := ctx.Response()

	var signals []string
	vendorHost := false
	for _, suf := range ppinfra.VendorHostSuffixes {
		if strings.HasSuffix(host, suf) {
			vendorHost = true
			signals = append(signals, "vendor host: *"+suf)
			break
		}
	}

	ok, bodySignals := ppinfra.MatchResponse(saasprobe.ResponseCookieNames(resp), resp.BodyToString())
	signals = append(signals, bodySignals...)

	if !ok && !vendorHost {
		// Do not claim the host as seen on a non-Power-Pages response — a later
		// response may still reveal the portal.
		return nil, nil
	}

	scanCtx.MarkTech(host, ppinfra.Tag)
	scanCtx.MarkTech(host, ppinfra.TagDataverse)
	scanCtx.MarkTech(host, "aspnet")

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.Contains(host) {
		return nil, nil
	}

	// Claim the host only now that it matched: a host whose
	// first response showed nothing stays open for later responses.
	if diskSet != nil && !diskSet.ClaimOnMatch(host) {
		return nil, nil
	}
	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			MatcherStatus:    true,
			ExtractedResults: signals,
			Info: output.Info{
				Name:        "Technology Detected: Microsoft Power Pages",
				Description: "Identified a Microsoft Power Pages / Power Apps portal via " + strings.Join(signals, ", "),
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"fingerprint", "powerpages", "dataverse", "microsoft"},
			},
			Metadata: map[string]any{"platform": "power-pages"},
		},
	}, nil
}
