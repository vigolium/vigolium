package salesforce_fingerprint

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	sf "github.com/vigolium/vigolium/pkg/modules/infra/salesforce"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Module fingerprints Salesforce Experience Cloud / Lightning sites and marks the
// tech registry so the active salesforce_* family gates onto real Salesforce.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

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
		ds: dedup.LazyDiskSet("salesforce_fingerprint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes the response to identify Salesforce installations.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if !ctx.HasResponse() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	host := urlx.Host

	var signals []string
	vendorHost := false
	for _, suf := range sf.VendorHostSuffixes {
		if strings.HasSuffix(host, suf) {
			vendorHost = true
			signals = append(signals, "vendor host: *"+suf)
			break
		}
	}

	ok, bodySignals := sf.MatchResponse(ctx.Response().BodyToString())
	signals = append(signals, bodySignals...)

	if !ok && !vendorHost {
		return nil, nil
	}

	scanCtx.MarkTech(host, sf.Tag)
	scanCtx.MarkTech(host, sf.TagLightning)
	scanCtx.MarkTech(host, "aura")

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
				Name:        "Technology Detected: Salesforce Experience Cloud",
				Description: "Identified a Salesforce Experience Cloud / Lightning (Aura) site via " + strings.Join(signals, ", "),
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"fingerprint", "salesforce", "aura", "lightning"},
			},
			Metadata: map[string]any{"platform": "salesforce"},
		},
	}, nil
}
