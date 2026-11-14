package aem_fingerprint

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	aeminfra "github.com/vigolium/vigolium/pkg/modules/infra/aem"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// Module implements the AEM fingerprinting passive scanner. It marks the tech
// registry with "aem"/"adobe" so the active aem_* family gates onto real AEM.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new AEM Fingerprint module.
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
		ds: dedup.LazyDiskSet("aem_fingerprint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes the response to identify AEM installations.
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
	ok, signals := aeminfra.MatchResponse(resp.StatusCode(), resp.Header, resp.BodyToString())
	if !ok {
		// Do not claim the host as seen on a non-AEM response — a later response
		// (e.g. the app shell after a static asset) may still reveal AEM.
		return nil, nil
	}

	// Mark tech first (idempotent) so sibling active modules gate on it even if two
	// AEM responses race; then claim the host so the finding is emitted once.
	scanCtx.MarkTech(host, aeminfra.Tag)
	scanCtx.MarkTech(host, aeminfra.TagAdobe)
	scanCtx.MarkTech(host, "java")

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.Contains(host) {
		return nil, nil
	}

	metadata := map[string]any{"cms": "aem"}
	name := "Technology Detected: Adobe Experience Manager"
	if version := aeminfra.ExtractVersion(resp.Header); version != "" {
		metadata["version"] = version
		signals = append(signals, "version: "+version)
		name = "Technology Detected: Adobe Experience Manager " + version
	}

	// Claim the host only now that it matched (MISS-19): a host whose
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
				Name:        name,
				Description: "Identified an Adobe Experience Manager installation via " + strings.Join(signals, ", "),
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"cms", "fingerprint", "aem", "adobe"},
			},
			Metadata: metadata,
		},
	}, nil
}
