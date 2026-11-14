package cloud_storage_fingerprint

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

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
		ds: dedup.LazyDiskSet("passive_cloud_storage_fingerprint"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	host := urlx.Host

	detected := make(map[cloudProvider][]string)
	// discloses tracks providers backed by a bucket/account-disclosing indicator
	// — the request host being a raw storage endpoint, or a storage URL in the
	// body. Provider headers (x-amz-*, x-goog-*, x-ms-*) and the Server header
	// only reveal that content is *served through* a cloud CDN/store (every
	// static asset behind S3+CloudFront carries them) and never name a bucket, so
	// they are kept as corroboration but never trigger a finding on their own.
	discloses := make(map[cloudProvider]bool)

	// Check response headers (corroboration only — no bucket disclosure)
	for _, hp := range headerPatterns {
		val := ctx.Response().Header(hp.header)
		if val != "" {
			detected[hp.provider] = append(detected[hp.provider], fmt.Sprintf("Header %s: %s", hp.header, val))
		}
	}

	// Check Server header (corroboration only — no bucket disclosure)
	serverHeader := ctx.Response().Header("Server")
	if serverHeader != "" {
		for _, sp := range serverPatterns {
			if strings.Contains(serverHeader, sp.match) {
				detected[sp.provider] = append(detected[sp.provider], fmt.Sprintf("Server: %s", serverHeader))
			}
		}
	}

	// Check if the request host itself is a cloud storage endpoint (discloses the bucket host)
	hostLower := strings.ToLower(host)
	for _, hp := range hostPatterns {
		if strings.Contains(hostLower, hp.suffix) {
			detected[hp.provider] = append(detected[hp.provider], fmt.Sprintf("Host: %s", host))
			discloses[hp.provider] = true
		}
	}

	// Check body for cloud storage URL patterns (discloses bucket/account)
	body := ctx.Response().BodyToString()
	if len(body) > 0 && len(body) < 1<<20 {
		for _, up := range urlPatterns {
			matches := up.re.FindAllString(body, 5)
			for _, match := range matches {
				detected[up.provider] = append(detected[up.provider], fmt.Sprintf("URL in body: %s", match))
				discloses[up.provider] = true
			}
		}
	}

	// Drop providers detected only via response headers/Server — those are pure
	// tech fingerprints with no actionable bucket to probe.
	for provider := range detected {
		if !discloses[provider] {
			delete(detected, provider)
		}
	}
	if len(detected) == 0 {
		return nil, nil
	}

	// Only now that there is something worth reporting do we consume the per-host
	// dedup slot, so a header-only response can't silence a later response from
	// the same host that actually names a bucket.
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.Contains(host) {
		return nil, nil
	}

	var results []*output.ResultEvent
	for provider, evidence := range detected {
		results = append(results, &output.ResultEvent{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: evidence,
			Info: output.Info{
				Name:        fmt.Sprintf("Cloud Storage Detected: %s", provider),
				Description: fmt.Sprintf("Detected %s cloud storage service via %d indicator(s)", provider, len(evidence)),
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"cloud-storage", "fingerprint", strings.ToLower(strings.ReplaceAll(string(provider), " ", "-"))},
			},
		})
	}

	// Claim the host only now that it matched (MISS-19): a host whose
	// first response showed nothing stays open for later responses.
	if len(results) > 0 && diskSet != nil && !diskSet.ClaimOnMatch(host) {
		return nil, nil
	}
	return results, nil
}
