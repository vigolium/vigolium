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
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	detected := make(map[cloudProvider][]string)

	// Check response headers
	for _, hp := range headerPatterns {
		val := ctx.Response().Header(hp.header)
		if val != "" {
			detected[hp.provider] = append(detected[hp.provider], fmt.Sprintf("Header %s: %s", hp.header, val))
		}
	}

	// Check Server header
	serverHeader := ctx.Response().Header("Server")
	if serverHeader != "" {
		for _, sp := range serverPatterns {
			if strings.Contains(serverHeader, sp.match) {
				detected[sp.provider] = append(detected[sp.provider], fmt.Sprintf("Server: %s", serverHeader))
			}
		}
	}

	// Check if the request host itself is a cloud storage endpoint
	hostLower := strings.ToLower(host)
	for _, hp := range hostPatterns {
		if strings.Contains(hostLower, hp.suffix) {
			detected[hp.provider] = append(detected[hp.provider], fmt.Sprintf("Host: %s", host))
		}
	}

	// Check body for cloud storage URL patterns
	body := ctx.Response().BodyToString()
	if len(body) > 0 && len(body) < 1<<20 {
		for _, up := range urlPatterns {
			matches := up.re.FindAllString(body, 5)
			for _, match := range matches {
				detected[up.provider] = append(detected[up.provider], fmt.Sprintf("URL in body: %s", match))
			}
		}
	}

	if len(detected) == 0 {
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

	return results, nil
}
