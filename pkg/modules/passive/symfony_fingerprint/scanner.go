package symfony_fingerprint

import (
	"strings"

	"github.com/pkg/errors"
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
		ds: dedup.LazyDiskSet("symfony_fingerprint"),
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

	var evidence []string

	if xpb := ctx.Response().Header("X-Powered-By"); strings.Contains(strings.ToLower(xpb), "symfony") {
		evidence = append(evidence, "X-Powered-By: "+xpb)
	}
	if dt := ctx.Response().Header("X-Debug-Token"); dt != "" {
		evidence = append(evidence, "X-Debug-Token: "+dt)
	}

	for _, h := range ctx.Response().Headers() {
		if !strings.EqualFold(h.Name, "Set-Cookie") {
			continue
		}
		if strings.HasPrefix(h.Value, "sf_redirect=") {
			evidence = append(evidence, "Set-Cookie: sf_redirect")
			break
		}
		if strings.HasPrefix(h.Value, "MOCKSESSID=") {
			evidence = append(evidence, "Set-Cookie: MOCKSESSID")
			break
		}
	}

	if len(evidence) == 0 {
		body := ctx.Response().BodyToString()
		if strings.Contains(body, "/_wdt/") || strings.Contains(body, "/_profiler/") {
			evidence = append(evidence, "Body: Symfony Web Debug Toolbar / Profiler marker")
		}
	}

	if len(evidence) == 0 {
		return nil, nil
	}

	scanCtx.MarkTech(host, "symfony")
	scanCtx.MarkTech(host, "php")

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: evidence,
			Info: output.Info{
				Name:        "Symfony Application Detected",
				Description: "Symfony PHP framework detected from response headers / cookies / body markers",
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"symfony", "php", "fingerprint"},
			},
			Metadata: map[string]any{
				"platform": "symfony",
			},
		},
	}, nil
}
