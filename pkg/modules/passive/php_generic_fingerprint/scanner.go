package php_generic_fingerprint

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
		ds: dedup.LazyDiskSet("php_generic_fingerprint"),
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

	var version string
	var evidence []string

	poweredBy := ctx.Response().Header("X-Powered-By")
	if strings.HasPrefix(strings.ToLower(poweredBy), "php/") {
		version = strings.TrimPrefix(poweredBy, "PHP/")
		version = strings.TrimPrefix(version, "php/")
		evidence = append(evidence, "X-Powered-By: "+poweredBy)
	}

	for _, h := range ctx.Response().Headers() {
		if !strings.EqualFold(h.Name, "Set-Cookie") {
			continue
		}
		if strings.HasPrefix(h.Value, "PHPSESSID=") {
			evidence = append(evidence, "Set-Cookie: PHPSESSID")
			break
		}
	}

	hasPHPExtension := strings.HasSuffix(strings.ToLower(urlx.Path), ".php")
	if hasPHPExtension && len(evidence) == 0 {
		// .php alone is too weak — require a header or cookie signal
		return nil, nil
	}
	if hasPHPExtension {
		evidence = append(evidence, "URL ends in .php")
	}

	if len(evidence) == 0 {
		return nil, nil
	}

	scanCtx.MarkTech(host, "php")

	desc := "PHP application detected"
	if version != "" {
		desc = "PHP " + version + " detected"
	}

	return []*output.ResultEvent{
		{
			ModuleID:         ModuleID,
			Host:             host,
			URL:              urlx.String(),
			Matched:          urlx.String(),
			ExtractedResults: evidence,
			Info: output.Info{
				Name:        "PHP Application Detected",
				Description: desc,
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"php", "fingerprint"},
			},
			Metadata: map[string]any{
				"platform": "php",
				"version":  version,
			},
		},
	}, nil
}
