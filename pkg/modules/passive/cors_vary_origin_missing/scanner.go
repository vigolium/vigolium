package cors_vary_origin_missing

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

// Module implements the CORS Vary Origin Missing passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new CORS Vary Origin Missing module.
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
		ds: dedup.LazyDiskSet("passive_cors_vary_origin_missing"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes responses for dynamic CORS headers missing Vary: Origin.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	if ctx.Response() == nil {
		return nil, nil
	}

	// Check for Access-Control-Allow-Origin header
	acao := ctx.Response().Header("Access-Control-Allow-Origin")
	if acao == "" {
		return nil, nil
	}

	// Only flag dynamic (non-wildcard) ACAO values
	if acao == "*" {
		return nil, nil
	}

	// Check if Vary header includes Origin
	vary := ctx.Response().Header("Vary")
	varyContainsOrigin := false
	for _, part := range strings.Split(vary, ",") {
		if strings.EqualFold(strings.TrimSpace(part), "Origin") {
			varyContainsOrigin = true
			break
		}
	}

	if varyContainsOrigin {
		return nil, nil
	}

	// Dedup by host + path + ACAO value
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s%s", urlx.Host, urlx.Path, acao))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	acac := ctx.Response().Header("Access-Control-Allow-Credentials")
	resultSeverity := severity.Low
	var issues []string

	issues = append(issues, fmt.Sprintf("Dynamic ACAO (%s) without Vary: Origin header", acao))

	if strings.EqualFold(acac, "true") {
		issues = append(issues, "Access-Control-Allow-Credentials: true amplifies cache poisoning risk")
	}

	return []*output.ResultEvent{
		{
			Host:    urlx.Host,
			URL:     urlx.String(),
			Request: string(ctx.Request().Raw()),
			ExtractedResults: []string{
				fmt.Sprintf("ACAO: %s", acao),
				fmt.Sprintf("Vary: %s", vary),
				fmt.Sprintf("ACAC: %s", acac),
			},
			Info: output.Info{
				Name:        "CORS Missing Vary: Origin",
				Description: strings.Join(issues, "; "),
				Severity:    resultSeverity,
				Confidence:  severity.Firm,
				Tags:        []string{"cors", "cache-poisoning", "vary"},
			},
		},
	}, nil
}
