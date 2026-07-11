package dom_xss_detect

import (
	"fmt"

	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
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
		ds: dedup.LazyDiskSet("passive_dom_xss_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes response body for DOM XSS patterns.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return results, nil
	}

	if ctx.Response() == nil || ctx.Response().BodyToString() == "" {
		return results, nil
	}

	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	hash := m.getHash(urlx)
	if diskSet != nil && diskSet.IsSeen(hash) {
		return results, nil
	}

	body := ctx.Response().BodyToString()

	highlighted := analyse(body)
	if highlighted != "" {
		results = append(results, &output.ResultEvent{
			ModuleID:      ModuleID,
			RecordKind:    output.RecordKindCandidate,
			EvidenceGrade: output.EvidenceGradeCandidate,
			DedupKey:      fmt.Sprintf("dom-xss-flow|%s|%s", urlx.Host, urlx.Path),
			URL:           urlx.String(),
			Host:          urlx.Host,
			Matched:       urlx.String(),
			Request:       string(ctx.Request().Raw()),
			Response:      string(ctx.Response().Raw()),
			Info: output.Info{
				Name:        "DOM XSS Source-to-Sink Candidate",
				Description: "DOM XSS candidate: a lightweight statement-local tracer connected browser-controlled data to an executable DOM sink. Browser execution and payload viability were not tested.\n```" + highlighted + "```",
				Severity:    ModuleSeverity,
				Confidence:  severity.Firm,
				Tags:        ModuleTags,
			},
			Metadata: map[string]any{"flow_engine": "lightweight", "connected_flow": true, "browser_execution_tested": false},
		})
	}

	redirectInfo := analyseOpenRedirect(body)
	if redirectInfo != "" {
		results = append(results, &output.ResultEvent{
			ModuleID:      ModuleID,
			RecordKind:    output.RecordKindCandidate,
			EvidenceGrade: output.EvidenceGradeCandidate,
			DedupKey:      fmt.Sprintf("dom-open-redirect-flow|%s|%s", urlx.Host, urlx.Path),
			URL:           urlx.String(),
			Host:          urlx.Host,
			Matched:       urlx.String(),
			Request:       string(ctx.Request().Raw()),
			Response:      string(ctx.Response().Raw()),
			Info: output.Info{
				Name:        "DOM Open Redirect Source-to-Sink Candidate",
				Description: "A lightweight statement-local tracer connected browser-controlled data to a navigation sink. Cross-origin navigation was not executed. " + redirectInfo,
				Severity:    ModuleSeverity,
				Confidence:  severity.Firm,
				Tags:        []string{"open-redirect", "javascript", "client-side"},
			},
			Metadata: map[string]any{"flow_engine": "lightweight", "connected_flow": true, "navigation_tested": false},
		})
	}

	return results, nil
}

func (m *Module) getHash(urlx *urlutil.URL) string {
	return utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
}
