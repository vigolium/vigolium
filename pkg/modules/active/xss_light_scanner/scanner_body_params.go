package xss_light_scanner

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/spitolas"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// BodyParamsModule tests reflected XSS in request BODY parameters (form, JSON,
// XML, multipart). The URL scanner reaches body parameters only through its
// POST→GET conversion, which misses every handler that reads the body alone.
//
// A body parameter is only probed when its base value already reflects in the
// stored response (a passive reflection prefilter): it is the cheap signal that
// the parameter reaches the page at all.
//
// Findings on a non-navigable request (anything but GET) cannot be confirmed in
// a browser from a link and are filed at the HTTP-breakout tier as
// Suspect/Tentative: the executable payload survived unescaped, nothing more.
type BodyParamsModule struct {
	modkit.BaseActiveModule
	rhm  dedup.Lazy[dedup.RequestHashManager]
	scan *URLParamsModule // shared canary/phase engine (analyzers, prefixes)

	// Probe runs the headless-browser confirmation step. Overridable so tests
	// never spawn a real browser. Default: spitolas.ProbeURL.
	Probe ProbeFunc
}

// NewBodyParamsScanner creates the body-parameter XSS scanner.
func NewBodyParamsScanner() *BodyParamsModule {
	m := &BodyParamsModule{
		BaseActiveModule: modkit.NewBaseActiveModule(
			BodyParamsModuleID,
			BodyParamsModuleName,
			BodyParamsModuleDesc,
			BodyParamsModuleShort,
			BodyParamsModuleConfirmation,
			BodyParamsModuleSeverity,
			BodyParamsModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.BodyParamTypes,
		),
		rhm:   dedup.LazyDefaultRHM("xss_light_body"),
		scan:  NewURLParamsScanner(),
		Probe: spitolas.ProbeURL,
	}
	m.ModuleTags = ModuleTags
	return m
}

// VulnClass shares the reflected-XSS class with the other xss-light variants.
func (m *BodyParamsModule) VulnClass() string { return modkit.VulnClassXSS }

// ClassPriority: HTTP-only canary reflection is the cheap in-band technique.
func (m *BodyParamsModule) ClassPriority() int { return modkit.ClassCostInBand }

// CanProcess accepts requests with a body.
func (m *BodyParamsModule) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	return ctx != nil && ctx.Request() != nil && len(ctx.Request().Body()) > 0
}

// isBodyParamType reports whether t is a body value point this scanner tests.
func isBodyParamType(t httpmsg.InsertionPointType) bool {
	switch t {
	case httpmsg.INS_PARAM_BODY, httpmsg.INS_PARAM_JSON, httpmsg.INS_PARAM_XML,
		httpmsg.INS_PARAM_MULTIPART_ATTR:
		return true
	}
	return false
}

// reflectsInBase is the passive prefilter: the parameter's own value must
// already appear in the stored response.
func reflectsInBase(baseBody string, ip httpmsg.InsertionPoint) bool {
	v := strings.TrimSpace(ip.BaseValue())
	return len(v) >= 3 && baseBody != "" && strings.Contains(baseBody, v)
}

// ScanPerRequest probes each reflecting body parameter.
func (m *BodyParamsModule) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	if !infra.IsValidForInjectionVulns(urlx, ctx) || !ctx.HasResponse() {
		return nil, nil
	}
	baseBody := ctx.Response().BodyToString()
	if baseBody == "" {
		return nil, nil
	}

	points, err := scanCtx.GetInsertionPoints(ctx.Request().Raw(), ctx.Request().ID(), true)
	if err != nil {
		return nil, err
	}
	var bodyPoints []httpmsg.InsertionPoint
	for _, ip := range points {
		if isBodyParamType(ip.Type()) && reflectsInBase(baseBody, ip) {
			bodyPoints = append(bodyPoints, ip)
		}
	}
	if len(bodyPoints) == 0 {
		return nil, nil
	}
	if rhm := m.rhm.Get(scanCtx.DedupMgr()); rhm != nil {
		bodyPoints = rhm.GetNotCheckedInsertionPoints(urlx, ctx.Request(), bodyPoints)
	}

	navigable := strings.EqualFold(ctx.Request().Method(), "GET")
	var results []*output.ResultEvent
	for _, ip := range bodyPoints {
		if scanCtx.ParamAlreadyFound(ctx, ip.Name(), m.VulnClass()) {
			continue
		}
		result, err := m.scan.scanInsertionPointWithPrefixes(ctx, ip, baseBody, httpClient)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}
		if result == nil || !result.HasVulnerability() {
			continue
		}
		evt := confirmXSS(m.Probe, ctx, ip, result, httpClient, "[body] ", nil)
		if evt == nil {
			continue
		}
		evt.ModuleID = BodyParamsModuleID
		if !navigable {
			gradeNonNavigable(evt)
		}
		results = append(results, evt)
	}
	return results, nil
}

// gradeNonNavigable caps a finding on a request a victim cannot be sent to by
// a link (POST/PUT/… body) at Suspect/Tentative: the HTTP breakout is real but
// exploitation needs a cross-site form or a stored path, which this module does
// not prove.
func gradeNonNavigable(evt *output.ResultEvent) {
	if evt.Info.Severity > severity.Suspect {
		if evt.Metadata == nil {
			evt.Metadata = map[string]any{}
		}
		evt.Metadata["claimed_severity"] = evt.Info.Severity.String()
	}
	evt.Info.Severity = severity.Suspect
	evt.Info.Confidence = severity.Tentative
	evt.Info.Description = "Potential " + evt.Info.Description +
		" — the request is not navigable (body parameter), so it was not browser-confirmed; exploitation needs a cross-site form or another delivery path"
}
