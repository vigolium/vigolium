package esi_injection

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

// The in-band oracle is TAG ADJACENCY: the probe is `<L><esi:comment …/><R>`
// with L and R freshly minted per call, and the needle is "LR". Only something
// that removed the element can put the two tags side by side; reflection in any
// encoding keeps bytes of the element between them.
//
// Removal alone is an absence signal, and absence oracles fire on any
// transformation (see ssi_injection, whose absence-based predecessor filed
// ~113 false positives): a sanitizer or WAF that strips every <tag> also makes
// L and R adjacent. The control round discriminates: `<L2><vgx:comment …/><R2>`
// is the same element in a namespace no ESI processor handles. A real ESI edge
// leaves it in place (no "L2R2"); a generic tag stripper removes it too, and
// that match rules the target out.
//
// esi:comment is used rather than an unknown esi:* element because it is part
// of ESI 1.0 and every mainstream processor (Varnish, Fastly, Akamai, Squid)
// removes it, while the handling of unknown esi:* elements varies.
const (
	esiElement     = `<esi:comment text="vigolium"/>`
	controlElement = `<vgx:comment text="vigolium"/>`

	// injectionType labels the OAST include leg; the URL is minted with
	// oastclass.ESI so the include fetch is rated as ESI injection.
	injectionType = "esi include"
)

// Module implements the ESI injection active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new ESI injection module.
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
			modkit.AllParamTypes,
		),
		rhm: dedup.LazyDefaultRHM("esi_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// VulnClass enables cross-module dedup of ESI findings per (URL, param).
func (m *Module) VulnClass() string { return "esi" }

// ConfirmsByBodyDifferential opts the in-band finding into the executor's
// replay-and-baseline safety net: the adjacent tag pair must reproduce on a
// replay and be absent from the clean baseline. Out-of-band findings are raised
// by the OAST service and never pass through this net.
func (m *Module) ConfirmsByBodyDifferential() bool { return true }

// ScanPerInsertionPoint runs the in-band adjacency probe and, when the input
// is reflected but not evaluated, plants an out-of-band esi:include.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
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

	// ESI processors run over text bodies of any media type, so only binary
	// responses are skipped.
	if r := ctx.Response(); r != nil && modkit.ClassifyContentType(r.Header("Content-Type")) == modkit.ContentClassBinary {
		return nil, nil
	}

	urlStr := urlx.String()
	finding, reached := m.confirmProcessing(ctx, ip, httpClient, urlStr)
	if finding != nil {
		return []*output.ResultEvent{finding}, nil
	}
	// The include leg only makes sense where the input reached a rendered
	// response: that is where an ESI processor would see it.
	if reached {
		m.fireIncludeOAST(ctx, ip, httpClient, scanCtx, urlStr)
	}
	return nil, nil
}

// confirmProcessing sends the probe and, on a match, the control. reached is
// true once the left tag shows up in a response the application rendered.
func (m *Module) confirmProcessing(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	urlStr string,
) (finding *output.ResultEvent, reached bool) {
	left, right := modkit.FreshCanary(), modkit.FreshCanary()
	probeRaw := ip.BuildRequest([]byte(left + esiElement + right))
	body, full, ok := renderedBody(ctx, httpClient, probeRaw, left+right)
	if !ok || !strings.Contains(body, left) {
		return nil, false
	}
	if !strings.Contains(body, left+right) {
		return nil, true
	}

	// Control: fresh tags so a cached probe response cannot answer for it.
	// Fail open on a transport error (a transient failure must not suppress a
	// real finding) and closed on a match (the stripper this round exists for).
	cl, cr := modkit.FreshCanary(), modkit.FreshCanary()
	controlRaw := ip.BuildRequest([]byte(cl + controlElement + cr))
	controlBody, controlFull, controlOK := renderedBody(ctx, httpClient, controlRaw, "")
	if controlOK && strings.Contains(controlBody, cl+cr) {
		return nil, true
	}

	ev := modkit.NewEvidenceCollector()
	ev.Add("baseline", modkit.CtxRequestRaw(ctx), modkit.CtxResponseRaw(ctx))
	ev.Add("control (non-ESI namespace, kept)", string(controlRaw), controlFull)

	return &output.ResultEvent{
		URL:                urlStr,
		Matched:            urlStr,
		Request:            string(probeRaw),
		Response:           full,
		AdditionalEvidence: ev.Entries(),
		FuzzingParameter:   ip.Name(),
		RecordKind:         output.RecordKindFinding,
		EvidenceGrade:      output.EvidenceGradeDifferential,
		ExtractedResults: []string{
			"esi_element=" + esiElement,
			"adjacent_tags=" + left + right,
		},
		Info: output.Info{
			Name:        ModuleName,
			Description: ModuleDesc,
			Severity:    ModuleSeverity,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
		},
	}, true
}

// renderedBody sends rawReq and returns its body only when the application
// rendered it: a WAF/CDN block or auth gate (IsBlockedResponse) echoes the URL
// on a page the origin never produced, and a 404 or 3xx ran no handler. full is
// the whole response, captured while the response is open, when keepIf is empty
// or present in the body.
func renderedBody(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	rawReq []byte,
	keepIf string,
) (body, full string, ok bool) {
	req := httpmsg.NewRequestResponseRaw(rawReq, ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
	if err != nil {
		return "", "", false
	}
	defer resp.Close()

	r := resp.Response()
	if r == nil || modkit.ClassifyContentType(r.Header.Get("Content-Type")) == modkit.ContentClassBinary {
		return "", "", false
	}
	if infra.IsBlockedResponse(resp) || !infra.IsErrorSurfaceStatus(resp) {
		return "", "", false
	}
	body = resp.Body().String()
	if keepIf == "" || strings.Contains(body, keepIf) {
		full = resp.FullResponseString()
	}
	return body, full, true
}

// fireIncludeOAST plants an esi:include pointing at a unique OAST host. A fetch
// of that host means an ESI processor evaluated the include.
func (m *Module) fireIncludeOAST(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
	urlStr string,
) {
	oast := scanCtx.OASTProv()
	if oast == nil || !oast.Enabled() {
		return
	}
	host := modkit.OASTURLFor(oast, oastclass.ESI, urlStr, ip.Name(), injectionType, ModuleID, ctx.Request().ID())
	if host == "" {
		return
	}
	payload := `<esi:include src="http://` + host + `/"/>`
	oast.RecordPayload(host, payload)
	req := httpmsg.NewRequestResponseRaw(ip.BuildRequest([]byte(payload)), ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		return
	}
	resp.Close()
}

// RequiresReflection opts into the executor's shared reflection probe
// (modkit.ReflectionAware): the oracle reads the payload back, so a
// point whose value does not come back is skipped.
func (m *Module) RequiresReflection() modkit.ReflectionNeed { return modkit.ReflectBody }

// HasOutOfBandLeg: the OAST include/exec leg needs no reflection, so the
// reflection gate applies only while OAST is off (modkit.OutOfBandLeg).
func (m *Module) HasOutOfBandLeg() bool { return true }
