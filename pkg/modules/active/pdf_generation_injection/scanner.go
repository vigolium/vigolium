package pdf_generation_injection

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/spitolas/loginsig"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// pdfParamNames are parameter name substrings that suggest content/HTML input
// likely consumed by a server-side PDF generator.
var pdfParamNames = []string{
	"content", "html", "body", "text", "template", "data", "page", "url",
	"source", "input", "document", "report", "invoice", "receipt", "pdf",
	"print", "render", "export", "generate", "convert", "title",
	"description", "name", "comment", "message", "note",
}

// reflectionPayload defines an HTML/JS injection payload and the marker to
// search for in the response. A zero-value sev/conf inherits the module
// defaults (High/Firm); set them to override per variant.
type reflectionPayload struct {
	payload string
	marker  string
	name    string
	sev     severity.Severity
	conf    severity.Confidence
}

var reflectionPayloads = []reflectionPayload{
	// Plain HTML marker reflection alone doesn't prove server-side PDF
	// rendering — a normal reflection can echo it back — so this variant is
	// downgraded to Medium/Tentative.
	{`<h1>VIGOLIUM_PDF_PROBE_7x8k2</h1>`, "VIGOLIUM_PDF_PROBE_7x8k2", "html-reflection", severity.Medium, severity.Tentative},
	{`<img src="x" onerror="document.write('VIGOLIUM_PDF_PROBE_7x8k2')">`, "VIGOLIUM_PDF_PROBE_7x8k2", "js-execution", severity.Undefined, severity.ConfidenceUndefined},
	{`<link rel="stylesheet" href="http://127.0.0.1:0/VIGOLIUM_PDF_SSRF">`, "VIGOLIUM_PDF_SSRF", "ssrf-link", severity.Undefined, severity.ConfidenceUndefined},
	{`<iframe src="file:///etc/hostname"></iframe>`, "", "file-read-iframe", severity.Undefined, severity.ConfidenceUndefined},
}

// oastPayloadTemplates define HTML tags that trigger outbound connections.
// The %s placeholder is replaced with the OAST URL.
var oastPayloadTemplates = []struct {
	tmpl string
	name string
}{
	{`<img src="http://%s/pdf-ssrf">`, "oast-img"},
	{`<script>fetch('http://%s/pdf-ssrf')</script>`, "oast-script"},
	{`<link rel="stylesheet" href="http://%s/pdf-ssrf">`, "oast-link"},
	{`<iframe src="http://%s/pdf-ssrf"></iframe>`, "oast-iframe"},
}

// Module implements the PDF generation injection active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new PDF Generation Injection module.
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
		rhm: dedup.LazyDefaultRHM("pdf_generation_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint tests a single insertion point for PDF generation injection.
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

	// Only test parameters whose name suggests content/HTML input
	if !isPDFRelatedParam(ip.Name()) {
		return nil, nil
	}

	// Dedup by request hash + param via RHM
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	var results []*output.ResultEvent

	// --- Strategy 1: Reflection-based (no OAST needed) ---
	for _, rp := range reflectionPayloads {
		fuzzedRaw := ip.BuildRequest([]byte(rp.payload))

		fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		body := resp.Body().String()
		fullResp := resp.FullResponseString()
		contentType := ""
		if resp.Response() != nil {
			contentType = resp.Response().Header.Get("Content-Type")
		}

		sev, conf, detail, hit := classifyReflection(ctx, rp, body, fullResp, contentType)
		if hit {
			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Matched:          urlx.String(),
				Request:          string(fuzzedRaw),
				Response:         fullResp,
				FuzzingParameter: ip.Name(),
				ExtractedResults: []string{rp.payload, detail},
				Info: output.Info{
					Name:        fmt.Sprintf("PDF Generation Injection: %s", rp.name),
					Description: fmt.Sprintf("Injected %q into parameter %q — %s", rp.payload, ip.Name(), detail),
					Severity:    sev,
					Confidence:  conf,
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	// --- Strategy 2: OAST-based (if OAST provider available) ---
	oast := scanCtx.OASTProv()
	if oast == nil || !oast.Enabled() {
		return results, nil
	}

	requestHash := ctx.Request().ID()

	for _, ot := range oastPayloadTemplates {
		oastURL := oast.GenerateURL(urlx.String(), ip.Name(), "parameter", ModuleID, requestHash)
		if oastURL == "" {
			continue
		}

		payload := fmt.Sprintf(ot.tmpl, oastURL)
		fuzzedRaw := ip.BuildRequest([]byte(payload))

		fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}
		resp.Close()
	}

	// OAST results arrive asynchronously via polling callbacks
	return results, nil
}

// classifyReflection decides whether a probe response is genuine evidence of
// server-side PDF/HTML rendering, and at what severity. Two signals, strongest
// first:
//
//  1. The marker reflected inside an actual generated PDF document — the real
//     in-band PDF-generation signature. Reported at the variant's declared
//     severity (High/Firm for the JS/SSRF variants).
//  2. The injected HTML markup survived UNESCAPED in a non-PDF response. This is
//     only a weak reflected-HTML signal, so it is capped at Medium/Tentative and
//     gated against generic reflecting shells. Bare marker text echoing back
//     URL-/entity-encoded or wrapped inside a URL or attribute value — the
//     Cloudflare-Access / SSO-login redirect_url pattern, where the body is the
//     same with or without the probe — is NEUTRALIZED reflection that never
//     rendered as HTML, so it is dropped.
//
// hit is false (with zero sev/conf/detail) when the response is not evidence.
func classifyReflection(
	ctx *httpmsg.HttpRequestResponse,
	rp reflectionPayload,
	body, fullResp, contentType string,
) (severity.Severity, severity.Confidence, string, bool) {
	isPDF := isPDFResponse(body, fullResp)

	// file-read-iframe carries no marker: only an actual PDF body is evidence.
	if rp.marker == "" {
		if isPDF && len(body) > 0 {
			sev, conf := resolveSeverity(rp)
			return sev, conf, fmt.Sprintf("%s (PDF response detected)", rp.name), true
		}
		return severity.Undefined, severity.ConfidenceUndefined, "", false
	}

	// Signal 1: marker reflected inside a real generated PDF.
	if isPDF && strings.Contains(body, rp.marker) {
		sev, conf := resolveSeverity(rp)
		return sev, conf, fmt.Sprintf("%s (marker %q in PDF response)", rp.name, rp.marker), true
	}

	// Signal 2: non-PDF response. Require the injected HTML markup to have
	// survived UNESCAPED — the literal payload, tags intact — not merely the
	// bare marker text. A reflection that comes back URL-/entity-encoded or
	// wrapped in a URL never rendered as HTML and is not PDF-generation evidence.
	if !strings.Contains(body, rp.payload) {
		return severity.Undefined, severity.ConfidenceUndefined, "", false
	}
	if !reflectedHTMLIsGenuine(ctx, body, contentType) {
		return severity.Undefined, severity.ConfidenceUndefined, "", false
	}
	// A non-PDF reflection is not proof of server-side PDF generation, so it is
	// never more than Medium/Tentative regardless of the variant's declared
	// severity.
	return severity.Medium, severity.Tentative,
		fmt.Sprintf("%s (marker %q reflected unescaped)", rp.name, rp.marker), true
}

// resolveSeverity returns the variant's declared severity/confidence, falling
// back to the module defaults (High/Firm) for the zero-value variants.
func resolveSeverity(rp reflectionPayload) (severity.Severity, severity.Confidence) {
	sev, conf := rp.sev, rp.conf
	if sev == severity.Undefined {
		sev = ModuleSeverity
	}
	if conf == severity.ConfidenceUndefined {
		conf = ModuleConfidence
	}
	return sev, conf
}

// reflectedHTMLIsGenuine screens out non-PDF responses that echo any input back
// into the page without rendering a document: static assets (never HTML-to-PDF
// endpoints), the catch-all / SPA shell that is textually identical to the
// observed page with or without the probe, and SSO / login walls (Cloudflare
// Access and IdP consoles reflect redirect_url and similar params straight into
// the page). It returns true only when the reflecting response is none of those.
func reflectedHTMLIsGenuine(ctx *httpmsg.HttpRequestResponse, body, contentType string) bool {
	if modkit.IsStaticAssetContentType(contentType) {
		return false
	}
	if modkit.ResemblesObservedPage(ctx, body) {
		return false
	}
	// SSO / login wall — by URL (Cloudflare Access host & /cdn-cgi/access/ path,
	// IdP authorize endpoints) or by the rendered auth shell in the body.
	if u, err := ctx.URL(); err == nil && loginsig.LooksLikeLoginURL(u.URL) {
		return false
	}
	if loginsig.BodyLooksLikeLogin([]byte(body)) {
		return false
	}
	return true
}

// isPDFRelatedParam checks if a parameter name suggests content/HTML input
// that might be consumed by a PDF generator.
func isPDFRelatedParam(name string) bool {
	nameLower := strings.ToLower(name)
	for _, p := range pdfParamNames {
		if strings.Contains(nameLower, p) {
			return true
		}
	}
	return false
}

// isPDFResponse checks if the response looks like a PDF document based on
// content type or magic bytes.
func isPDFResponse(body, fullResponse string) bool {
	if strings.HasPrefix(body, "%PDF") {
		return true
	}
	respLower := strings.ToLower(fullResponse)
	if strings.Contains(respLower, "application/pdf") {
		return true
	}
	if strings.Contains(respLower, "content-type: pdf") {
		return true
	}
	return false
}
