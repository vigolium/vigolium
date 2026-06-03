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
// search for in the response.
type reflectionPayload struct {
	payload string
	marker  string
	name    string
}

var reflectionPayloads = []reflectionPayload{
	{`<h1>VIGOLIUM_PDF_PROBE_7x8k2</h1>`, "VIGOLIUM_PDF_PROBE_7x8k2", "html-reflection"},
	{`<img src="x" onerror="document.write('VIGOLIUM_PDF_PROBE_7x8k2')">`, "VIGOLIUM_PDF_PROBE_7x8k2", "js-execution"},
	{`<link rel="stylesheet" href="http://127.0.0.1:0/VIGOLIUM_PDF_SSRF">`, "VIGOLIUM_PDF_SSRF", "ssrf-link"},
	{`<iframe src="file:///etc/hostname"></iframe>`, "", "file-read-iframe"},
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
		contentType := resp.FullResponseString()

		isPDF := isPDFResponse(body, contentType)
		markerFound := rp.marker != "" && strings.Contains(body, rp.marker)

		// For the file-read payload (no marker), flag if the response is a PDF
		// with non-trivial content that doesn't look like a normal HTML page.
		fileReadHit := rp.marker == "" && isPDF && len(body) > 0

		if markerFound || (isPDF && rp.marker != "") || fileReadHit {
			detail := rp.name
			if markerFound {
				detail = fmt.Sprintf("%s (marker %q reflected)", rp.name, rp.marker)
			} else if isPDF {
				detail = fmt.Sprintf("%s (PDF response detected)", rp.name)
			}

			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Matched:          urlx.String(),
				Request:          string(fuzzedRaw),
				Response:         resp.FullResponseString(),
				FuzzingParameter: ip.Name(),
				ExtractedResults: []string{rp.payload, detail},
				Info: output.Info{
					Name:        fmt.Sprintf("PDF Generation Injection: %s", rp.name),
					Description: fmt.Sprintf("Injected %q into parameter %q — %s", rp.payload, ip.Name(), detail),
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
