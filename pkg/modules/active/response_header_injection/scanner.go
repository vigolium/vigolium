package response_header_injection

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

type payload struct {
	name      string
	tmpl      string // %s = canary token
	rawInject bool   // if true, inject directly into raw request bytes (skip URL encoding)
}

// Detection-location kinds returned by probePayload, ordered from the strongest
// to the weakest evidence of a genuine CRLF response-header injection.
const (
	// locResponseHeader: the injected canary landed in the response HEADER block
	// — a header value was split, or an injected header was parsed as a real
	// key/value pair. Unambiguous response-header injection.
	locResponseHeader = "response_header"
	// locBodyInjection: the injected CRLF actually terminated the header block,
	// so the canary marker is the *leading* content of the parsed response body.
	// Genuine HTTP response splitting.
	locBodyInjection = "response_body_injection"
	// locBodyReflection: the canary marker is reflected *inside* the legitimate
	// response body (CRLF bytes preserved as data, header block intact and well
	// formed). This is plain value reflection — e.g. the value echoed into a
	// JSON/XML string — NOT a confirmed CRLF response-header injection. Reported
	// at Suspect/Tentative and never escalated to RQP.
	locBodyReflection = "response_body_reflection"
)

type Module struct {
	modkit.BaseActiveModule
	canary        string
	payloads      []payload
	headerPattern *regexp.Regexp
	rhm           dedup.Lazy[dedup.RequestHashManager]
}

// buildHeaderPayloads returns the CRLF header-injection payload set carrying the
// given canary. The index of each payload is stable, so a successful technique
// can be replayed verbatim with a fresh canary during re-confirmation.
func buildHeaderPayloads(canary string) []payload {
	// Payloads inject CRLF + a synthetic header containing the canary.
	// Mirrors real-world vectors: value reflected into Set-Cookie, Location, or custom headers.
	return []payload{
		// URL-encoded payloads: inject directly into raw request to avoid double-encoding
		{name: "crlf-encoded", tmpl: "%s%%0d%%0aX-Injected:+" + canary, rawInject: true},
		{name: "crlf-encoded-upper", tmpl: "%s%%0D%%0AX-Injected:+" + canary, rawInject: true},
		{name: "crlf-double-encoded", tmpl: "%s%%250d%%250aX-Injected:+" + canary, rawInject: true},
		{name: "crlf-setcookie-encoded", tmpl: "%s%%0d%%0aSet-Cookie:+injected=" + canary, rawInject: true},
		{name: "crlf-body-break-encoded", tmpl: "%s%%0d%%0a%%0d%%0a<injected>" + canary + "</injected>", rawInject: true},
		{name: "crlf-unicode", tmpl: "%s%%e5%%98%%8a%%e5%%98%%8dX-Injected:+" + canary, rawInject: true},
		// Raw CRLF payloads: use BuildRequest which will URL-encode \r\n to %0D%0A
		{name: "crlf-header", tmpl: "%s\r\nX-Injected: " + canary},
		{name: "crlf-lf-only", tmpl: "%s\nX-Injected: " + canary},
		{name: "crlf-setcookie", tmpl: "%s\r\nSet-Cookie: injected=" + canary},
		{name: "crlf-body-break", tmpl: "%s\r\n\r\n<injected>" + canary + "</injected>"},
	}
}

// headerPatternFor returns the raw-header-dump match pattern for a given canary.
func headerPatternFor(canary string) *regexp.Regexp {
	return regexp.MustCompile(`(?mi)\n(?:X-Injected:\s*` + regexp.QuoteMeta(canary) + `|Set-Cookie:\s*injected=` + regexp.QuoteMeta(canary) + `)`)
}

func New() *Module {
	canary := "vigRHI" + utils.RandomString(8)

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
		canary:        canary,
		payloads:      buildHeaderPayloads(canary),
		headerPattern: headerPatternFor(canary),
		rhm:           dedup.LazyDefaultRHM("response_header_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

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

	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	var results []*output.ResultEvent

	for i, p := range m.payloads {
		location, fuzzedRawStr, evidence, contentType, found, err := m.probePayload(ctx, ip, httpClient, p, m.canary, m.headerPattern)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}
		if !found {
			continue
		}

		// Re-confirm before reporting: replay the SAME technique with fresh random
		// canaries across multiple rounds. A real injection copies the changing
		// attacker-controlled value into the response every round; a coincidental
		// match (or a server echoing a fixed string) will not track the canary.
		confirmed, cerr := m.confirmInjection(ctx, ip, httpClient, i)
		if cerr != nil {
			if errors.Is(cerr, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}
		if !confirmed {
			continue
		}

		// RQP-amplification consult: only enriches an already-confirmed *header*
		// injection — the detection flow above is untouched. A body-reflection
		// match never split the header stream, so it is not RQP-escalatable and
		// the amplification check is skipped entirely.
		var rqpAmplified bool
		var rqpEvidence string
		if location != locBodyReflection {
			rqpAmplified, rqpEvidence = infra.RQPAmplification(ctx.Response())
		}
		results = append(results, m.buildResult(urlx.String(), ip.Name(), p.name, location, contentType, fuzzedRawStr, evidence, rqpAmplified, rqpEvidence))
		return results, nil
	}

	return results, nil
}

// probePayload sends payload p (already built for `canary`) into the insertion
// point and reports whether the canary was reflected as an injected response
// header or body, using all three detection methods. The returned location,
// content type and evidence describe the match. The body-break method
// distinguishes a genuine header/body split from plain value reflection (see
// classifyBodyBreak), so a canary echoed into a JSON/XML body is not mistaken
// for a CRLF response-header injection.
func (m *Module) probePayload(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	p payload,
	canary string,
	pattern *regexp.Regexp,
) (location, fuzzedRawStr, evidence, contentType string, found bool, err error) {
	var fuzzedRaw []byte
	if p.rawInject {
		// For URL-encoded payloads (%0d%0a), inject directly into the raw request
		// bytes to avoid double-encoding by the insertion point encoder.
		fuzzedRaw = m.injectRawPayload(ctx.Request().Raw(), ip, fmt.Sprintf(p.tmpl, ip.BaseValue()))
	} else {
		fuzzedRaw = ip.BuildRequest([]byte(fmt.Sprintf(p.tmpl, ip.BaseValue())))
	}
	if fuzzedRaw == nil {
		return "", "", "", "", false, nil
	}

	fuzzedReq, perr := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if perr != nil {
		return "", "", "", "", false, nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, rerr := httpClient.Execute(fuzzedReq, http.Options{})
	if rerr != nil {
		return "", "", "", "", false, rerr
	}
	defer resp.Close()

	headersStr := resp.HeadersString()
	if nativeResp := resp.Response(); nativeResp != nil {
		contentType = nativeResp.Header.Get("Content-Type")
	}

	// Method 1: regex match on raw header dump (works for HTTP/1.1)
	if pattern.MatchString(headersStr) {
		return locResponseHeader, string(fuzzedRaw), headersStr, contentType, true, nil
	}

	// Method 2: check parsed response headers for the injected header (works for HTTP/2
	// where Go's client parses injected headers as proper key-value pairs)
	if nativeResp := resp.Response(); nativeResp != nil {
		if v := nativeResp.Header.Get("X-Injected"); strings.Contains(v, canary) {
			return locResponseHeader, string(fuzzedRaw), headersStr, contentType, true, nil
		}
		for _, cookie := range nativeResp.Cookies() {
			if cookie.Name == "injected" && strings.Contains(cookie.Value, canary) {
				return locResponseHeader, string(fuzzedRaw), headersStr, contentType, true, nil
			}
		}
	}

	// Method 3: body-break. The %0d%0a%0d%0a payload tries to terminate the header
	// block early so "<injected>canary</injected>" lands as raw response content.
	// The marker can surface in the full response for two very different reasons,
	// so classifyBodyBreak separates a genuine split from plain reflection.
	if strings.Contains(p.name, "body-break") {
		if loc, ev, ok := classifyBodyBreak(resp.HeadersString(), resp.BodyString(), resp.FullResponseString(), canary); ok {
			return loc, string(fuzzedRaw), ev, contentType, true, nil
		}
	}

	return "", string(fuzzedRaw), headersStr, contentType, false, nil
}

// classifyBodyBreak inspects a body-break probe response for the injected marker
// and returns the location kind describing *how* it appeared:
//
//   - locResponseHeader  — the marker *starts its own line* in the parsed HEADER
//     block: the injected CRLF survived into the response byte stream as a real
//     line terminator and began a new header line (genuine header injection).
//   - locBodyInjection   — the marker is the *leading* content of the parsed
//     body: the injected CRLF terminated the header block, so the original
//     value was consumed into a header and everything after the split became
//     body (genuine HTTP response splitting).
//   - locBodyReflection  — the marker is reflected *within* the legitimate body
//     (e.g. a JSON/XML string value) with its CRLF bytes preserved as data; the
//     header block was never split. Plain reflection, NOT a CRLF injection.
//
// ok is false when the marker is absent, OR when the marker appears only
// *mid-line inside an existing header value* (e.g. copied into a Set-Cookie or
// Location value with its CR/LF neutralised to spaces by a fronting proxy). That
// is value reflection into a header, not a CRLF split — the header block was
// never broken, so there is no injection to report. This is the discriminator
// for the CloudFront/SAML-login false positive where `idp=…%0d%0a%0d%0a<marker>`
// comes back as `Set-Cookie: idp=…  <marker>;Path=/` on a single line.
func classifyBodyBreak(headersStr, bodyStr, fullResp, canary string) (location, evidence string, ok bool) {
	marker := "<injected>" + canary + "</injected>"
	switch {
	case markerStartsHeaderLine(headersStr, marker):
		return locResponseHeader, headersStr, true
	case markerLeadsBody(bodyStr, marker):
		return locBodyInjection, fullResp, true
	case strings.Contains(bodyStr, marker):
		return locBodyReflection, fullResp, true
	default:
		return "", "", false
	}
}

// markerStartsHeaderLine reports whether the injected marker begins its own line
// within the raw response header dump — i.e. it is immediately preceded by a CR
// or LF byte that the server emitted as a real line terminator. That is the
// structural signature of a genuine CRLF split: the attacker-supplied newline
// survived into the response stream and started a fresh header line, so any HTTP
// parser on the wire would treat the marker as a new header.
//
// It deliberately rejects the marker appearing mid-line inside an existing
// header value (the CR/LF was stripped or collapsed to spaces by the app or a
// fronting cache/proxy). In that case the value was merely copied into one
// header and the header block was never split — no injection occurred.
func markerStartsHeaderLine(headersStr, marker string) bool {
	return strings.Contains(headersStr, "\n"+marker)
}

// markerLeadsBody reports whether the injected marker is the leading content of
// the response body (ignoring any leading CR/LF/whitespace left at the split
// point). In a genuine body-break the original parameter value is consumed into
// the header whose value the CRLF terminated, so the parsed body *begins* with
// the injected marker. When the server merely echoes the value into a structured
// body, the marker is preceded by the legitimate body (e.g. `{"id":"…`) and this
// returns false.
func markerLeadsBody(body, marker string) bool {
	return strings.HasPrefix(strings.TrimLeft(body, "\r\n \t"), marker)
}

// confirmInjection replays the technique at index techniqueIdx with a fresh
// random canary per round (via modkit.ConfirmReflection), requiring the canary
// to be reflected as an injected header/body every round.
func (m *Module) confirmInjection(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	techniqueIdx int,
) (bool, error) {
	return modkit.ConfirmReflection(2, func(canary string) (bool, error) {
		p := buildHeaderPayloads(canary)[techniqueIdx]
		_, _, _, _, found, perr := m.probePayload(ctx, ip, httpClient, p, canary, headerPatternFor(canary))
		return found, perr
	})
}

// injectRawPayload replaces the parameter value directly in the raw request bytes,
// bypassing URL encoding. This is necessary for payloads containing pre-encoded
// sequences like %0d%0a that would otherwise be double-encoded.
func (m *Module) injectRawPayload(rawRequest []byte, ip httpmsg.InsertionPoint, payload string) []byte {
	raw := string(rawRequest)
	originalValue := ip.BaseValue()
	paramName := ip.Name()

	// Find "paramName=originalValue" in the query string portion of the request line
	needle := paramName + "=" + originalValue
	idx := strings.Index(raw, needle)
	if idx < 0 {
		return nil
	}

	// Replace only the value part
	valueStart := idx + len(paramName) + 1
	valueEnd := valueStart + len(originalValue)
	result := raw[:valueStart] + payload + raw[valueEnd:]
	return []byte(result)
}

func (m *Module) buildResult(url, paramName, payloadName, location, contentType, request, response string, rqpAmplified bool, rqpEvidence string) *output.ResultEvent {
	extracted := []string{
		"payload=" + payloadName,
		"canary=" + m.canary,
		"location=" + location,
	}
	if contentType != "" {
		extracted = append(extracted, "content-type="+contentType)
	}

	// Reflection-only: the canary was echoed into the legitimate response body
	// (CRLF bytes preserved as data) but the header block was never split. This
	// is value reflection, not a confirmed CRLF response-header injection, so it
	// is reported at Suspect/Tentative and is NOT eligible for RQP escalation.
	if location == locBodyReflection {
		ctClause := ""
		if contentType != "" {
			ctClause = fmt.Sprintf(" (Content-Type %q indicates the value was echoed as a data string, not interpreted as headers)", contentType)
		}
		desc := fmt.Sprintf("Parameter %q is reflected into the response BODY using the %s payload: the injected canary %q, including its CRLF bytes, appeared inside the response body%s, but the HTTP header block was not split. "+
			"This is value reflection, not a confirmed CRLF/HTTP response-header injection — the server did not copy the input into a response header. Manual verification is recommended before treating this as response splitting.",
			paramName, payloadName, m.canary, ctClause)
		return &output.ResultEvent{
			URL:              url,
			Request:          request,
			Response:         response,
			FuzzingParameter: paramName,
			ExtractedResults: extracted,
			Info: output.Info{
				Description: desc,
				Severity:    severity.Suspect,
				Confidence:  severity.Tentative,
			},
		}
	}

	desc := fmt.Sprintf("HTTP response header injection via parameter %q using %s payload. "+
		"The injected canary %q appeared in the %s, confirming the server copies user input into response headers without sanitizing CRLF sequences.",
		paramName, payloadName, m.canary, location)

	info := output.Info{Description: desc}

	// RQP amplification: a confirmed header injection that rides an HTTP/1.1
	// keep-alive connection behind a pooling proxy can be escalated to Response
	// Queue Poisoning — poisoning the shared connection's response queue so other
	// users receive attacker-controlled responses. We flag the precondition and
	// raise severity, but deliberately never run the live cross-user confirmation,
	// which would expose another user's response.
	if rqpAmplified {
		extracted = append(extracted, "rqp-amplification="+rqpEvidence)
		info.Severity = severity.High
		info.Description = desc + fmt.Sprintf(" Escalation: the response is served over %s, so this injection is likely escalatable to Response Queue Poisoning (RQP), delivering attacker-controlled responses to other users on the shared connection. Live RQP confirmation is intentionally not attempted.", rqpEvidence)
	}

	return &output.ResultEvent{
		URL:              url,
		Request:          request,
		Response:         response,
		FuzzingParameter: paramName,
		ExtractedResults: extracted,
		Info:             info,
	}
}
