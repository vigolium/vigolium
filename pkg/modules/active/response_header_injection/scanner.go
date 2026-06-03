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
		location, fuzzedRawStr, evidence, found, err := m.probePayload(ctx, ip, httpClient, p, m.canary, m.headerPattern)
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

		// RQP-amplification consult: only enriches an already-confirmed finding —
		// the detection flow above is untouched.
		rqpAmplified, rqpEvidence := infra.RQPAmplification(ctx.Response())
		results = append(results, m.buildResult(urlx.String(), ip.Name(), p.name, location, fuzzedRawStr, evidence, rqpAmplified, rqpEvidence))
		return results, nil
	}

	return results, nil
}

// probePayload sends payload p (already built for `canary`) into the insertion
// point and reports whether the canary was reflected as an injected response
// header or body, using all three detection methods. The returned location and
// evidence describe the match.
func (m *Module) probePayload(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	p payload,
	canary string,
	pattern *regexp.Regexp,
) (location, fuzzedRawStr, evidence string, found bool, err error) {
	var fuzzedRaw []byte
	if p.rawInject {
		// For URL-encoded payloads (%0d%0a), inject directly into the raw request
		// bytes to avoid double-encoding by the insertion point encoder.
		fuzzedRaw = m.injectRawPayload(ctx.Request().Raw(), ip, fmt.Sprintf(p.tmpl, ip.BaseValue()))
	} else {
		fuzzedRaw = ip.BuildRequest([]byte(fmt.Sprintf(p.tmpl, ip.BaseValue())))
	}
	if fuzzedRaw == nil {
		return "", "", "", false, nil
	}

	fuzzedReq, perr := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if perr != nil {
		return "", "", "", false, nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, rerr := httpClient.Execute(fuzzedReq, http.Options{})
	if rerr != nil {
		return "", "", "", false, rerr
	}
	defer resp.Close()

	headersStr := resp.Headers().String()

	// Method 1: regex match on raw header dump (works for HTTP/1.1)
	if pattern.MatchString(headersStr) {
		return "response_header", string(fuzzedRaw), headersStr, true, nil
	}

	// Method 2: check parsed response headers for the injected header (works for HTTP/2
	// where Go's client parses injected headers as proper key-value pairs)
	if nativeResp := resp.Response(); nativeResp != nil {
		if v := nativeResp.Header.Get("X-Injected"); strings.Contains(v, canary) {
			return "response_header", string(fuzzedRaw), headersStr, true, nil
		}
		for _, cookie := range nativeResp.Cookies() {
			if cookie.Name == "injected" && strings.Contains(cookie.Value, canary) {
				return "response_header", string(fuzzedRaw), headersStr, true, nil
			}
		}
	}

	// Method 3: check if CRLF+body injection succeeded (canary in body after double CRLF)
	if strings.Contains(p.name, "body-break") {
		fullResp := resp.FullResponseString()
		if strings.Contains(fullResp, "<injected>"+canary+"</injected>") {
			return "response_body_injection", string(fuzzedRaw), fullResp, true, nil
		}
	}

	return "", string(fuzzedRaw), headersStr, false, nil
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
		_, _, _, found, perr := m.probePayload(ctx, ip, httpClient, p, canary, headerPatternFor(canary))
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

func (m *Module) buildResult(url, paramName, payloadName, location, request, response string, rqpAmplified bool, rqpEvidence string) *output.ResultEvent {
	extracted := []string{
		"payload=" + payloadName,
		"canary=" + m.canary,
		"location=" + location,
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
