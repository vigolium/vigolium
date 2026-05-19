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
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
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

func New() *Module {
	canary := "vigRHI" + utils.RandomString(8)

	// Payloads inject CRLF + a synthetic header containing the canary.
	// Mirrors real-world vectors: value reflected into Set-Cookie, Location, or custom headers.
	payloads := []payload{
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
		payloads:      payloads,
		headerPattern: regexp.MustCompile(`(?mi)\n(?:X-Injected:\s*` + regexp.QuoteMeta(canary) + `|Set-Cookie:\s*injected=` + regexp.QuoteMeta(canary) + `)`),
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

	for _, p := range m.payloads {
		var fuzzedRaw []byte

		if p.rawInject {
			// For URL-encoded payloads (%0d%0a), inject directly into the raw request
			// bytes to avoid double-encoding by the insertion point encoder.
			fuzzedRaw = m.injectRawPayload(ctx.Request().Raw(), ip, fmt.Sprintf(p.tmpl, ip.BaseValue()))
		} else {
			fuzzedRaw = ip.BuildRequest([]byte(fmt.Sprintf(p.tmpl, ip.BaseValue())))
		}
		if fuzzedRaw == nil {
			continue
		}

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

		headersStr := resp.Headers().String()

		// Method 1: regex match on raw header dump (works for HTTP/1.1)
		if m.headerPattern.MatchString(headersStr) {
			results = append(results, m.buildResult(urlx.String(), ip.Name(), p.name, "response_header", string(fuzzedRaw), headersStr))
			resp.Close()
			return results, nil
		}

		// Method 2: check parsed response headers for the injected header (works for HTTP/2
		// where Go's client parses injected headers as proper key-value pairs)
		if nativeResp := resp.Response(); nativeResp != nil {
			if v := nativeResp.Header.Get("X-Injected"); strings.Contains(v, m.canary) {
				results = append(results, m.buildResult(urlx.String(), ip.Name(), p.name, "response_header", string(fuzzedRaw), headersStr))
				resp.Close()
				return results, nil
			}
			for _, cookie := range nativeResp.Cookies() {
				if cookie.Name == "injected" && strings.Contains(cookie.Value, m.canary) {
					results = append(results, m.buildResult(urlx.String(), ip.Name(), p.name, "response_header", string(fuzzedRaw), headersStr))
					resp.Close()
					return results, nil
				}
			}
		}

		// Method 3: check if CRLF+body injection succeeded (canary in body after double CRLF)
		if strings.Contains(p.name, "body-break") {
			fullResp := resp.FullResponse().String()
			if strings.Contains(fullResp, "<injected>"+m.canary+"</injected>") {
				results = append(results, m.buildResult(urlx.String(), ip.Name(), p.name, "response_body_injection", string(fuzzedRaw), fullResp))
				resp.Close()
				return results, nil
			}
		}

		resp.Close()
	}

	return results, nil
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

func (m *Module) buildResult(url, paramName, payloadName, location, request, response string) *output.ResultEvent {
	return &output.ResultEvent{
		URL:              url,
		Request:          request,
		Response:         response,
		FuzzingParameter: paramName,
		ExtractedResults: []string{
			"payload=" + payloadName,
			"canary=" + m.canary,
			"location=" + location,
		},
		Info: output.Info{
			Description: fmt.Sprintf("HTTP response header injection via parameter %q using %s payload. "+
				"The injected canary %q appeared in the %s, confirming the server copies user input into response headers without sanitizing CRLF sequences.",
				paramName, payloadName, m.canary, location),
		},
	}
}
