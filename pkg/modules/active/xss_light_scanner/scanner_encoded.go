package xss_light_scanner

import (
	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/infra/xssencode"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// EncodedModule detects reflected XSS in parameters the application decodes
// before reflecting. It reuses the base scanner's reflection/transform analysis
// unchanged — the only difference is that the survival-probe canary is wrapped
// in an encoding before being sent. A finding therefore still requires the
// *decoded* probe to land in an exploitable context, so the encoding layer
// cannot introduce false positives.
type EncodedModule struct {
	modkit.BaseActiveModule
	base *Module // reuses analyzePhase1 / buildResultEvent (same package)
	rhm  dedup.Lazy[dedup.RequestHashManager]
}

// encodedProbeVariants are the pre-encodings tried per insertion point, in
// order. Each is a no-op for values without structural characters, in which
// case it is skipped.
//
// Note on layering: BuildRequest percent-encodes a URL-param value once and the
// server framework decodes it once, so they cancel — the application handler
// receives exactly the string we pass here. "url" therefore sends a
// single-URL-encoded probe to catch a handler that performs *one extra* decode
// (a filter that passes %3C but the app later turns into <); "base64" catches a
// handler that base64-decodes the parameter.
var encodedProbeVariants = []struct {
	name string
	fn   func(string) string
}{
	{"url", xssencode.URLEncode},
	{"base64", xssencode.Base64},
}

// NewEncodedScanner creates the pre-encoded XSS Light variant.
func NewEncodedScanner() *EncodedModule {
	m := &EncodedModule{
		BaseActiveModule: modkit.NewBaseActiveModule(
			EncodedModuleID,
			EncodedModuleName,
			EncodedModuleDesc,
			EncodedModuleShort,
			EncodedModuleConfirmation,
			EncodedModuleSeverity,
			EncodedModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		base: New(),
		rhm:  dedup.LazyDefaultRHM("xss_light_encoded"),
	}
	// Inherit the base XSS tags plus an "encoded" marker so operators can
	// include/exclude this heavier variant independently.
	m.ModuleTags = append(append([]string{}, ModuleTags...), "encoded")
	return m
}

// ScanPerRequest runs the pre-encoded XSS Light variant for a single request.
func (m *EncodedModule) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return results, nil
	}

	points, err := scanCtx.GetInsertionPoints(ctx.Request().Raw(), ctx.Request().ID(), true)
	if err != nil {
		return results, errors.Wrap(err, "failed to create insertion points")
	}

	points = filterXSSRelevantPoints(points)

	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		points = rhm.GetNotCheckedInsertionPoints(urlx, ctx.Request(), points)
	}
	if len(points) == 0 {
		return results, nil
	}

	for _, ip := range points {
		evt, err := m.scanInsertionPointEncoded(ctx, ip, httpClient)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}
		if evt != nil {
			results = append(results, evt)
		}
	}

	return results, nil
}

// scanInsertionPointEncoded tries each pre-encoding for one insertion point and
// returns the first exploitable reflection, or nil.
func (m *EncodedModule) scanInsertionPointEncoded(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
) (*output.ResultEvent, error) {
	for _, enc := range encodedProbeVariants {
		payload := GeneratePrimary()
		encoded := enc.fn(payload.FullPayload)
		if encoded == payload.FullPayload {
			// Encoding was a no-op for this probe (no structural chars); the
			// base xss-light module already covers the raw case.
			continue
		}

		body, err := sendAndValidateRawPayload(ctx, ip, encoded, httpClient)
		if err != nil {
			return nil, err
		}
		if body == nil {
			continue
		}

		analyses := m.base.analyzePhase1(body, payload)
		var exploitable []*EscapeAnalysis
		for _, ea := range analyses {
			if ea.IsExploitable() {
				exploitable = append(exploitable, ea)
			}
		}
		if len(exploitable) == 0 {
			continue
		}

		result := NewXSSScanResult()
		result.InsertionPoint = ip.Name()
		result.PrimaryPayload = payload
		result.PrimaryResponse = body
		result.ExploitableAnalyses = exploitable

		evt := m.base.buildResultEvent(ctx, ip, result)
		evt.Info.Description = "[encoded: " + enc.name + "] " + evt.Info.Description
		// Show the payload actually sent (the encoded form), not the decoded probe.
		evt.Request = string(ip.BuildRequest([]byte(encoded)))
		return evt, nil
	}

	return nil, nil
}
