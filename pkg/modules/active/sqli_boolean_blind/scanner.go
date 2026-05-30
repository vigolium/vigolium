package sqli_boolean_blind

import (
	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

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
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		rhm: dedup.LazyDefaultRHM("sqli_boolean_blind"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(
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

	// Create all insertion points (uses cached provider when available)
	points, err := scanCtx.GetInsertionPoints(ctx.Request().Raw(), ctx.Request().ID(), true)
	if err != nil {
		return results, errors.Wrap(err, "failed to create insertion points")
	}

	// Filter out already checked insertion points
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		points = rhm.GetNotCheckedInsertionPoints(urlx, ctx.Request(), points)
	}
	if len(points) == 0 {
		return results, nil
	}

	// If a WAF was observed fronting this host (recorded by other modules on
	// block responses), prepare signature-evasion mutators so detection isn't
	// silently defeated by the WAF dropping the plain payloads.
	wafType := scanCtx.DetectedWAF(urlx.Host)

ipScan:
	for _, ip := range points {
		baseValue := ip.BaseValue()

		// Get baseline signature by sending the original unmodified value.
		// This lets us detect cases where both TRUE and FALSE payloads differ
		// from baseline in the same way (e.g., mangled header values causing
		// different responses due to syntax breakage, not SQL logic).
		_, baselineSig, err := m.sendPayload(ctx, httpClient, ip, baseValue)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		// Only meaningful to look for a 200-vs-200 content differential when the
		// unmodified request itself returns 200. Skip non-200 baselines outright.
		if !statusOK(baselineSig) {
			continue
		}

		payloads := getPayloadsForValue(baseValue)
		if wafType != "" {
			payloads = append(payloads, wafVariants(payloads, wafType)...)
		}

		for _, pair := range payloads {
			result, err := m.testPayloadPair(ctx, httpClient, ip, baseValue, pair, baselineSig)
			if err != nil {
				if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
					return results, nil
				}
				continue
			}

			if result != nil {
				result.URL = urlx.String()
				results = append(results, result)
				continue ipScan
			}
		}
	}

	return results, nil
}

// testPayloadPair implements the verification algorithm with baseline
// comparison. Discrimination is driven by difflib-style textual similarity
// (quickRatio) rather than exact body length/hash, so it survives dynamic
// content (CSRF tokens, timestamps) and detects content-level TRUE/FALSE
// differentials that a byte comparison would miss. The conservative
// length/hash pre-checks are kept as a fast reject path.
func (m *Module) testPayloadPair(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	baseValue string,
	pair payloadPair,
	baselineSig responseSignature,
) (*output.ResultEvent, error) {
	truePayload := baseValue + pair.trueVal
	falsePayload := baseValue + pair.falseVal

	// Step 1: Send TRUE payload
	_, trueSig1, err := m.sendPayload(ctx, httpClient, ip, truePayload)
	if err != nil {
		return nil, err
	}

	// Step 2: Send FALSE payload
	_, falseSig1, err := m.sendPayload(ctx, httpClient, ip, falsePayload)
	if err != nil {
		return nil, err
	}

	// Step 3a: All three responses must be HTTP 200. Boolean-blind manifests as
	// content differences *within* a successful response; a differential that is
	// really a status flip (e.g. baseline/TRUE 200 vs FALSE 302 redirect, or a
	// 4xx/5xx error) is a classic false positive, so reject anything that isn't
	// 200/200/200.
	if !statusOK(baselineSig) || !statusOK(trueSig1) || !statusOK(falseSig1) {
		return nil, nil
	}

	// Step 3b: TRUE and FALSE must produce materially different responses.
	// Fast length/hash reject first, then require textual divergence so that
	// near-identical pages (same content, only dynamic noise differs) are
	// rejected even when their hashes differ.
	if !isDifferent(trueSig1, falseSig1) {
		return nil, nil
	}
	if quickRatio(trueSig1, falseSig1) >= upperRatioBound {
		return nil, nil // Effectively the same page — not a boolean signal
	}
	// Step 3c: the size gap between TRUE and FALSE must be large. Real
	// boolean-blind (row-found vs no-row) changes the response substantially;
	// requiring a big body-length delta rejects marginal differentials.
	if !hasSubstantialBodyDifference(trueSig1, falseSig1) {
		return nil, nil
	}

	// Step 4: The differential must be SQL-driven, not syntax breakage. Compare
	// each of TRUE/FALSE to the baseline: a real boolean injection makes exactly
	// one branch resemble the original page while the other diverges. Require the
	// two similarities-to-baseline to differ by at least ratioDiffTolerance.
	// Mirrors sqlmap's (ratio - matchRatio) > DIFF_TOLERANCE decision and
	// naturally rejects pure status-flip false positives (identical body →
	// identical normalized tokens → divergence ~0).
	trueVsBase := quickRatio(trueSig1, baselineSig)
	falseVsBase := quickRatio(falseSig1, baselineSig)
	divergence := trueVsBase - falseVsBase
	if divergence < 0 {
		divergence = -divergence
	}
	if divergence < ratioDiffTolerance {
		return nil, nil // Both branches relate to baseline equally — not SQL logic
	}
	// At least one branch must clearly resemble the baseline; if both diverge
	// far from the original the value was likely just mangled (syntax break).
	if trueVsBase < upperRatioBound && falseVsBase < upperRatioBound {
		return nil, nil
	}

	// Step 5: Confirm TRUE is consistent across a retry (ratio-stable).
	_, trueSig2, err := m.sendPayload(ctx, httpClient, ip, truePayload)
	if err != nil {
		return nil, err
	}
	if !ratioSimilar(trueSig1, trueSig2) {
		return nil, nil // Unstable TRUE response
	}

	// Step 6: Confirm FALSE is consistent across a retry.
	_, falseSig2, err := m.sendPayload(ctx, httpClient, ip, falsePayload)
	if err != nil {
		return nil, err
	}
	if !ratioSimilar(falseSig1, falseSig2) {
		return nil, nil // Unstable FALSE response
	}

	// Step 7: Re-verify baseline hasn't drifted (catches dynamic content noise).
	_, baselineSig2, err := m.sendPayload(ctx, httpClient, ip, ip.BaseValue())
	if err != nil {
		return nil, err
	}
	if !ratioSimilar(baselineSig, baselineSig2) {
		return nil, nil // Baseline is unstable — responses are too dynamic to trust
	}

	// Step 8: Multi-round, multi-factor confirmation. Boolean-blind is the
	// technique most prone to false positives, so a single TRUE/FALSE
	// differential is never trusted on its own. For pairs whose breakout
	// boundary is known (the randomized matrix), run a logic battery: several
	// AND rounds with fresh random operands, an OR formulation, and an
	// invalid-syntax probe — all must behave deterministically. For opaque
	// curated/bypass pairs, re-run the differential across multiple rounds.
	var confirmed bool
	if pair.boundaried {
		confirmed, err = m.confirmLogic(ctx, httpClient, ip, baseValue, pair.prefix, pair.suffix)
	} else {
		confirmed, err = m.confirmRepeat(ctx, httpClient, ip, truePayload, falsePayload)
	}
	if err != nil {
		return nil, err
	}
	if !confirmed {
		return nil, nil
	}

	// All checks passed — confirmed blind SQLi
	fuzzedRaw := ip.BuildRequest([]byte(truePayload))
	return &output.ResultEvent{
		Request:          string(fuzzedRaw),
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{truePayload, falsePayload},
		Info: output.Info{
			Description: "Boolean-based blind SQL injection confirmed via TRUE/FALSE response differential with baseline verification",
		},
	}, nil
}

// sendPayload sends a payload through an insertion point and returns the response signature.
func (m *Module) sendPayload(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	payload string,
) (string, responseSignature, error) {
	fuzzedRaw := ip.BuildRequest([]byte(payload))

	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return "", responseSignature{}, err
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
	if err != nil {
		return "", responseSignature{}, err
	}
	defer resp.Close()

	if resp.Response() == nil {
		return "", responseSignature{}, nil
	}

	body := resp.FullResponseString()
	sig := newResponseSignature(resp.Response().StatusCode, body, payload)
	return body, sig, nil
}
