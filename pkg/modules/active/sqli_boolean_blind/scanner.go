package sqli_boolean_blind

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

// negotiationHeaders are request headers consumed by content-negotiation /
// locale middleware that legitimately varies the response body (language,
// encoding, charset). A boolean-blind differential on them is a mangled-locale
// artifact, not SQL logic, and a genuine injection through them is rare — so
// they are excluded from injection-point testing. Headers that commonly reach a
// backend store (User-Agent, Referer, X-Forwarded-*) are deliberately NOT here.
var negotiationHeaders = map[string]bool{
	"accept-language": true,
	"accept-encoding": true,
	"accept-charset":  true,
	"accept":          true,
}

// isExcludedHeader reports whether ip is a high-false-positive content-negotiation
// request header that boolean-blind detection should not test.
func isExcludedHeader(ip httpmsg.InsertionPoint) bool {
	if ip.Type() != httpmsg.INS_HEADER {
		return false
	}
	return negotiationHeaders[strings.ToLower(ip.Name())]
}

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

	// A cache/CDN-fronted response or a large rendered HTML page is an unreliable
	// boolean-differential surface: cache HIT/MISS swings and per-request dynamic
	// content (ads, recommendations, rotating blocks) manufacture phantom TRUE/FALSE
	// differentials. Boolean-blind detection is entirely a body differential, so
	// skip the whole request on such a surface.
	// Covers cache/CDN-fronted surfaces, large dynamic HTML, and opaque high-entropy
	// bodies (encrypted CDN/challenge blobs) — all unreliable for a body differential.
	if modkit.DifferentialSurfaceUnreliable(ctx.Response()) {
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
		// Skip content-negotiation request headers (see negotiationHeaders).
		if isExcludedHeader(ip) {
			continue
		}
		baseValue := ip.BaseValue()

		// Get baseline signature by sending the original unmodified value.
		// This lets us detect cases where both TRUE and FALSE payloads differ
		// from baseline in the same way (e.g., mangled header values causing
		// different responses due to syntax breakage, not SQL logic).
		baselineFull, baselineSig, baselineBlocked, err := m.sendPayload(ctx, httpClient, ip, baseValue)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		// A WAF/CDN block on the *unmodified* request means this surface is fronted
		// by hostile edge logic — every payload differential below would be the
		// edge talking, not the application. Skip the insertion point.
		if baselineBlocked {
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
			result, err := m.testPayloadPair(ctx, httpClient, ip, baseValue, pair, baselineSig, baselineFull)
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

		// Additive fallback: the plain single-parameter differential was
		// inconclusive for this point. If a front-end filter blocked the plain
		// payloads, retry the SAME differential + confirmation battery through HTTP
		// Parameter Pollution channels — a WAF/proxy may inspect one occurrence of
		// the parameter while the backend evaluates another. This only ever changes
		// HOW the payload is delivered; the confirmation bar is unchanged, so it
		// introduces no new false positives.
		hpp, err := m.tryHPPFallback(ctx, httpClient, ip, baseValue, baselineSig, baselineFull)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}
		if hpp != nil {
			hpp.URL = urlx.String()
			results = append(results, hpp)
			continue ipScan
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
	baselineFull string,
) (*output.ResultEvent, error) {
	truePayload := baseValue + pair.trueVal
	falsePayload := baseValue + pair.falseVal

	// Step 1: Send TRUE payload
	trueFull, trueSig1, trueBlocked, err := m.sendPayload(ctx, httpClient, ip, truePayload)
	if err != nil {
		return nil, err
	}

	// Step 2: Send FALSE payload
	falseFull, falseSig1, falseBlocked, err := m.sendPayload(ctx, httpClient, ip, falsePayload)
	if err != nil {
		return nil, err
	}

	// Step 2b: Block gate. If either branch is a WAF/CDN block or challenge, the
	// differential is the edge reacting to a payload signature (the literal `1=1`
	// tautology, the `/**/` comment-evasion form), not the application's SQL logic.
	// This is the single most common boolean-blind false positive — kill it here.
	if trueBlocked || falseBlocked {
		return nil, nil
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
	_, trueSig2, trueBlocked2, err := m.sendPayload(ctx, httpClient, ip, truePayload)
	if err != nil {
		return nil, err
	}
	if trueBlocked2 || !ratioSimilar(trueSig1, trueSig2) {
		return nil, nil // Unstable TRUE response (or now blocked)
	}

	// Step 6: Confirm FALSE is consistent across a retry.
	_, falseSig2, falseBlocked2, err := m.sendPayload(ctx, httpClient, ip, falsePayload)
	if err != nil {
		return nil, err
	}
	if falseBlocked2 || !ratioSimilar(falseSig1, falseSig2) {
		return nil, nil // Unstable FALSE response (or now blocked)
	}

	// Step 7: Re-verify baseline hasn't drifted (catches dynamic content noise).
	_, baselineSig2, _, err := m.sendPayload(ctx, httpClient, ip, ip.BaseValue())
	if err != nil {
		return nil, err
	}
	if !ratioSimilar(baselineSig, baselineSig2) {
		return nil, nil // Baseline is unstable — responses are too dynamic to trust
	}

	// Step 8: Multi-round, multi-factor confirmation. Boolean-blind is the
	// technique most prone to false positives, so a single TRUE/FALSE
	// differential is never trusted on its own. For pairs whose breakout
	// boundary is known (the randomized matrix), run the full logic battery. For
	// curated/bypass/WAF pairs — which historically only re-ran the same literal
	// `1=1`/`1=2` strings and so could not tell a real boolean oracle from a WAF
	// tautology signature — re-derive the condition with fresh RANDOM operands in
	// the same boundary (preserving any comment/encoding evasion) and require the
	// differential to reproduce. A differential bound to the literal token, not to
	// boolean truth, vanishes under random operands and is rejected.
	isHeader := ip.Type() == httpmsg.INS_HEADER
	var confirmed bool
	if pair.boundaried {
		confirmed, err = m.confirmLogic(ctx, httpClient, ip, baseValue, pair.prefix, pair.suffix)
	} else {
		confirmed, err = m.confirmRandomized(ctx, httpClient, ip, truePayload, falsePayload, isHeader)
	}
	if err != nil {
		return nil, err
	}
	if !confirmed {
		return nil, nil
	}

	// All checks passed — confirmed blind SQLi. Attach the differential that proves
	// it: the TRUE payload is the primary (proof) pair; the clean baseline and the
	// FALSE payload — the two responses TRUE was discriminated against — go in the
	// evidence so a reviewer can see all three sides of the comparison.
	fuzzedRaw := ip.BuildRequest([]byte(truePayload))
	ev := modkit.NewEvidenceCollector()
	ev.Add("baseline (unmodified value)", string(ip.BuildRequest([]byte(baseValue))), baselineFull)
	ev.Add("false-payload", string(ip.BuildRequest([]byte(falsePayload))), falseFull)
	return &output.ResultEvent{
		Request:            string(fuzzedRaw),
		Response:           trueFull,
		AdditionalEvidence: ev.Entries(),
		FuzzingParameter:   ip.Name(),
		ExtractedResults:   []string{truePayload, falsePayload},
		Info: output.Info{
			Description: "Boolean-based blind SQL injection confirmed via TRUE/FALSE response differential with baseline verification",
		},
	}, nil
}

// sendPayload sends a payload through an insertion point and returns the response
// body, its comparison signature, and whether the response came from a WAF/CDN
// block or challenge. A blocked response carries no SQL signal: a boolean
// differential that is really a WAF reacting to the literal `1=1` tautology
// signature (the classic header/login false positive) must never be read as
// injection, so every caller gates on the blocked flag before trusting a
// differential.
func (m *Module) sendPayload(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	payload string,
) (string, responseSignature, bool, error) {
	fuzzedRaw := ip.BuildRequest([]byte(payload))

	// BuildRequest produces well-formed raw, so wrap directly instead of
	// re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())

	// NoClustering: the boolean-blind confirmation re-sends IDENTICAL requests to
	// prove stability — the TRUE/FALSE retries (ratio-stable across a second send),
	// the baseline-drift re-fetch of the original value, and confirmRepeat's repeated
	// rounds. The 500ms request-cluster cache keys on raw request bytes, so without
	// this those re-sends return the first response's cached copy and the stability
	// checks pass trivially even on a non-deterministic (flapping / load-balanced)
	// endpoint — silently defeating the module's core false-positive defenses.
	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return "", responseSignature{}, false, err
	}
	defer resp.Close()

	// Classify the block status while the response chain is still open.
	blocked := infra.IsBlockedResponse(resp)

	if resp.Response() == nil {
		return "", responseSignature{}, blocked, nil
	}

	// The boolean differential (TRUE vs FALSE vs baseline ratio) must be computed
	// over the response BODY only. Building the signature from the full response
	// string would fold the header block — volatile per-request headers (Set-Cookie
	// session blobs, Date, request-ids) — into the token multiset and body-length,
	// adding noise that can mask a real content difference or manufacture a phantom
	// one. The full response string is kept solely as the reported evidence.
	fullResp := resp.FullResponseString()
	sig := newResponseSignature(resp.Response().StatusCode, resp.Body().String(), payload)
	return fullResp, sig, blocked, nil
}
