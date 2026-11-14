package sqli_boolean_blind

import (
	"context"
	"fmt"
	"strconv"
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
	modkit.RequestScopeContextStubs // no-op ScanPer{InsertionPoint,Host}Context
	rhm                             dedup.Lazy[dedup.RequestHashManager]
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

// VulnClass enables cross-module (param, class) dedup: once any sqli module
// reports a parameter, the others in the class skip it.
func (m *Module) VulnClass() string { return modkit.VulnClassSQLi }

// ClassPriority orders this module within its vuln class (lower runs first).
func (m *Module) ClassPriority() int { return modkit.ClassCostBoolean }

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	return m.scanPerRequest(context.Background(), ctx, httpClient, scanCtx)
}

// ScanPerRequestContext is the deadline-aware entry point. Insertion points are
// scanned in priority order (query/body params before cookies before headers), and
// the loop returns the findings confirmed so far the moment runCtx is cancelled —
// so a request carrying many insertion points (a browser-captured request has
// 20+) never loses an already-confirmed injection when the per-module watchdog
// fires. See pkg/core executor callGuard/runActiveWithTimeout.
func (m *Module) ScanPerRequestContext(
	runCtx context.Context,
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	return m.scanPerRequest(runCtx, ctx, httpClient, scanCtx)
}

func (m *Module) scanPerRequest(
	runCtx context.Context,
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
	// Header points: same class gate the executor applies to per-point
	// modules (ECON-1) — noise headers never, logged/negotiation/routing
	// headers once per host.
	points = modkit.FilterPointsFor(scanCtx, m, ctx, points)

	if len(points) == 0 {
		return results, nil
	}
	// rhm dedup is claimed PER insertion point inside the loop (just before
	// scanning it), not for the whole batch up front: GetNotCheckedInsertionPoints
	// marks every point seen at filter time, so a per-module timeout after an early
	// point left the later (never-probed) points permanently suppressed on a
	// retry/resume. See the per-point ShouldCheckInsertionPoint claim below.
	rhm := m.rhm.Get(scanCtx.DedupMgr())

	// If a WAF was observed fronting this host (recorded by other modules on
	// block responses), prepare signature-evasion mutators so detection isn't
	// silently defeated by the WAF dropping the plain payloads.
	wafType := scanCtx.DetectedWAF(urlx.Host)

ipScan:
	for _, ip := range points {
		// Per-module deadline reached — return the findings already confirmed
		// rather than letting the hard watchdog discard the whole result set. The
		// vulnerable query/body params are tested first (points are priority
		// ordered), so a confirmed injection survives even under a tight budget.
		if runCtx.Err() != nil {
			return results, nil
		}
		// Skip content-negotiation request headers (see negotiationHeaders).
		if isExcludedHeader(ip) {
			continue
		}
		// Another module of this vuln class already reported this param here.
		if scanCtx.ParamAlreadyFound(ctx, ip.Name(), m.VulnClass()) {
			continue
		}
		// Claim dedup for THIS point immediately before scanning it (marks it seen).
		// Doing it per point — rather than for the whole batch up front — keeps
		// points that a tight per-module budget never reaches eligible on retry.
		if rhm != nil && !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), ip.Name(), ip.BaseValue(), strconv.Itoa(int(ip.Type()))) {
			continue
		}
		baseValue := ip.BaseValue()

		// Get baseline signature by sending the original unmodified value.
		// This lets us detect cases where both TRUE and FALSE payloads differ
		// from baseline in the same way (e.g., mangled header values causing
		// different responses due to syntax breakage, not SQL logic).
		//
		// The unmodified response is the same for every insertion point of this
		// record, so it is fetched once per record (memoised, ECON-6); each point
		// still builds its own signature, normalised for its own base value. The
		// step-7 drift re-check stays per point.
		rb, err := m.recordBaseline(ctx, httpClient, scanCtx)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}
		baselineFull, baselineBlocked := rb.full, rb.blocked
		var baselineSig responseSignature
		if rb.status != 0 {
			baselineSig = newResponseSignature(rb.status, rb.body, baseValue)
		}

		// A WAF/CDN block on the *unmodified* request means this surface is fronted
		// by hostile edge logic — every payload differential below would be the
		// edge talking, not the application. Skip the insertion point.
		if baselineBlocked {
			continue
		}

		// The unmodified response must be able to anchor a differential: a 2xx,
		// or a 3xx/4xx with a body that is neither a login redirect nor an
		// auth/WAF/rate-limit status (see statusEligible). 5xx baselines and
		// empty redirects/errors are skipped outright.
		if !statusEligible(baselineSig, locationOf(baselineFull)) {
			continue
		}

		plain := getPayloadsForValue(baseValue)
		var waf []payloadPair
		if wafType != "" {
			waf = wafVariants(plain, wafType)
		}
		payloads := append(append(make([]payloadPair, 0, len(plain)+len(waf)), plain...), waf...)

		// Consecutive blocked plain pairs: once maxConsecutiveBlockedPairs in a
		// row are blocked, the remaining plain pairs would only be blocked too —
		// skip to the WAF variants and the HPP fallback, which exist for exactly
		// this case (ECON-6).
		blockedRun := 0
		for i, pair := range payloads {
			if i < len(plain) && blockedRun >= maxConsecutiveBlockedPairs {
				continue
			}
			// Honor the per-module deadline BETWEEN payload pairs too: a
			// high-parameter request's baseline/true/false/WAF/stability/confirmation
			// probes for one point can far outlast the watchdog if only checked
			// between points.
			if runCtx.Err() != nil {
				return results, nil
			}
			result, pairBlocked, err := m.testPayloadPairDetail(ctx, httpClient, ip, baseValue, pair, baselineSig, baselineFull)
			if err != nil {
				if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
					return results, nil
				}
				continue
			}
			if pairBlocked {
				blockedRun++
			} else {
				blockedRun = 0
			}

			if result != nil {
				// Last gate: the whole differential above assumes the endpoint is a
				// function of the request. On a host that round-robins between
				// mismatched backends the same unmodified `GET /` returns two
				// different pages, so TRUE-vs-FALSE, each-vs-baseline, and every
				// single-retry stability check reduce to coin flips that the scan's
				// payload × insertion-point fan-out will eventually line up. Prove
				// determinism from the unmodified request before reporting — and
				// discard the request's earlier results too, since they rode on the
				// same broken assumption. Memoized per record, so this costs nothing
				// on the requests that never reach a candidate.
				if modkit.EndpointVolatile(scanCtx, ctx, httpClient) {
					return nil, nil
				}
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
			// Same endpoint-determinism gate as the direct differential above: HPP
			// only changes how the payload is delivered, so it inherits the same
			// coin-flip failure mode on a non-deterministic endpoint.
			if modkit.EndpointVolatile(scanCtx, ctx, httpClient) {
				return nil, nil
			}
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
	res, _, err := m.testPayloadPairDetail(ctx, httpClient, ip, baseValue, pair, baselineSig, baselineFull)
	return res, err
}

// testPayloadPairDetail is testPayloadPair also reporting whether the pair was
// rejected because TRUE or FALSE came back blocked.
func (m *Module) testPayloadPairDetail(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	baseValue string,
	pair payloadPair,
	baselineSig responseSignature,
	baselineFull string,
) (*output.ResultEvent, bool, error) {
	var blocked bool
	res, err := m.testPayloadPairBody(ctx, httpClient, ip, baseValue, pair, baselineSig, baselineFull, &blocked)
	return res, blocked, err
}

func (m *Module) testPayloadPairBody(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	baseValue string,
	pair payloadPair,
	baselineSig responseSignature,
	baselineFull string,
	blockedOut *bool,
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
		*blockedOut = true
		return nil, nil
	}

	// Step 3a: classify the status triplet. A same-status triplet (200/200/200,
	// 201/201/201, a 404-with-body triplet, …) is judged on content by steps 3b–8
	// below. A stable 2xx/2xx/other split is a status oracle, which skips the
	// content-ratio steps but must clear its own controls. Anything else —
	// TRUE leaving the baseline status, a 5xx, an auth/WAF/rate-limit status, a
	// login redirect — is the classic status-flip false positive and is rejected.
	mode := classifyStatusPair(baselineSig, trueSig1, falseSig1,
		locationOf(baselineFull), locationOf(trueFull), locationOf(falseFull))
	switch mode {
	case modeReject:
		return nil, nil
	case modeStatusOracle:
		return m.confirmStatusOracle(ctx, httpClient, ip, baseValue, pair, baselineSig, baselineFull, trueFull, falseFull, falseSig1)
	}
	prof := contentProfile(baselineSig.StatusCode)

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

	// Step 8: multi-round, multi-factor confirmation (see confirmBoolean).
	confirmed, err := m.confirmBoolean(ctx, httpClient, ip, baseValue, pair, prof)
	if err != nil {
		return nil, err
	}
	if !confirmed {
		return nil, nil
	}

	// All checks passed — confirmed blind SQLi.
	return buildFinding(ip, baseValue, truePayload, falsePayload, baselineFull, trueFull, falseFull,
		"Boolean-based blind SQL injection confirmed via TRUE/FALSE response differential with baseline verification"), nil
}

// confirmBoolean runs step 8, the multi-round, multi-factor confirmation, under
// the given branch profile. Boolean-blind is the technique most prone to false
// positives, so a single TRUE/FALSE differential is never trusted on its own.
// For pairs whose breakout boundary is known (the randomized matrix), run the
// full logic battery. For curated/bypass/WAF pairs — which historically only
// re-ran the same literal `1=1`/`1=2` strings and so could not tell a real
// boolean oracle from a WAF tautology signature — re-derive the condition with
// fresh RANDOM operands in the same boundary (preserving any comment/encoding
// evasion) and require the differential to reproduce. A differential bound to
// the literal token, not to boolean truth, vanishes under random operands and
// is rejected. Header points and status oracles may not fall back to
// repeat-only confirmation.
func (m *Module) confirmBoolean(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	baseValue string,
	pair payloadPair,
	prof branchProfile,
) (bool, error) {
	if pair.boundaried {
		return m.confirmLogic(ctx, httpClient, ip, baseValue, pair.prefix, pair.suffix, prof)
	}
	requireOperands := ip.Type() == httpmsg.INS_HEADER || prof.isStatusOracle()
	return m.confirmRandomized(ctx, httpClient, ip, baseValue+pair.trueVal, baseValue+pair.falseVal, requireOperands, prof)
}

// confirmStatusOracle confirms a status-flip differential (baseline and TRUE
// share a 2xx status, FALSE returns another status). The content-ratio steps
// are skipped, so the status itself must prove the boolean logic:
//
//	(a) the FALSE status reproduces on retry, TRUE keeps the baseline status,
//	    and the baseline status is stable;
//	(b) a syntax-break control (base value + `'")`) must NOT return the FALSE
//	    status — otherwise any malformed input yields that status and the flip
//	    is input validation, not a SQL condition;
//	(c) the multi-round random-operand battery (confirmLogic/confirmRandomized)
//	    reproduces the split with status as the comparator.
//
// A confirmed oracle is reported at Firm confidence with all statuses in the
// evidence.
func (m *Module) confirmStatusOracle(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	ip httpmsg.InsertionPoint,
	baseValue string,
	pair payloadPair,
	baselineSig responseSignature,
	baselineFull, trueFull, falseFull string,
	falseSig responseSignature,
) (*output.ResultEvent, error) {
	truePayload := baseValue + pair.trueVal
	falsePayload := baseValue + pair.falseVal
	prof := statusOracleProfile(baselineSig.StatusCode, falseSig.StatusCode)

	// (a) Reproduce the split, and prove the baseline status itself is stable.
	_, trueSig2, trueBlocked2, err := m.sendPayload(ctx, httpClient, ip, truePayload)
	if err != nil {
		return nil, err
	}
	_, falseSig2, falseBlocked2, err := m.sendPayload(ctx, httpClient, ip, falsePayload)
	if err != nil {
		return nil, err
	}
	if trueBlocked2 || falseBlocked2 || !prof.distinct(trueSig2, falseSig2) {
		return nil, nil
	}
	_, baselineSig2, baselineBlocked2, err := m.sendPayload(ctx, httpClient, ip, baseValue)
	if err != nil {
		return nil, err
	}
	if baselineBlocked2 || baselineSig2.StatusCode != baselineSig.StatusCode {
		return nil, nil
	}

	// (b) Syntax-break control: malformed input must not land on the FALSE status.
	breakPayload := baseValue + syntaxBreakSuffix
	breakFull, breakSig, breakBlocked, err := m.sendPayload(ctx, httpClient, ip, breakPayload)
	if err != nil {
		return nil, err
	}
	if breakBlocked || breakSig.StatusCode == prof.falseStatus {
		return nil, nil
	}

	// (c) Random-operand battery with status as the comparator.
	confirmed, err := m.confirmBoolean(ctx, httpClient, ip, baseValue, pair, prof)
	if err != nil || !confirmed {
		return nil, err
	}

	statuses := fmt.Sprintf("baseline=%d TRUE=%d FALSE=%d syntax-break=%d",
		baselineSig.StatusCode, prof.trueStatus, prof.falseStatus, breakSig.StatusCode)
	r := buildFinding(ip, baseValue, truePayload, falsePayload, baselineFull, trueFull, falseFull,
		"Boolean-based blind SQL injection confirmed via a TRUE/FALSE HTTP status differential ("+statuses+
			"): TRUE keeps the original status, FALSE reproducibly returns another, the split follows random operands, "+
			"and malformed SQL does not produce the FALSE status")
	r.Info.Confidence = severity.Firm
	if r.Metadata == nil {
		r.Metadata = map[string]interface{}{}
	}
	r.Metadata["differential"] = modeStatusOracle.String()
	r.Metadata["statuses"] = statuses
	ev := modkit.NewEvidenceCollector()
	ev.Add(fmt.Sprintf("syntax-break control (status %d)", breakSig.StatusCode),
		string(ip.BuildRequest([]byte(breakPayload))), breakFull)
	r.AdditionalEvidence = append(r.AdditionalEvidence, ev.Entries()...)
	r.AdditionalEvidence = append(r.AdditionalEvidence, "# [status-oracle] "+statuses)
	return r, nil
}

// buildFinding assembles a confirmed boolean-blind finding. The TRUE payload is
// the primary (proof) pair; the clean baseline and the FALSE payload — the two
// responses TRUE was discriminated against — go in the evidence so a reviewer
// can see all three sides of the comparison.
func buildFinding(
	ip httpmsg.InsertionPoint,
	baseValue, truePayload, falsePayload string,
	baselineFull, trueFull, falseFull string,
	description string,
) *output.ResultEvent {
	ev := modkit.NewEvidenceCollector()
	ev.Add("baseline (unmodified value)", string(ip.BuildRequest([]byte(baseValue))), baselineFull)
	ev.Add("false-payload", string(ip.BuildRequest([]byte(falsePayload))), falseFull)
	return &output.ResultEvent{
		Request:            string(ip.BuildRequest([]byte(truePayload))),
		Response:           trueFull,
		AdditionalEvidence: ev.Entries(),
		FuzzingParameter:   ip.Name(),
		ExtractedResults:   []string{truePayload, falsePayload},
		Info: output.Info{
			Description: description,
		},
	}
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
