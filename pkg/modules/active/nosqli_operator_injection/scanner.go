package nosqli_operator_injection

import (
	"fmt"
	"time"

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

// Module implements the NoSQL Operator Injection active scanner.
type Module struct {
	modkit.BaseActiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new NoSQL Operator Injection module.
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
		rhm: dedup.LazyDefaultRHM("nosqli_operator_injection"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess extends the default to skip static assets / code bundles (JS, CSS,
// fonts, images, media, archives): a static file is never a NoSQL query handler,
// so its body size, boolean differential, or any error token inside it is noise,
// not an injection signal. Both the captured content-type and the URL path are
// checked, mirroring the nosqli_error_based gate.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if !m.BaseActiveModule.CanProcess(ctx) {
		return false
	}
	if ctx.Response() != nil && modkit.IsStaticAssetContentType(ctx.Response().Header("Content-Type")) {
		return false
	}
	if u, err := ctx.URL(); err == nil && modkit.IsStaticAssetPath(u.Path) {
		return false
	}
	return true
}

// ScanPerInsertionPoint tests a single insertion point for NoSQL operator injection.
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

	// Reject media/JS URLs, OPTIONS/CONNECT, and CDN-edge infra paths (/cdn-cgi/):
	// none route to a NoSQL-backed application, and a CDN challenge endpoint returns
	// an opaque per-request body that fools the boolean/size differential.
	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return nil, nil
	}

	// Dedup check
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Baseline data. A captured baseline that is itself a WAF/CDN edge block
	// (a CloudFront "Request blocked" 403, a Cloudflare/Akamai/Incapsula block,
	// a 429) is the edge talking, not the application: its status AND its body
	// belong to the block page. Both captured-baseline detection paths would then
	// compare the operator response against edge mitigation rather than the app —
	// the auth-bypass path reads the block's status as a "denied" gate and the
	// size-change path reads the tiny block page as a small baseline. This is the
	// motivating false positive: a spider-submitted form value of ~1400 random
	// chars tripped a CloudFront length/anomaly rule (403, 919-byte block page),
	// so a short "[$ne]=" operator value that simply did not trip it (200, full
	// 55 KB page) read as a 403→200 auth bypass. Discard such a baseline so those
	// two paths do not fire; the boolean-diff and time-based legs measure their
	// own fresh, per-probe-gated baselines and are unaffected.
	var baselineBody string
	var baselineStatus int
	if r := ctx.Response(); r != nil && !modkit.IsEdgeBlockedResponse(r) {
		baselineBody = r.BodyToString()
		baselineStatus = r.StatusCode()
	}

	// Select payloads based on insertion point type
	payloads := getPayloadsForType(ip.Type())

	for _, payload := range payloads {
		// For boolean diff, we need to handle pairs (true + false conditions)
		if payload.detectType == detectBooleanDiff {
			continue // handled separately below
		}

		if payload.detectType == detectTimeDelay {
			result, err := m.testTimeBasedPayload(ctx, ip, httpClient, payload)
			if err != nil {
				if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
					return nil, nil
				}
				continue
			}
			if result != nil {
				return []*output.ResultEvent{result}, nil
			}
			continue
		}

		result, err := m.testPayload(ctx, ip, httpClient, payload, baselineBody, baselineStatus)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
			continue
		}
		if result != nil {
			return []*output.ResultEvent{result}, nil
		}
	}

	// Boolean diff: test matched true/false pairs
	result, err := m.testBooleanDiff(ctx, ip, httpClient, baselineBody)
	if err != nil && !errors.Is(err, hosterrors.ErrUnresponsiveHost) {
		return nil, nil
	}
	if result != nil {
		return []*output.ResultEvent{result}, nil
	}

	return nil, nil
}

// testPayload sends a single payload and analyzes the response.
func (m *Module) testPayload(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	payload nosqliPayload,
	baselineBody string,
	baselineStatus int,
) (*output.ResultEvent, error) {
	var fuzzedValue string
	if payload.detectType == detectAuthBypass || payload.detectType == detectSizeChange {
		// Replace the entire value with the operator payload
		fuzzedValue = payload.value
	} else {
		// Append payload to existing value
		fuzzedValue = ip.BaseValue() + payload.value
	}

	fuzzedRaw := ip.BuildRequest([]byte(fuzzedValue))
	// BuildRequest produces well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(fuzzedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil, err
	}

	// A WAF/CDN challenge, auth gate, or rate-limit page is not the app
	// responding to the operator payload — skip it so its body/size/status can't
	// trip any detection path (the SSO/Cloudflare-challenge false-positive class).
	if infra.IsBlockedResponse(resp) {
		resp.Close()
		return nil, nil
	}
	// Keep resp open until we know whether this probe becomes a finding: its full
	// raw response is only needed on the (rare) detection branch, so capturing it
	// eagerly for every probe would allocate a headers+body copy most probes drop.
	// (The executor no longer backfills a baseline response for a mutated request,
	// so a real finding must supply its own — captured lazily at the return below.)
	defer resp.Close()

	body := resp.Body().String()
	probeStatus := 0
	if resp.Response() != nil {
		probeStatus = resp.Response().StatusCode
	}

	// Skip if response contains NoSQL error patterns (delegate to nosqli_error_based)
	if containsNoSQLError(body) {
		return nil, nil
	}

	var detected bool
	var detectionDesc string
	// These paths are behavioral inferences, not direct proof of query control.
	// Auth bypass (a re-confirmed 401/403→2xx transition) is the strongest signal,
	// reported High/Tentative. The size-increase path only INFERS exfiltration
	// from response growth — never proving leaked data is in the body — so it is
	// the weakest and stays Suspect/Tentative, matching the time-based path.
	findingSeverity := severity.High
	findingConfidence := severity.Tentative

	switch payload.detectType {
	case detectAuthBypass:
		if analyzeAuthBypass(baselineStatus, probeStatus) &&
			m.confirmAuthBypass(ctx, ip, httpClient, fuzzedValue) {
			detected = true
			detectionDesc = fmt.Sprintf("Auth bypass: status changed from %d to %d", baselineStatus, probeStatus)
		}
	case detectSizeChange:
		findingSeverity = severity.Suspect
		findingConfidence = severity.Tentative
		// Require a real, ALLOWED captured baseline: a 2xx status AND a non-empty
		// body. Two artifacts this rejects:
		//   - a served (2xx) page that captured as 0 bytes is almost always an
		//     encoding/capture artifact (gzip not decoded at capture, streamed/HEAD
		//     body) — analyzeSizeIncrease(0, N) would misread any non-trivial
		//     response as a size increase from zero (the Cloudflare-Access SSO-page
		//     false positive: empty captured baseline, 200 status, a 22 KB static
		//     login page returned for every value);
		//   - a DENIED/blocked baseline (a 401/403 auth or WAF-length page) is not
		//     the app's normal response, so a short value returning the full page
		//     over it is the value clearing the gate, not the operator exfiltrating
		//     data. "Data exfiltration" is only meaningful measured FROM a normal
		//     2xx response, so a non-2xx baseline cannot anchor a size delta.
		//
		// Beyond the captured-baseline delta, confirmSizeIncrease must reproduce
		// the growth against a FRESH clean fetch AND find the payload body
		// structurally divergent from it.
		if baselineStatus >= 200 && baselineStatus < 300 && len(baselineBody) > 0 &&
			analyzeSizeIncrease(len(baselineBody), len(body)) &&
			m.confirmSizeIncrease(ctx, ip, httpClient, fuzzedValue, body) {
			detected = true
			detectionDesc = fmt.Sprintf("Data exfiltration: body size increased from %d to %d bytes", len(baselineBody), len(body))
		}
	}

	if !detected {
		return nil, nil
	}

	ev := modkit.NewEvidenceCollector()
	ev.Add("baseline", modkit.CtxRequestRaw(ctx), modkit.CtxResponseRaw(ctx))

	urlx, _ := ctx.URL()
	return &output.ResultEvent{
		URL:                urlx.String(),
		Matched:            urlx.String(),
		Request:            string(fuzzedRaw),
		Response:           resp.FullResponseString(),
		FuzzingParameter:   ip.Name(),
		ExtractedResults:   []string{payload.value},
		AdditionalEvidence: ev.Entries(),
		Info: output.Info{
			Name:        "NoSQL Operator Injection",
			Description: fmt.Sprintf("%s — %s via parameter %q", detectionDesc, payload.desc, ip.Name()),
			Severity:    findingSeverity,
			Confidence:  findingConfidence,
			Tags:        []string{"nosqli", "injection", "mongodb"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"},
		},
	}, nil
}

// confirmAuthBypass verifies an apparent 401/403→200 transition is genuinely
// caused by the operator payload, not a transient block, a WAF, or a value-shape
// artifact. Each round holds the operator as the only variable and requires ALL
// of:
//
//   - the ORIGINAL base value is STILL denied (401/403) by the APPLICATION — a
//     denial that is a vendor WAF/CDN edge block (CloudFront/Cloudflare/Akamai/
//     Incapsula, or a 429) is not an auth gate, so it cannot be "bypassed";
//   - a benign, OPERATOR-FREE control value is ALSO denied — if a plain
//     non-operator value is allowed (2xx), the gate is not rejecting on value
//     content but on something incidental to the original base value (its length
//     or entropy tripping a WAF rule), so the operator is not what unblocks the
//     request. This is the CloudFront length-rule false positive: a ~1400-char
//     random base value was blocked (403) while any short value — operator or
//     not — passed (200);
//   - the payload value is STILL allowed (2xx) and not itself an edge block.
//
// The fetches bypass the response cache so a stale replay can't mask flapping.
// Fails open on a transport error so a transient failure never suppresses a true
// positive.
func (m *Module) confirmAuthBypass(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	payloadValue string,
) bool {
	const rounds = 2
	for range rounds {
		baseStatus, baseBlocked, err := m.freshStatus(ctx, ip, httpClient, ip.BaseValue())
		if err != nil {
			return true // fail open on transport error
		}
		if baseBlocked {
			return false // the "denial" is a WAF/CDN edge block, not an app auth gate
		}
		if baseStatus != 401 && baseStatus != 403 {
			return false // not denied WITHOUT the payload → the block isn't payload-attributable
		}

		// A benign, operator-free value of comparable shape must ALSO be denied.
		// If it is allowed, the gate rejects on the base value's incidentals
		// (length/entropy tripping a WAF), not on operator interpretation — the
		// operator is not the discriminator, so the 401/403→2xx transition is not
		// a NoSQL auth bypass.
		ctrlStatus, ctrlBlocked, err := m.freshStatus(ctx, ip, httpClient, benignProbeSuffix)
		if err != nil {
			return true
		}
		if !ctrlBlocked && ctrlStatus >= 200 && ctrlStatus < 300 {
			return false // benign non-operator value allowed → not operator-attributable
		}

		probeStatus, probeBlocked, err := m.freshStatus(ctx, ip, httpClient, payloadValue)
		if err != nil {
			return true
		}
		if probeBlocked || probeStatus < 200 || probeStatus >= 300 {
			return false // not allowed WITH the payload → not a reproducible bypass
		}
	}
	return true
}

// freshStatus issues the insertion point built with value and returns the status
// code plus whether the response is a vendor WAF/CDN edge block (CloudFront/
// Cloudflare/Akamai/Incapsula block or a 429 — NOT a generic application 401/403).
// It bypasses the response cache (NoClustering) so a confirmation re-fetch is a
// genuinely fresh observation rather than a replayed one.
func (m *Module) freshStatus(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	value string,
) (status int, edgeBlocked bool, err error) {
	// BuildRequest produces well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(ip.BuildRequest([]byte(value)), ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
	if err != nil {
		return 0, false, err
	}
	defer resp.Close()
	// A vendor-identified edge block is detected before reading the status so a
	// blocked 403/429 is never mistaken for an application denial. Validate flags
	// only vendor WAF/CDN blocks and challenges, not a plain app 401/403.
	edgeBlocked = infra.GetBlockDetectionValidator().Validate(resp) != nil
	if resp.Response() == nil {
		return 0, edgeBlocked, nil
	}
	return resp.Response().StatusCode, edgeBlocked, nil
}

// confirmSizeIncrease re-confirms a detectSizeChange hit by checking the body
// growth is payload-driven rather than the endpoint's own per-request size
// variance or a capture artifact. It fetches the ORIGINAL value twice (taking
// the largest clean response) and re-sends the payload once. To survive, ALL of:
//
//   - the fresh clean fetches must produce a NON-EMPTY body — without a real
//     live baseline the "growth" is unverifiable (the captured 0-byte baseline
//     that can trigger this path cannot be trusted), so we drop;
//   - the SMALLER of the two payload responses must still exceed the LARGEST
//     clean response by the size-increase thresholds (rejects large-by-default
//     and non-deterministic endpoints);
//   - the payload body must STRUCTURALLY DIVERGE from the clean body — a static
//     page that renders identically regardless of the operator (e.g. an SSO
//     login page) is rejected even if a measurement glitch inflated a length.
//
// Unlike the auth-bypass path this fails CLOSED on a transport error: the size
// oracle is weak and already prone to baseline artifacts, so a re-fetch we
// cannot complete must DROP the finding rather than confirm it — a transient
// upstream error (rate-limit, reset) must never become a confirmed
// data-exfiltration report.
func (m *Module) confirmSizeIncrease(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	payloadValue string,
	firstProbeBody string,
) bool {
	maxClean := 0
	var cleanBody string
	for i := 0; i < 2; i++ {
		_, body, blocked, err := m.measureDuration(ctx, ip, httpClient, ip.BaseValue())
		if err != nil {
			return false // fail closed: cannot reproduce a clean baseline
		}
		// A denied/blocked fresh fetch of the ORIGINAL value is not a clean
		// baseline: the "growth" would then just be a short payload value clearing
		// a WAF/auth gate the long original value tripped, not the operator pulling
		// records. Drop rather than anchor the delta on a block page.
		if blocked {
			return false
		}
		if len(body) > maxClean {
			maxClean = len(body)
			cleanBody = body
		}
	}
	// A served response that yields no live clean body is an encoding/capture
	// artifact, not a measurable baseline — drop rather than treat 0→N as growth.
	if maxClean == 0 {
		return false
	}

	_, probeBody, _, err := m.measureDuration(ctx, ip, httpClient, payloadValue)
	if err != nil {
		return false // fail closed
	}
	smallestProbe := firstProbeBody
	if len(probeBody) < len(smallestProbe) {
		smallestProbe = probeBody
	}
	if !analyzeSizeIncrease(maxClean, len(smallestProbe)) {
		return false
	}
	// Reproducible growth alone is not enough: the larger payload body must also
	// be structurally different from the clean body. Identical content that
	// merely measured larger is the same page, not exfiltrated data.
	return responsesDiverge(cleanBody, smallestProbe)
}

// testTimeBasedPayload confirms a time-based NoSQL injection by measuring a
// fresh baseline for the insertion point and then requiring every one of
// timeBasedConfirmationRounds probes to exceed timeDelayThresholdMs over that
// baseline. A generally slow endpoint yields a slow baseline and is rejected;
// a single jittery probe is rejected because subsequent rounds must also
// confirm. Only payloads with detectType == detectTimeDelay reach this path.
func (m *Module) testTimeBasedPayload(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	payload nosqliPayload,
) (*output.ResultEvent, error) {
	baselineDuration, _, baselineBlocked, err := m.measureDuration(ctx, ip, httpClient, ip.BaseValue())
	if err != nil {
		return nil, err
	}
	// A blocked baseline (WAF/CDN edge block, auth gate, rate-limit) is not an
	// application surface to time-test — the request never reaches a backend
	// query, so any latency here is the edge, not a sleep.
	if baselineBlocked {
		return nil, nil
	}

	// The three probes exercise the SAME $where JS-eval path; only the sleep argument
	// differs. Their payloads are loop-invariant, so build them once. The high-sleep
	// payload is also the finding's evidence pair.
	controlVal := ip.BaseValue() + whereSleep(timeBasedControlMs)
	lowVal := ip.BaseValue() + whereSleep(timeBasedLowMs)
	highVal := ip.BaseValue() + whereSleep(timeBasedHighMs)
	fuzzedRaw := ip.BuildRequest([]byte(highVal))

	// probe measures one sleep magnitude, reporting whether the response is unusable
	// as a timing sample (a WAF/CDN block or a NoSQL error surface, on which latency
	// proves nothing).
	probe := func(value string) (dur time.Duration, unusable bool, err error) {
		d, body, blocked, err := m.measureDuration(ctx, ip, httpClient, value)
		if err != nil {
			return 0, false, err
		}
		return d, blocked || containsNoSQLError(body), nil
	}

	var lastControl, lastLow, lastHigh time.Duration
	for i := 0; i < timeBasedConfirmationRounds; i++ {
		control, bad, err := probe(controlVal)
		if err != nil {
			return nil, err
		}
		if bad {
			return nil, nil
		}
		low, bad, err := probe(lowVal)
		if err != nil {
			return nil, err
		}
		if bad {
			return nil, nil
		}
		high, bad, err := probe(highVal)
		if err != nil {
			return nil, err
		}
		if bad {
			return nil, nil
		}

		// Coarse floor: the high sleep must clear the absolute threshold over the
		// control (guards a control that itself came back oddly slow). Then require
		// the delay to scale with the injected duration over the control — a
		// constant-expensive $where scan delays the control just as much, so nothing
		// scales, and a spike on only the high probe leaves the low sleep flat.
		if !analyzeTimeDelay(control, high) {
			return nil, nil
		}
		if !infra.ScaledDelayConfirmed(control, low, high,
			time.Duration(timeBasedLowMs)*time.Millisecond, time.Duration(timeBasedHighMs)*time.Millisecond,
			timeScaleDenom, timeOvershootFactor) {
			return nil, nil
		}
		lastControl, lastLow, lastHigh = control, low, high
	}

	ev := modkit.NewEvidenceCollector()
	ev.Add("baseline", modkit.CtxRequestRaw(ctx), modkit.CtxResponseRaw(ctx))

	urlx, _ := ctx.URL()
	return &output.ResultEvent{
		URL:                urlx.String(),
		Matched:            urlx.String(),
		Request:            string(fuzzedRaw),
		FuzzingParameter:   ip.Name(),
		ExtractedResults:   []string{whereSleep(timeBasedHighMs), whereSleep(timeBasedControlMs)},
		AdditionalEvidence: ev.Entries(),
		Info: output.Info{
			Name: "NoSQL Operator Injection",
			Description: fmt.Sprintf(
				"Time-based injection confirmed over %d rounds; the response delay scales with the injected $where "+
					"sleep duration (final round: no-sleep %dms, %dms-sleep %dms, %dms-sleep %dms) — %s via parameter %q",
				timeBasedConfirmationRounds, lastControl.Milliseconds(), timeBasedLowMs, lastLow.Milliseconds(),
				timeBasedHighMs, lastHigh.Milliseconds(), payload.desc, ip.Name(),
			),
			// Time-based inference is prone to backend-delay false positives
			// (unlike the auth-bypass/boolean paths) — flag as suspect.
			Severity:   severity.Suspect,
			Confidence: severity.Tentative,
			Tags:       []string{"nosqli", "injection", "mongodb", "time-based"},
			Reference:  []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"},
		},
		Metadata: map[string]any{
			"baseline_ms":         baselineDuration.Milliseconds(),
			"control_ms":          lastControl.Milliseconds(),
			"low_sleep_ms":        timeBasedLowMs,
			"high_sleep_ms":       timeBasedHighMs,
			"confirmation_rounds": timeBasedConfirmationRounds,
		},
	}, nil
}

// whereSleep builds a MongoDB $where sleep payload for the given millisecond
// duration. Used by the time-based leg to probe several sleep magnitudes (including
// a no-sleep control) on the identical $where JS-eval path so the delay's scaling
// with the injected duration can be verified.
func whereSleep(ms int) string {
	return fmt.Sprintf(`{"$where":"sleep(%d)"}`, ms)
}

// measureDuration executes a single request with the given fuzzed value and
// returns its wall-clock duration, the response body, and whether the response
// was a WAF/CDN/auth/rate-limit block. A blocked response must never be read as a
// time delay: its latency is the edge denying us (a 429/503 in particular adds
// its own delay), not a backend query executing the injected sleep.
func (m *Module) measureDuration(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	value string,
) (time.Duration, string, bool, error) {
	raw := ip.BuildRequest([]byte(value))
	// BuildRequest produces well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())

	start := time.Now()
	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		return 0, "", false, err
	}
	duration := time.Since(start)
	body := resp.Body().String()
	blocked := infra.IsBlockedResponse(resp)
	resp.Close()
	return duration, body, blocked, nil
}

// boolSample is one probe of a boolean-diff condition, carrying the signals the
// confirmation logic needs to reject a non-analyzable response (a binary CDN
// object, a WAF/auth/rate-limit page, or a NoSQL error surface).
type boolSample struct {
	body     string
	status   int
	blocked  bool // WAF/CDN/auth/rate-limit page — not the application
	binary   bool // non-text body (image/font/archive) — text diff is meaningless
	nosqlErr bool // NoSQL driver error — defer to nosqli_error_based
}

// testBooleanDiff tests structurally-matched always-true / always-false payload
// pairs to detect boolean-based NoSQL injection. Each condition is sampled several
// times, interleaved with a benign operator-free CONTROL on the same cadence, so a
// randomizing, flapping, or schedule-correlated endpoint cannot manufacture a
// phantom differential: the always-true responses must stay mutually similar, the
// always-false responses must stay mutually similar, the benign control must be
// self-consistent (parity guard), and the true/false clusters must clearly diverge.
// A surviving hit must additionally REPRODUCE with a second set of constants before
// it is reported. Binary and blocked responses abandon the pair (or the whole
// insertion point), defeating the CDN-image / Akamai-block false positive.
//
// Two gates run before any pair is probed:
//   - the surface gate (#4) skips large rendered HTML pages and cache/CDN-fronted
//     responses, whose dynamic content / cache HIT-MISS swings drown the signal;
//   - the relevance precheck (#5) skips path-segment and header insertion points
//     whose benign value returns the same page as the baseline (a cosmetic
//     catch-all segment or a header the application never consumes).
func (m *Module) testBooleanDiff(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	baselineBody string,
) (*output.ResultEvent, error) {
	// #4 surface gate — header/size only, sends no traffic.
	if modkit.DifferentialSurfaceUnreliable(ctx.Response()) {
		return nil, nil
	}

	// #5 relevance precheck for path-segment / header insertion points.
	if pathOrHeaderInsertionTypes.Contains(ip.Type()) {
		inert, err := m.insertionPointIsInert(ctx, ip, httpClient, baselineBody)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, err
			}
			// A transient error during the precheck skips the precheck, not the scan.
		} else if inert {
			return nil, nil
		}
	}

	order := interleavedProbeOrder3(boolTrueSamples, boolFalseSamples, boolNeutralSamples)

	for _, pair := range booleanDiffPairs {
		trueBodies, falseBodies, neutralBodies, outcome, err := m.runBooleanProbeSet(
			ctx, ip, httpClient, order, pair.truePayload, pair.falsePayload)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, err
			}
			return nil, nil // transport hiccup — abandon the boolean diff
		}
		switch outcome {
		case probeAbortIP:
			return nil, nil
		case probeSkipPair:
			continue
		}

		if !confirmBooleanDiffWithControl(neutralBodies, trueBodies, falseBodies, baselineBody) {
			continue
		}

		// Secondary-literal confirmation: the differential must reproduce with a
		// DIFFERENT always-true / always-false constant pair, or it was a transient
		// fluke (cache miss, round-robin upstream, momentary variant), not a boolean
		// oracle that flips the response for every constant.
		secTrue, secFalse, secNeutral, secOutcome, secErr := m.runBooleanProbeSet(
			ctx, ip, httpClient, order, pair.secTruePayload, pair.secFalsePayload)
		if secErr != nil {
			if errors.Is(secErr, hosterrors.ErrUnresponsiveHost) {
				return nil, secErr
			}
			continue
		}
		if secOutcome != probeOK ||
			!confirmBooleanDiffWithControl(secNeutral, secTrue, secFalse, baselineBody) {
			continue
		}

		trueReq := string(ip.BuildRequest([]byte(ip.BaseValue() + pair.truePayload)))
		falseReq := string(ip.BuildRequest([]byte(ip.BaseValue() + pair.falsePayload)))
		secTrueReq := string(ip.BuildRequest([]byte(ip.BaseValue() + pair.secTruePayload)))
		secFalseReq := string(ip.BuildRequest([]byte(ip.BaseValue() + pair.secFalsePayload)))

		ev := modkit.NewEvidenceCollector()
		ev.Add("baseline", modkit.CtxRequestRaw(ctx), modkit.CtxResponseRaw(ctx))
		ev.Add("true-payload", trueReq, trueBodies[0])
		ev.Add("false-payload", falseReq, falseBodies[0])
		ev.Add("recheck-true-payload", secTrueReq, secTrue[0])
		ev.Add("recheck-false-payload", secFalseReq, secFalse[0])

		urlx, _ := ctx.URL()
		return &output.ResultEvent{
			URL:                urlx.String(),
			Matched:            urlx.String(),
			Request:            trueReq,
			FuzzingParameter:   ip.Name(),
			ExtractedResults:   []string{pair.truePayload, pair.falsePayload},
			AdditionalEvidence: ev.Entries(),
			Info: output.Info{
				Name: "NoSQL Boolean-based Injection",
				Description: fmt.Sprintf(
					"Boolean differential reproduced across %d always-true and %d always-false probes against a benign same-cadence control, then reconfirmed with independent constants (%s vs %s): each condition stays self-consistent across repeats while the true/false clusters diverge beyond the endpoint's own per-request variance — via parameter %q — %s",
					len(trueBodies), len(falseBodies), pair.secTruePayload, pair.secFalsePayload, ip.Name(), pair.desc,
				),
				Severity:   severity.High,
				Confidence: severity.Tentative,
				Tags:       []string{"nosqli", "boolean-injection", "mongodb"},
				Reference:  []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"},
			},
			Metadata: map[string]any{
				"true_samples":  len(trueBodies),
				"false_samples": len(falseBodies),
				"baseline_len":  len(baselineBody),
			},
		}, nil
	}

	return nil, nil
}

// probeCond identifies which condition a scheduled probe sends.
type probeCond int

const (
	condTrue probeCond = iota
	condFalse
	condNeutral
)

// probeOutcome is the disposition of a full probe set for one true/false pair.
type probeOutcome int

const (
	probeOK       probeOutcome = iota
	probeSkipPair              // non-analyzable here (block / NoSQL error / non-2xx true) — try the next pair
	probeAbortIP               // the whole insertion point is non-analyzable (binary body)
)

// interleavedProbeOrder3 returns a send schedule that round-robins the always-true,
// always-false, and benign-control conditions so any slow drift — and, crucially,
// any cadence-correlated variance (round-robin upstreams, alternating cache
// HIT/MISS) — lands on all three conditions rather than biasing one cluster.
func interleavedProbeOrder3(trueN, falseN, neutralN int) []probeCond {
	order := make([]probeCond, 0, trueN+falseN+neutralN)
	for trueN > 0 || falseN > 0 || neutralN > 0 {
		if trueN > 0 {
			order = append(order, condTrue)
			trueN--
		}
		if falseN > 0 {
			order = append(order, condFalse)
			falseN--
		}
		if neutralN > 0 {
			order = append(order, condNeutral)
			neutralN--
		}
	}
	return order
}

// runBooleanProbeSet sends one interleaved schedule of always-true, always-false,
// and benign-control probes for a single true/false constant pair, classifying each
// response. It returns the per-condition bodies plus an outcome telling the caller
// whether to use the set, skip this pair, or abandon the insertion point.
func (m *Module) runBooleanProbeSet(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	order []probeCond,
	truePayload, falsePayload string,
) (trueBodies, falseBodies, neutralBodies []string, outcome probeOutcome, err error) {
	for _, cond := range order {
		suffix := benignProbeSuffix
		switch cond {
		case condTrue:
			suffix = truePayload
		case condFalse:
			suffix = falsePayload
		}

		s, perr := m.probeBoolean(ctx, ip, httpClient, suffix)
		if perr != nil {
			return nil, nil, nil, probeAbortIP, perr
		}
		// A binary body means the endpoint serves non-text content (a CDN image
		// object); a text differential is meaningless, so abandon the whole point.
		if s.binary {
			return nil, nil, nil, probeAbortIP, nil
		}
		// A blocked page (WAF/auth/rate-limit) or a NoSQL error surface disqualifies
		// this pair — try the next.
		if s.blocked || s.nosqlErr {
			return nil, nil, nil, probeSkipPair, nil
		}
		// Status discipline (all branches): a NoSQL boolean oracle returns 2xx for
		// every branch — the same endpoint rendering a different result set. A branch
		// that flips to a 3xx redirect / 4xx / 5xx is a status artifact (auth bounce,
		// error page), not query control, so the true/false differential would be a
		// status flip. Previously only condTrue was gated, and it accepted 3xx; require
		// strict 2xx on every branch (mirrors sqli_boolean_blind's statusOK).
		if s.status < 200 || s.status >= 300 {
			return nil, nil, nil, probeSkipPair, nil
		}
		switch cond {
		case condTrue:
			trueBodies = append(trueBodies, s.body)
		case condFalse:
			falseBodies = append(falseBodies, s.body)
		case condNeutral:
			neutralBodies = append(neutralBodies, s.body)
		}
	}
	return trueBodies, falseBodies, neutralBodies, probeOK, nil
}

// insertionPointIsInert reports whether a path-segment or header insertion point
// ignores its value: it sends one benign, operator-free value and compares the
// response to the captured baseline. A cosmetic catch-all path segment or a header
// the application never consumes returns the SAME page for any value, so a boolean
// true/false differential there is endpoint noise, not query control. It fails OPEN
// (not inert) whenever it cannot decide — no baseline, a transport error, or a
// non-analyzable (blocked/binary/NoSQL-error) probe — so the main path still runs.
func (m *Module) insertionPointIsInert(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	baselineBody string,
) (bool, error) {
	if baselineBody == "" {
		return false, nil
	}
	s, err := m.probeBoolean(ctx, ip, httpClient, benignProbeSuffix)
	if err != nil {
		return false, err
	}
	if s.blocked || s.binary || s.nosqlErr {
		return false, nil
	}
	nb := normalizeResponse(baselineBody)
	ns := normalizeResponse(s.body)
	if nb == "" || ns == "" {
		return false, nil
	}
	return diceSimilarity(nb, ns) >= booleanInertMax, nil
}

// pathOrHeaderInsertionTypes are the high-noise, low-yield surfaces for boolean
// NoSQLi — URL path segments and HTTP headers — where the relevance precheck
// applies (a cosmetic path segment or an unconsumed header yields no query signal).
var pathOrHeaderInsertionTypes = modkit.NewInsertionPointTypeSet(
	httpmsg.INS_HEADER, httpmsg.INS_URL_PATH_FOLDER, httpmsg.INS_URL_PATH_FILENAME,
)

// probeBoolean sends one boolean-diff payload and classifies the response. It
// bypasses the response cache (NoClustering) so repeated identical sends are
// genuinely fresh observations — essential for measuring the endpoint's
// per-request variance rather than replaying a single clustered body.
func (m *Module) probeBoolean(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	payloadValue string,
) (boolSample, error) {
	fuzzedValue := ip.BaseValue() + payloadValue
	// BuildRequest produces well-formed raw, so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(ip.BuildRequest([]byte(fuzzedValue)), ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoClustering: true})
	if err != nil {
		return boolSample{}, err
	}
	defer resp.Close()

	s := boolSample{blocked: infra.IsBlockedResponse(resp)}
	if resp.Response() != nil {
		s.status = resp.Response().StatusCode
		s.binary = isBinaryContentType(resp.Response().Header.Get("Content-Type"))
	}
	s.body = resp.Body().String()
	if !s.binary {
		s.binary = looksBinary(s.body)
	}
	s.nosqlErr = containsNoSQLError(s.body)
	return s, nil
}
