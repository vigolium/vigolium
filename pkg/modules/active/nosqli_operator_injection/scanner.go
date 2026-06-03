package nosqli_operator_injection

import (
	"fmt"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
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

// CanProcess extends the default to skip non-injectable content types.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if !m.BaseActiveModule.CanProcess(ctx) {
		return false
	}
	if ctx.Response() != nil {
		ct := strings.ToLower(ctx.Response().Header("Content-Type"))
		if strings.Contains(ct, "image/") || strings.Contains(ct, "audio/") || strings.Contains(ct, "video/") {
			return false
		}
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

	// Dedup check
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Baseline data
	var baselineBody string
	var baselineStatus int
	if ctx.Response() != nil {
		baselineBody = ctx.Response().BodyToString()
		baselineStatus = ctx.Response().StatusCode()
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

	// Boolean diff: test true/false pairs
	result, err := m.testBooleanDiff(ctx, ip, httpClient, payloads, baselineBody, baselineStatus)
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
	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return nil, nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil, err
	}

	body := resp.Body().String()
	probeStatus := 0
	if resp.Response() != nil {
		probeStatus = resp.Response().StatusCode
	}
	resp.Close()

	// Skip if response contains NoSQL error patterns (delegate to nosqli_error_based)
	if containsNoSQLError(body) {
		return nil, nil
	}

	var detected bool
	var detectionDesc string
	// Auth bypass is a directly observable 401/403→2xx transition (re-confirmed
	// interleaved), so it stays high/firm. The size-increase path only INFERS
	// exfiltration from response growth — it never proves leaked data is in the
	// body — so it is FP-prone and reported as suspect/tentative, matching the
	// time-based path.
	findingSeverity := severity.High
	findingConfidence := severity.Firm

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
		// Require a real captured baseline: a status AND a non-empty body. A
		// served (2xx) page that captured as 0 bytes is almost always an
		// encoding/capture artifact (gzip not decoded at capture, streamed/HEAD
		// body) — and analyzeSizeIncrease(0, N) would misread any non-trivial
		// response as a size increase from zero. This is exactly the reported
		// Cloudflare-Access SSO-page false positive: empty captured baseline,
		// 200 status, a 22 KB static login page returned for every value.
		//
		// Beyond the captured-baseline delta, confirmSizeIncrease must reproduce
		// the growth against a FRESH clean fetch AND find the payload body
		// structurally divergent from it.
		if baselineStatus != 0 && len(baselineBody) > 0 &&
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
// caused by the operator payload, not a transient block — a 401/403 from a
// WAF/rate-limit layer that simply cleared between requests, or auth that is
// enforced intermittently. It re-runs the pair interleaved with the payload as
// the only variable: each round the ORIGINAL base value must STILL be denied
// (401/403) and the payload value must STILL be allowed (2xx). The fetches bypass
// the response cache so a stale replay can't mask flapping. Fails open on a
// transport error so a transient failure never suppresses a true positive.
func (m *Module) confirmAuthBypass(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	payloadValue string,
) bool {
	const rounds = 2
	for range rounds {
		controlStatus, err := m.freshStatus(ctx, ip, httpClient, ip.BaseValue())
		if err != nil {
			return true // fail open on transport error
		}
		if controlStatus != 401 && controlStatus != 403 {
			return false // not denied WITHOUT the payload → the block isn't payload-attributable
		}
		probeStatus, err := m.freshStatus(ctx, ip, httpClient, payloadValue)
		if err != nil {
			return true
		}
		if probeStatus < 200 || probeStatus >= 300 {
			return false // not allowed WITH the payload → not a reproducible bypass
		}
	}
	return true
}

// freshStatus issues the insertion point built with value and returns the status
// code, bypassing the response cache (NoClustering) so a confirmation re-fetch is
// a genuinely fresh observation rather than a replayed one.
func (m *Module) freshStatus(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	value string,
) (int, error) {
	req, err := httpmsg.ParseRawRequest(string(ip.BuildRequest([]byte(value))))
	if err != nil {
		return 0, err
	}
	req = req.WithService(ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoClustering: true})
	if err != nil {
		return 0, err
	}
	defer resp.Close()
	if resp.Response() == nil {
		return 0, nil
	}
	return resp.Response().StatusCode, nil
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
		_, body, _, err := m.measureDuration(ctx, ip, httpClient, ip.BaseValue())
		if err != nil {
			return false // fail closed: cannot reproduce a clean baseline
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
	baselineDuration, _, _, err := m.measureDuration(ctx, ip, httpClient, ip.BaseValue())
	if err != nil {
		return nil, err
	}

	fuzzedValue := ip.BaseValue() + payload.value
	fuzzedRaw := ip.BuildRequest([]byte(fuzzedValue))

	var lastDelay time.Duration
	for i := 0; i < timeBasedConfirmationRounds; i++ {
		probeDuration, body, _, err := m.measureDuration(ctx, ip, httpClient, fuzzedValue)
		if err != nil {
			return nil, err
		}
		if containsNoSQLError(body) {
			return nil, nil
		}
		if !analyzeTimeDelay(baselineDuration, probeDuration) {
			return nil, nil
		}
		lastDelay = probeDuration - baselineDuration
	}

	ev := modkit.NewEvidenceCollector()
	ev.Add("baseline", modkit.CtxRequestRaw(ctx), modkit.CtxResponseRaw(ctx))

	urlx, _ := ctx.URL()
	return &output.ResultEvent{
		URL:                urlx.String(),
		Matched:            urlx.String(),
		Request:            string(fuzzedRaw),
		FuzzingParameter:   ip.Name(),
		ExtractedResults:   []string{payload.value},
		AdditionalEvidence: ev.Entries(),
		Info: output.Info{
			Name: "NoSQL Operator Injection",
			Description: fmt.Sprintf(
				"Time-based injection confirmed over %d rounds (baseline %dms, last probe delayed by %dms) — %s via parameter %q",
				timeBasedConfirmationRounds, baselineDuration.Milliseconds(), lastDelay.Milliseconds(), payload.desc, ip.Name(),
			),
			// Time-based inference is prone to backend-delay false positives
			// (unlike the auth-bypass/size/boolean paths) — flag as suspect.
			Severity:   severity.Suspect,
			Confidence: severity.Tentative,
			Tags:       []string{"nosqli", "injection", "mongodb", "time-based"},
			Reference:  []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"},
		},
		Metadata: map[string]any{
			"baseline_ms":         baselineDuration.Milliseconds(),
			"delay_ms":            lastDelay.Milliseconds(),
			"sleep_ms":            timeBasedSleepMs,
			"confirmation_rounds": timeBasedConfirmationRounds,
		},
	}, nil
}

// measureDuration executes a single request with the given fuzzed value and
// returns its wall-clock duration along with the response body and status.
func (m *Module) measureDuration(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	value string,
) (time.Duration, string, int, error) {
	raw := ip.BuildRequest([]byte(value))
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return 0, "", 0, err
	}
	req = req.WithService(ctx.Service())

	start := time.Now()
	resp, _, err := httpClient.Execute(req, http.Options{})
	if err != nil {
		return 0, "", 0, err
	}
	duration := time.Since(start)
	body := resp.Body().String()
	status := 0
	if resp.Response() != nil {
		status = resp.Response().StatusCode
	}
	resp.Close()
	return duration, body, status, nil
}

// testBooleanDiff tests true/false payload pairs to detect boolean-based NoSQL injection.
func (m *Module) testBooleanDiff(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	payloads []nosqliPayload,
	baselineBody string,
	baselineStatus int,
) (*output.ResultEvent, error) {
	// Collect boolean diff payloads in true/false pairs
	var boolPayloads []nosqliPayload
	for _, p := range payloads {
		if p.detectType == detectBooleanDiff {
			boolPayloads = append(boolPayloads, p)
		}
	}

	// Process in pairs (true condition, false condition)
	for i := 0; i+1 < len(boolPayloads); i += 2 {
		truePayload := boolPayloads[i]
		falsePayload := boolPayloads[i+1]

		trueBody, trueStatus, err := m.sendPayload(ctx, ip, httpClient, truePayload.value)
		if err != nil {
			return nil, err
		}

		// Skip if response contains NoSQL errors
		if containsNoSQLError(trueBody) {
			continue
		}

		falseBody, falseStatus, err := m.sendPayload(ctx, ip, httpClient, falsePayload.value)
		if err != nil {
			return nil, err
		}

		if containsNoSQLError(falseBody) {
			continue
		}

		// Skip when either probe was blocked by an auth/WAF/rate-limit layer — a
		// block page asymmetry (WAF blocks one payload, app serves the other) is
		// not evidence of boolean-based NoSQL injection.
		if isAccessDenied(trueStatus) || isAccessDenied(falseStatus) {
			continue
		}

		// The always-true condition must yield a valid (served) response.
		if trueStatus < 200 || trueStatus >= 400 {
			continue
		}

		// Stability re-probe: send the always-true payload a second time to measure
		// the endpoint's intrinsic per-request variance. Endpoints that embed a fresh
		// token/nonce/timestamp in every response (e.g. bot-detection/challenge pages)
		// would otherwise make any true/false difference look like a boolean signal.
		trueBody2, _, err := m.sendPayload(ctx, ip, httpClient, truePayload.value)
		if err != nil {
			return nil, err
		}
		if containsNoSQLError(trueBody2) {
			continue
		}

		if !confirmBooleanDiff(trueBody, trueBody2, falseBody, baselineBody) {
			continue
		}

		ev := modkit.NewEvidenceCollector()
		ev.Add("baseline", modkit.CtxRequestRaw(ctx), modkit.CtxResponseRaw(ctx))
		ev.Add("true-payload", string(ip.BuildRequest([]byte(ip.BaseValue()+truePayload.value))), trueBody)
		ev.Add("false-payload", string(ip.BuildRequest([]byte(ip.BaseValue()+falsePayload.value))), falseBody)

		urlx, _ := ctx.URL()
		return &output.ResultEvent{
			URL:                urlx.String(),
			Matched:            urlx.String(),
			Request:            string(ip.BuildRequest([]byte(ip.BaseValue() + truePayload.value))),
			FuzzingParameter:   ip.Name(),
			ExtractedResults:   []string{truePayload.value, falsePayload.value},
			AdditionalEvidence: ev.Entries(),
			Info: output.Info{
				Name:        "NoSQL Boolean-based Injection",
				Description: fmt.Sprintf("Boolean differential confirmed: always-true and always-false conditions produce structurally different responses (beyond the endpoint's own per-request variance) via parameter %q — %s", ip.Name(), truePayload.desc),
				Severity:    severity.High,
				Confidence:  severity.Firm,
				Tags:        []string{"nosqli", "boolean-injection", "mongodb"},
				Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"},
			},
			Metadata: map[string]any{
				"true_body_len":  len(trueBody),
				"false_body_len": len(falseBody),
				"baseline_len":   len(baselineBody),
			},
		}, nil
	}

	_ = baselineStatus // baseline status reserved for future auth-state checks

	return nil, nil
}

// sendPayload sends a payload and returns the response body and status.
func (m *Module) sendPayload(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	payloadValue string,
) (string, int, error) {
	fuzzedValue := ip.BaseValue() + payloadValue
	fuzzedRaw := ip.BuildRequest([]byte(fuzzedValue))

	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return "", 0, nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return "", 0, err
	}
	defer resp.Close()

	body := resp.Body().String()
	status := 0
	if resp.Response() != nil {
		status = resp.Response().StatusCode
	}
	return body, status, nil
}
