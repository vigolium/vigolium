package nosqli_operator_injection

import (
	"fmt"
	"strings"
	"time"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/pkg/errors"
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

	switch payload.detectType {
	case detectAuthBypass:
		if analyzeAuthBypass(baselineStatus, probeStatus) {
			detected = true
			detectionDesc = fmt.Sprintf("Auth bypass: status changed from %d to %d", baselineStatus, probeStatus)
		}
	case detectSizeChange:
		if analyzeSizeIncrease(len(baselineBody), len(body)) {
			detected = true
			detectionDesc = fmt.Sprintf("Data exfiltration: body size increased from %d to %d bytes", len(baselineBody), len(body))
		}
	}

	if !detected {
		return nil, nil
	}

	urlx, _ := ctx.URL()
	return &output.ResultEvent{
		URL:              urlx.String(),
		Matched:          urlx.String(),
		Request:          string(fuzzedRaw),
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{payload.value},
		Info: output.Info{
			Name:        "NoSQL Operator Injection",
			Description: fmt.Sprintf("%s — %s via parameter %q", detectionDesc, payload.desc, ip.Name()),
			Severity:    severity.High,
			Confidence:  severity.Firm,
			Tags:        []string{"nosqli", "injection", "mongodb"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection"},
		},
	}, nil
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

	urlx, _ := ctx.URL()
	return &output.ResultEvent{
		URL:              urlx.String(),
		Matched:          urlx.String(),
		Request:          string(fuzzedRaw),
		FuzzingParameter: ip.Name(),
		ExtractedResults: []string{payload.value},
		Info: output.Info{
			Name: "NoSQL Operator Injection",
			Description: fmt.Sprintf(
				"Time-based injection confirmed over %d rounds (baseline %dms, last probe delayed by %dms) — %s via parameter %q",
				timeBasedConfirmationRounds, baselineDuration.Milliseconds(), lastDelay.Milliseconds(), payload.desc, ip.Name(),
			),
			Severity:   severity.High,
			Confidence: severity.Firm,
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

		falseBody, _, err := m.sendPayload(ctx, ip, httpClient, falsePayload.value)
		if err != nil {
			return nil, err
		}

		if containsNoSQLError(falseBody) {
			continue
		}

		// Check: true condition should differ from false condition
		// AND true condition should be more similar to baseline (or produce a valid response)
		if analyzeBooleanDiff(trueBody, falseBody) && trueStatus >= 200 && trueStatus < 400 {
			urlx, _ := ctx.URL()
			return &output.ResultEvent{
				URL:              urlx.String(),
				Matched:          urlx.String(),
				Request:          string(ip.BuildRequest([]byte(ip.BaseValue() + truePayload.value))),
				FuzzingParameter: ip.Name(),
				ExtractedResults: []string{truePayload.value, falsePayload.value},
				Info: output.Info{
					Name:        "NoSQL Boolean-based Injection",
					Description: fmt.Sprintf("Boolean differential detected: true/false conditions produce different responses via parameter %q — %s", ip.Name(), truePayload.desc),
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
	}

	_ = baselineStatus // used for context in future enhancements

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
