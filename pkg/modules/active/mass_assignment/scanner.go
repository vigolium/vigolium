package mass_assignment

import (
	"encoding/json"
	"maps"
	stdurl "net/url"
	"reflect"
	"strings"

	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// privilegeProbes are key/value pairs to inject into JSON bodies.
var privilegeProbes = []struct {
	key   string
	value any
}{
	{"role", "admin"},
	{"admin", true},
	{"is_admin", true},
	{"isAdmin", true},
	{"permissions", "admin"},
	{"user_type", "admin"},
	{"userType", "admin"},
	{"privilege", "admin"},
	{"access_level", 99},
	{"verified", true},
	{"admin", "true"},
	{"user", map[string]any{"role": "admin"}},
	{"roles", []any{"admin", "user"}},
	{"level", 9999},
}

// canaryKey is a benign, non-privileged field used as a control. If the endpoint
// echoes this arbitrary unknown key back, it blindly reflects whatever it receives
// and any privilege-key "echo" is meaningless — so we suppress findings entirely.
const (
	canaryKey   = "vgl_ma_canary_field"
	canaryValue = "vgl_ma_canary_value"
)

// Module implements the Mass Assignment active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds                dedup.Lazy[dedup.DiskSet]
	limitCheckPerHost int
}

// New creates a new Mass Assignment module.
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
		ds:                dedup.LazyDiskSet("mass_assignment"),
		limitCheckPerHost: 10,
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess returns true only for POST/PUT/PATCH with JSON content type.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}

	method := ctx.Request().Method()
	if method != "POST" && method != "PUT" && method != "PATCH" {
		return false
	}

	if ctx.Response() == nil {
		return false
	}

	// Check request content-type for JSON
	reqCT := ""
	for _, h := range ctx.Request().Headers() {
		if strings.EqualFold(h.Name, "Content-Type") {
			reqCT = strings.ToLower(h.Value)
			break
		}
	}

	return strings.Contains(reqCT, "application/json")
}

// IncludesBaseCanProcess returns false since we have fully custom CanProcess.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// injResult holds the outcome of a single injected request.
type injResult struct {
	status   int
	body     string // response body only (for comparison/echo checks)
	full     string // full response incl. headers (evidence)
	raw      []byte // the modified request, raw
	location string
}

// ScanPerRequest tests mass assignment on the given JSON request.
//
// Detection is differential: a privilege key is only reported when injecting it
// actually changes the response AND the key appears in the response because of our
// injection (it is absent from the untouched baseline). A benign canary key is sent
// first; if the endpoint echoes that too, it reflects arbitrary input indiscriminately
// and we report nothing — this avoids flagging endpoints that simply ignore or blindly
// mirror unknown fields without honoring them.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if !m.markAndShouldContinue(urlx, scanCtx) {
		return nil, nil
	}

	body := ctx.Request().Body()
	if len(body) == 0 {
		return nil, nil
	}

	// Parse JSON body
	var originalObj map[string]any
	if err := json.Unmarshal(body, &originalObj); err != nil {
		return nil, nil // Not a JSON object, skip
	}

	// Baseline body from the original, un-injected response. Used to attribute any
	// reflected key to our injection rather than the endpoint's natural output.
	baselineBody := ctx.Response().BodyToString()

	// Control probe: inject a benign unknown key. If the endpoint reflects it back
	// (and the baseline did not already contain it), it mirrors arbitrary input and
	// no privilege-key echo can be trusted — bail out to avoid false positives.
	if _, exists := originalObj[canaryKey]; !exists {
		control := make(map[string]any, len(originalObj)+1)
		maps.Copy(control, originalObj)
		control[canaryKey] = canaryValue

		ctl, err := m.sendInjected(ctx, httpClient, control)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
		} else if valueNewlyReflected(canaryKey, canaryValue, ctl.body, baselineBody) {
			// Endpoint blindly reflects unknown fields — unreliable, report nothing.
			return nil, nil
		}
	}

	var results []*output.ResultEvent

	for _, probe := range privilegeProbes {
		// Skip if key already exists in original body
		if _, exists := originalObj[probe.key]; exists {
			continue
		}

		// Clone the object and inject the probe key
		injected := make(map[string]any, len(originalObj)+1)
		maps.Copy(injected, originalObj)
		injected[probe.key] = probe.value

		// Capture a fresh no-key control BEFORE mutation. A post-mutation control
		// is invalid for stateful endpoints: if the injection really persisted,
		// the subsequent no-key response should still contain the value and would
		// incorrectly suppress the true positive.
		preControl, err := m.sendInjected(ctx, httpClient, originalObj)
		if err != nil || preControl.status < 200 || preControl.status >= 300 ||
			jsonContainsKeyValue(preControl.body, probe.key, probe.value) {
			continue
		}

		res, err := m.sendInjected(ctx, httpClient, injected)
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		// Server rejected the unknown field — it validates input, not vulnerable.
		if isRejected(res.status, res.body) {
			continue
		}

		if res.status < 200 || res.status >= 300 {
			continue
		}

		// Require evidence the injection actually took effect:
		//   1. the response genuinely differs from the un-injected baseline, AND
		//   2. the exact typed key/value surfaces in the response because of us.
		// Without this, an endpoint that silently ignores the field returns the same
		// 2xx response as before and must NOT be flagged.
		if normalizeBody(res.body) == normalizeBody(baselineBody) {
			continue
		}
		if !valueNewlyReflected(probe.key, probe.value, res.body, baselineBody) {
			continue
		}
		// Reconfirm the key's reflection TRACKS our injection rather than being the
		// page's own per-request variance. The baseline is a single (possibly stale)
		// snapshot, so a common word like "level"/"verified" that drifts in and out
		// of an SSR page's embedded state (feature flags, personalization) can look
		// "newly reflected" by coincidence. Require it to reflect again on re-injection
		// AND be absent from a fresh no-key control before trusting it.
		if !m.reflectionTracksInjection(ctx, httpClient, injected, probe.key, probe.value) {
			continue
		}

		readback, persisted := m.verifyPersistence(ctx, httpClient, res, probe.key, probe.value)
		kind := output.RecordKindCandidate
		grade := output.EvidenceGradeDifferential
		name := "Mass Assignment Acceptance Candidate"
		description := "The endpoint repeatedly returned the exact injected privilege value while a benign unknown field was not accepted. This proves selective binding/acceptance, but no durable state readback was available."
		var additionalEvidence []string
		if persisted {
			kind = output.RecordKindFinding
			grade = output.EvidenceGradeImpact
			name = "Mass Assignment with Persistent Privilege Field"
			description = "The endpoint accepted the exact injected privilege value and two independent GET readbacks returned that same typed value, confirming durable unauthorized state assignment."
			additionalEvidence = []string{readback.rawString(), readback.full}
		}

		results = append(results, &output.ResultEvent{
			ModuleID:           ModuleID,
			URL:                urlx.String(),
			Request:            string(res.raw),
			Response:           res.full,
			AdditionalEvidence: additionalEvidence,
			FuzzingParameter:   probe.key,
			ExtractedResults:   []string{probe.key + "=" + toString(probe.value)},
			RecordKind:         kind,
			EvidenceGrade:      grade,
			Info: output.Info{
				Name:        name,
				Description: description,
				Severity:    ModuleSeverity,
				Confidence:  ModuleConfidence,
				Tags:        ModuleTags,
			},
			Metadata: map[string]any{
				"injected_key":   probe.key,
				"injected_value": probe.value,
				"persisted":      persisted,
			},
		})
		return results, nil
	}

	return results, nil
}

// sendInjected marshals obj, swaps it into the request body, executes it, and returns
// the (closed) response details. The caller does not need to Close anything.
func (m *Module) sendInjected(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	obj map[string]any,
) (*injResult, error) {
	injectedBody, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	modifiedRaw, err := httpmsg.SetBody(ctx.Request().Raw(), injectedBody)
	if err != nil {
		return nil, err
	}

	// modifiedRaw is internally built (well-formed), so wrap directly instead
	// of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	res := &injResult{raw: modifiedRaw}
	if resp.Response() != nil {
		res.status = resp.Response().StatusCode
		res.body = resp.BodyString()
		res.full = resp.FullResponseString()
		res.location = resp.Response().Header.Get("Location")
	}
	return res, nil
}

// isRejected reports whether the server explicitly refused the unknown field.
func isRejected(status int, body string) bool {
	if status == 400 || status == 422 {
		return true
	}
	b := strings.ToLower(body)
	return strings.Contains(b, "unknown field") ||
		strings.Contains(b, "unexpected field") ||
		strings.Contains(b, "not allowed")
}

// valueNewlyReflected requires the exact typed value, not just the key name. A
// server that accepts a known field but normalizes role=admin back to role=user
// has not granted the requested privilege and must not be reported.
func valueNewlyReflected(key string, value any, injectedBody, baselineBody string) bool {
	return jsonContainsKeyValue(injectedBody, key, value) && !jsonContainsKeyValue(baselineBody, key, value)
}

// reflectionTracksInjection reconfirms that a privilege key surfaces in the
// response BECAUSE we injected it, not because the endpoint's output naturally
// varies request to request. The caller captured a fresh pre-mutation no-key
// control; this helper re-sends the injected body and requires the exact typed
// value again. Transport ambiguity fails closed.
func (m *Module) reflectionTracksInjection(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	injected map[string]any,
	key string,
	value any,
) bool {
	// (a) Re-inject: a genuinely accepted/echoed field reflects on every send. A 2xx
	// re-injection that no longer carries the key means the first reflection was
	// per-request noise, not our field.
	re, err := m.sendInjected(ctx, httpClient, injected)
	if err != nil || re.status < 200 || re.status >= 300 || !jsonContainsKeyValue(re.body, key, value) {
		return false
	}

	return true
}

func jsonContainsKeyValue(body, key string, expected any) bool {
	var document any
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		return false
	}
	canonicalExpected := canonicalJSONValue(expected)
	return findJSONKeyValue(document, key, canonicalExpected)
}

func canonicalJSONValue(value any) any {
	encoded, err := json.Marshal(value)
	if err != nil {
		return value
	}
	var canonical any
	if err := json.Unmarshal(encoded, &canonical); err != nil {
		return value
	}
	return canonical
}

func findJSONKeyValue(value any, key string, expected any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for candidate, child := range typed {
			if candidate == key && jsonValueContains(child, expected) {
				return true
			}
			if findJSONKeyValue(child, key, expected) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if findJSONKeyValue(child, key, expected) {
				return true
			}
		}
	}
	return false
}

// jsonValueContains permits response objects to enrich an injected nested map
// with server fields while still requiring every requested nested value.
func jsonValueContains(actual, expected any) bool {
	expectedMap, expectedIsMap := expected.(map[string]any)
	actualMap, actualIsMap := actual.(map[string]any)
	if expectedIsMap {
		if !actualIsMap {
			return false
		}
		for key, expectedChild := range expectedMap {
			actualChild, ok := actualMap[key]
			if !ok || !jsonValueContains(actualChild, expectedChild) {
				return false
			}
		}
		return true
	}
	return reflect.DeepEqual(actual, expected)
}

func (m *Module) verifyPersistence(
	ctx *httpmsg.HttpRequestResponse,
	client *http.Requester,
	injected *injResult,
	key string,
	value any,
) (*injResult, bool) {
	readRaw, ok := readbackRequest(ctx, injected.location)
	if !ok {
		return nil, false
	}
	first, err := m.sendRaw(ctx, client, readRaw)
	if err != nil || first.status < 200 || first.status >= 300 || !jsonContainsKeyValue(first.body, key, value) {
		return nil, false
	}
	second, err := m.sendRaw(ctx, client, readRaw)
	if err != nil || second.status != first.status || !jsonContainsKeyValue(second.body, key, value) || !modkit.BodiesSimilar(first.body, second.body) {
		return nil, false
	}
	return first, true
}

func readbackRequest(ctx *httpmsg.HttpRequestResponse, location string) ([]byte, bool) {
	method := strings.ToUpper(ctx.Request().Method())
	raw := append([]byte(nil), ctx.Request().Raw()...)
	if method == "POST" {
		if strings.TrimSpace(location) == "" {
			return nil, false
		}
		parsed, err := stdurl.Parse(location)
		if err != nil {
			return nil, false
		}
		if parsed.IsAbs() {
			urlx, err := ctx.URL()
			if err != nil || !strings.EqualFold(parsed.Host, urlx.Host) {
				return nil, false
			}
		}
		path := parsed.EscapedPath()
		if path == "" {
			path = "/"
		}
		if parsed.RawQuery != "" {
			path += "?" + parsed.RawQuery
		}
		raw, err = httpmsg.SetPath(raw, path)
		if err != nil {
			return nil, false
		}
	} else if method != "PUT" && method != "PATCH" {
		return nil, false
	}
	var err error
	raw, err = httpmsg.SetMethod(raw, "GET")
	if err != nil {
		return nil, false
	}
	raw, err = httpmsg.SetBody(raw, nil)
	if err != nil {
		return nil, false
	}
	return raw, true
}

func (m *Module) sendRaw(ctx *httpmsg.HttpRequestResponse, client *http.Requester, raw []byte) (*injResult, error) {
	request := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := client.Execute(request, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil, err
	}
	defer resp.Close()
	result := &injResult{raw: raw}
	if resp.Response() != nil {
		result.status = resp.Response().StatusCode
		result.body = resp.BodyString()
		result.full = resp.FullResponseString()
		result.location = resp.Response().Header.Get("Location")
	}
	return result, nil
}

func (r *injResult) rawString() string {
	if r == nil {
		return ""
	}
	return string(r.raw)
}

// normalizeBody strips all whitespace so two responses can be compared for material
// (rather than cosmetic) differences.
func normalizeBody(s string) string {
	return strings.Join(strings.Fields(s), "")
}

// markAndShouldContinue limits checks per host.
func (m *Module) markAndShouldContinue(urlx *urlutil.URL, scanCtx *modkit.ScanContext) bool {
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet == nil {
		return true
	}
	dedupKey := utils.Sha1(urlx.Hostname() + urlx.Path + strings.ToUpper(urlx.RawQuery))
	_, shouldContinue := diskSet.IncrementAndCheck(dedupKey, m.limitCheckPerHost)
	return shouldContinue
}

func toString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
