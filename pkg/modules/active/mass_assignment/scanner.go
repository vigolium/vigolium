package mass_assignment

import (
	"encoding/json"
	"maps"
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
	status int
	body   string // response body only (for comparison/echo checks)
	full   string // full response incl. headers (evidence)
	raw    []byte // the modified request, raw
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
		} else if keyNewlyReflected(canaryKey, ctl.body, baselineBody) {
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
		//   2. the injected key surfaces in the response because of us (it was not
		//      already present in the baseline).
		// Without this, an endpoint that silently ignores the field returns the same
		// 2xx response as before and must NOT be flagged.
		if normalizeBody(res.body) == normalizeBody(baselineBody) {
			continue
		}
		if !keyNewlyReflected(probe.key, res.body, baselineBody) {
			continue
		}

		results = append(results, &output.ResultEvent{
			URL:              urlx.String(),
			Request:          string(res.raw),
			Response:         res.full,
			FuzzingParameter: probe.key,
			ExtractedResults: []string{probe.key + "=" + toString(probe.value)},
			Info: output.Info{
				Description: "Mass assignment: injecting privilege key '" + probe.key +
					"' changed the response and the key was reflected back, indicating the server accepted an unauthorized field.",
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

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil, err
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	res := &injResult{raw: modifiedRaw}
	if resp.Response() != nil {
		res.status = resp.Response().StatusCode
		res.body = resp.BodyString()
		res.full = resp.FullResponseString()
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

// keyNewlyReflected reports whether the JSON key surfaces in the injected response
// but was absent from the baseline response — i.e. it appears because we injected it,
// not because the endpoint naturally returns that field.
func keyNewlyReflected(key, injectedBody, baselineBody string) bool {
	needle := `"` + key + `"`
	return strings.Contains(injectedBody, needle) && !strings.Contains(baselineBody, needle)
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
