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

// ScanPerRequest tests mass assignment on the given JSON request.
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

		injectedBody, err := json.Marshal(injected)
		if err != nil {
			continue
		}

		modifiedRaw, err := httpmsg.SetBody(ctx.Request().Raw(), injectedBody)
		if err != nil {
			continue
		}

		fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		statusCode := 0
		respBody := ""
		if resp.Response() != nil {
			statusCode = resp.Response().StatusCode
			respBody = resp.FullResponse().String()
		}

		// Server returned validation error — skip (server properly rejects unknown fields)
		if statusCode == 400 || statusCode == 422 {
			resp.Close()
			continue
		}

		respBodyLower := strings.ToLower(respBody)
		if strings.Contains(respBodyLower, "unknown field") ||
			strings.Contains(respBodyLower, "unexpected field") ||
			strings.Contains(respBodyLower, "not allowed") {
			resp.Close()
			continue
		}

		if statusCode >= 200 && statusCode < 300 {
			// Check if the injected key is echoed back in the response
			echoed := strings.Contains(respBody, `"`+probe.key+`"`)

			desc := "Mass assignment: server accepted injected key '" + probe.key + "'"
			if echoed {
				desc = "Mass assignment: server echoed back injected privilege key '" + probe.key + "'"
			}

			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Request:          string(modifiedRaw),
				Response:         respBody,
				FuzzingParameter: probe.key,
				ExtractedResults: []string{probe.key + "=" + toString(probe.value)},
				Info: output.Info{
					Description: desc,
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
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
