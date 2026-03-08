package csrf_verify

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
)

// csrfParamPattern matches common CSRF token parameter names.
var csrfParamPattern = regexp.MustCompile(`(?i)(csrf|xsrf|token|authenticity.token|__RequestVerificationToken|antiforgery|_token|nonce|csrfmiddlewaretoken)`)

// stateChangingMethods are HTTP methods that modify server state.
var stateChangingMethods = map[string]bool{
	"POST":   true,
	"PUT":    true,
	"DELETE": true,
	"PATCH":  true,
}

// csrfProbe defines a CSRF verification strategy.
type csrfProbe struct {
	name string
	desc string
	// mutate returns modified raw request bytes; receives param name, type, and original raw
	mutate func(raw []byte, paramName string, paramType httpmsg.ParamType) ([]byte, error)
}

var probes = []csrfProbe{
	{
		name: "Token Removed",
		desc: "CSRF token was completely removed from the request, but the server still accepted it",
		mutate: func(raw []byte, paramName string, paramType httpmsg.ParamType) ([]byte, error) {
			return httpmsg.RemoveParametersByName(raw, []string{paramName}, paramType)
		},
	},
	{
		name: "Token Empty",
		desc: "CSRF token was set to an empty string, but the server still accepted it",
		mutate: func(raw []byte, paramName string, paramType httpmsg.ParamType) ([]byte, error) {
			param := httpmsg.BuildParameter(paramName, "", paramType)
			return httpmsg.UpdateParameter(raw, param)
		},
	},
	{
		name: "Token Randomized",
		desc: "CSRF token was replaced with a random value, but the server still accepted it",
		mutate: func(raw []byte, paramName string, paramType httpmsg.ParamType) ([]byte, error) {
			param := httpmsg.BuildParameter(paramName, utils.RandomString(32), paramType)
			return httpmsg.UpdateParameter(raw, param)
		},
	},
}

// Module implements the CSRF Token Verification active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new CSRF Token Verification module.
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
		ds: dedup.LazyDiskSet("csrf_verify"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest verifies CSRF token enforcement by mutating the token.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Only check state-changing methods
	method := strings.ToUpper(ctx.Request().Method())
	if !stateChangingMethods[method] {
		return nil, nil
	}

	// Dedup by method:host:path
	dedupKey := utils.Sha1(fmt.Sprintf("%s:%s:%s", method, urlx.Host, urlx.Path))
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	// Find CSRF token parameter
	params, err := ctx.Request().Parameters()
	if err != nil {
		return nil, nil
	}

	var csrfParamName string
	var csrfParamType httpmsg.ParamType
	for _, param := range params {
		if csrfParamPattern.MatchString(param.Name()) {
			csrfParamName = param.Name()
			csrfParamType = param.Type()
			break
		}
	}

	// No CSRF token found — passive module handles this case
	if csrfParamName == "" {
		return nil, nil
	}

	// Get baseline status code
	baselineStatus := 0
	if ctx.Response() != nil {
		baselineStatus = ctx.Response().StatusCode()
	}

	var results []*output.ResultEvent

	for _, probe := range probes {
		mutatedRaw, err := probe.mutate(ctx.Request().Raw(), csrfParamName, csrfParamType)
		if err != nil {
			continue
		}

		fuzzedReq, err := httpmsg.ParseRawRequest(string(mutatedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		respStatus := 0
		if resp.Response() != nil {
			respStatus = resp.Response().StatusCode
		}
		resp.Close()

		// If server rejects with 4xx/5xx, token is validated — stop probing
		if respStatus >= 400 {
			return results, nil
		}

		// If response is 2xx and same class as baseline, token was not validated
		if respStatus >= 200 && respStatus < 300 && sameStatusClass(respStatus, baselineStatus) {
			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Matched:          urlx.String(),
				Request:          string(mutatedRaw),
				FuzzingParameter: csrfParamName,
				ExtractedResults: []string{probe.name},
				Info: output.Info{
					Name:        fmt.Sprintf("CSRF Token Not Validated: %s", probe.name),
					Description: probe.desc,
					Severity:    severity.High,
					Confidence:  severity.Firm,
					Tags:        []string{"csrf", "token-bypass", "session"},
					Reference:   []string{"https://portswigger.net/web-security/csrf/bypassing-token-validation"},
				},
				Metadata: map[string]any{
					"csrf_param":      csrfParamName,
					"probe":           probe.name,
					"baseline_status": baselineStatus,
					"probe_status":    respStatus,
				},
			})
			return results, nil
		}
	}

	return results, nil
}

// sameStatusClass checks if two status codes are in the same HTTP status class (2xx, 3xx, etc.)
func sameStatusClass(a, b int) bool {
	return a/100 == b/100
}
