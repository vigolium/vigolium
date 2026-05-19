package jsonp_callback

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

const probeCallback = "vgnmCallback"

// callbackParamNames are common JSONP callback parameter names.
var callbackParamNames = []string{"callback", "cb", "jsonp", "jsonpcallback", "func", "_callback", "handler"}

// jsonpPattern matches existing JSONP response: functionName({...}) or functionName([...])
var jsonpPattern = regexp.MustCompile(`^\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\([\s\S]+\)\s*;?\s*$`)

// injectedPattern matches our injected callback wrapper.
var injectedPattern = regexp.MustCompile(`^\s*` + probeCallback + `\s*\(`)

// sensitiveDataPatterns detect sensitive data in JSONP responses.
var sensitiveDataPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)"(email|e-mail)"\s*:`),
	regexp.MustCompile(`(?i)"(password|passwd|pass)"\s*:`),
	regexp.MustCompile(`(?i)"(token|access_token|api_key|apikey|secret)"\s*:`),
	regexp.MustCompile(`(?i)"(ssn|social_security|credit_card|card_number)"\s*:`),
	regexp.MustCompile(`(?i)"(phone|mobile|telephone)"\s*:`),
}

// Module implements the JSONP Callback Injection active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new JSONP Callback Injection module.
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
		ds: dedup.LazyDiskSet("jsonp_callback"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest checks for JSONP callback injection.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Only test JSON-like responses
	if !isJSONLikeResponse(ctx) {
		return nil, nil
	}

	// Dedup by host:path
	dedupKey := utils.Sha1(fmt.Sprintf("%s:%s", urlx.Host, urlx.Path))
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(dedupKey) {
		return nil, nil
	}

	// Skip if URL already has a callback parameter
	lowerQuery := strings.ToLower(urlx.RawQuery)
	for _, name := range callbackParamNames {
		if strings.Contains(lowerQuery, name+"=") {
			return nil, nil
		}
	}

	// Phase 1: Passive — check if response already has JSONP wrapping
	if ctx.HasResponse() {
		body := strings.TrimSpace(ctx.Response().BodyToString())
		if jsonpPattern.MatchString(body) {
			sev := severity.Medium
			if containsSensitiveData(body) {
				sev = severity.High
			}
			return []*output.ResultEvent{
				{
					URL:              urlx.String(),
					Matched:          urlx.String(),
					Request:          string(ctx.Request().Raw()),
					ExtractedResults: []string{"Existing JSONP response detected"},
					Info: output.Info{
						Name:        "JSONP Endpoint Detected",
						Description: "Response is already wrapped in a JSONP callback function, enabling cross-origin data theft",
						Severity:    sev,
						Confidence:  severity.Certain,
						Tags:        []string{"jsonp", "cross-origin", "data-theft"},
						Reference:   []string{"https://owasp.org/www-community/attacks/Cross_Site_Script_Inclusion"},
					},
				},
			}, nil
		}
	}

	// Phase 2: Active — inject callback parameter
	for _, paramName := range callbackParamNames {
		suffix := paramName + "=" + probeCallback
		modifiedRaw := utils.AppendToQuery(ctx.Request().Raw(), suffix)

		fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
			continue
		}

		body := strings.TrimSpace(resp.Body().String())
		resp.Close()

		if injectedPattern.MatchString(body) {
			sev := severity.Medium
			if containsSensitiveData(body) {
				sev = severity.High
			}

			return []*output.ResultEvent{
				{
					URL:              urlx.String(),
					Matched:          urlx.String(),
					Request:          string(modifiedRaw),
					FuzzingParameter: paramName,
					ExtractedResults: []string{fmt.Sprintf("Callback param: %s", paramName)},
					Info: output.Info{
						Name:        "JSONP Callback Injection",
						Description: fmt.Sprintf("JSONP callback injection via parameter %q — response is wrapped in the injected function call, enabling cross-origin data theft", paramName),
						Severity:    sev,
						Confidence:  severity.Firm,
						Tags:        []string{"jsonp", "callback-injection", "cross-origin"},
						Reference:   []string{"https://owasp.org/www-community/attacks/Cross_Site_Script_Inclusion"},
					},
				},
			}, nil
		}
	}

	return nil, nil
}

// isJSONLikeResponse checks if the response looks like it could be JSON/JSONP.
func isJSONLikeResponse(ctx *httpmsg.HttpRequestResponse) bool {
	if !ctx.HasResponse() {
		return false
	}
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if strings.Contains(ct, "json") || strings.Contains(ct, "javascript") {
		return true
	}
	// Check body prefix
	body := strings.TrimSpace(ctx.Response().BodyToString())
	if len(body) > 0 {
		first := body[0]
		if first == '{' || first == '[' {
			return true
		}
		// Check for existing JSONP pattern (function call wrapping)
		if len(body) > 2 && body[len(body)-1] == ')' || (len(body) > 2 && body[len(body)-1] == ';' && body[len(body)-2] == ')') {
			return true
		}
	}
	return false
}

// containsSensitiveData checks if the response body contains sensitive data patterns.
func containsSensitiveData(body string) bool {
	for _, pattern := range sensitiveDataPatterns {
		if pattern.MatchString(body) {
			return true
		}
	}
	return false
}
