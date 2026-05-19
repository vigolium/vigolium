package sensitive_url_params

import (
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// sensitiveParamPattern matches parameter names that suggest sensitive data.
var sensitiveParamPattern = regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|session[_-]?id|private[_-]?key|credit[_-]?card|ssn|cvv|pin)`)

// Module implements the Sensitive URL Params passive scanner.
type Module struct {
	modkit.BasePassiveModule
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new Sensitive URL Params module.
func New() *Module {
	m := &Module{
		BasePassiveModule: modkit.NewBasePassiveModule(
			ModuleID,
			ModuleName,
			ModuleDesc,
			ModuleShort,
			ModuleConfirmation,
			ModuleSeverity,
			ModuleConfidence,
			modkit.ScanScopeRequest,
			modkit.PassiveScanScopeRequest,
		),
		rhm: dedup.LazyDefaultRHM("passive_sensitive_url_params"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes URL query parameters for sensitive data.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	var results []*output.ResultEvent

	rhm := m.rhm.Get(scanCtx.DedupMgr())

	urlx.Params.Iterate(func(key string, value []string) bool {
		if sensitiveParamPattern.MatchString(key) {
			if rhm == nil || rhm.ShouldCheck3(urlx, ctx.Request().Method(), ctx.Request().BodyToString(), key, "", "inURL") {
				// Mask the value for reporting
				maskedValue := maskValue(strings.Join(value, ","))
				results = append(results, &output.ResultEvent{
					Host:             urlx.Host,
					URL:              urlx.String(),
					FuzzingParameter: key,
					Request:          string(ctx.Request().Raw()),
					ExtractedResults: []string{key + "=" + maskedValue},
					Info: output.Info{
						Description: "Sensitive parameter in URL: " + key,
					},
				})
			}
		}
		return true
	})

	return results, nil
}

// maskValue masks sensitive values for safe reporting.
func maskValue(v string) string {
	if len(v) <= 4 {
		return "****"
	}
	return v[:2] + "****" + v[len(v)-2:]
}
