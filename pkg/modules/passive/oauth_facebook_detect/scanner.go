package oauth_facebook_detect

import (
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

type Module struct {
	modkit.BasePassiveModule
	redirectRegex *regexp.Regexp
}

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
		// DO NOT USE *dedup.RequestHashManager to check hash in this module
		redirectRegex: regexp.MustCompile(`(?i)^(?:redirect_uri|next)$`),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes Facebook OAuth requests for redirect parameters.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, _ *modkit.ScanContext) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return results, nil
	}
	if strings.ToLower(urlx.Hostname()) != "www.facebook.com" {
		return results, nil
	}
	urlx.Params.Iterate(func(key string, value []string) bool {
		if m.redirectRegex.MatchString(key) {
			results = append(results, &output.ResultEvent{
				Host:             urlx.Host,
				URL:              urlx.String(),
				FuzzingParameter: key,
				Request:          string(ctx.Request().Raw()),
			})
		}
		return true
	})
	return results, nil
}
