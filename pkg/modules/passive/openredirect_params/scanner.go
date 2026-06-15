package openredirect_params

import (
	"context"
	"regexp"
	"strings"

	"go.uber.org/zap"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

type Module struct {
	modkit.BasePassiveModule
	redirectRegex *regexp.Regexp
	rhm           dedup.Lazy[dedup.RequestHashManager]
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
		redirectRegex: regexp.MustCompile(`(?i)(?:redirect|callback|cb|url|uri|link|location)`),
		rhm:           dedup.LazyDefaultRHM("passive_openredirect_params"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes request parameters for potential open redirect vectors.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return results, nil
	}
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	urlx.Params.Iterate(func(key string, value []string) bool {
		if m.redirectRegex.MatchString(key) {
			// Skip empty / JS-placeholder values ("redirect=null", "url="): there is
			// no redirect target to abuse, so the bare parameter name is noise.
			if modkit.IsPlaceholderValue(strings.Join(value, ",")) {
				return true
			}
			if rhm == nil || rhm.ShouldCheck3(urlx, ctx.Request().Method(), ctx.Request().BodyToString(), key, "", "inURL") {
				results = append(results, &output.ResultEvent{
					Host:             urlx.Host,
					URL:              urlx.String(),
					FuzzingParameter: key,
					Request:          string(ctx.Request().Raw()),
				})
			}
		}
		return true
	})

	// Annotate record with semantic tag if redirect params found
	if len(results) > 0 && scanCtx != nil && scanCtx.RemarksAnnotator != nil && scanCtx.RequestUUIDResolver != nil {
		uuid := scanCtx.RequestUUIDResolver.ResolveRequestUUID(ctx.Request().ID())
		if uuid != "" {
			if err := scanCtx.RemarksAnnotator.AppendRemarks(context.Background(), map[string][]string{uuid: {"redirect-candidate"}}); err != nil {
				zap.L().Debug("openredirect_params: failed to annotate", zap.Error(err))
			}
		}
	}

	return results, nil
}
