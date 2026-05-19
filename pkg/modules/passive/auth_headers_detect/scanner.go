package auth_headers_detect

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
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
		ds: dedup.LazyDiskSet("passive_auth_headers_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes request headers for authorization tokens.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return results, nil
	}

	authValue := ctx.Request().Header("Authorization")
	if authValue == "" {
		return results, nil
	}
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := m.getHash(urlx, "Authorization", authValue)
	if diskSet != nil && diskSet.IsSeen(hash) {
		return results, nil
	}
	results = append(results, &output.ResultEvent{
		Host:             urlx.Host,
		URL:              urlx.String(),
		FuzzingParameter: "Authorization",
		Request:          string(ctx.Request().Raw()),
		ExtractedResults: []string{authValue},
	})

	// Annotate record with semantic tags
	if scanCtx.RemarksAnnotator != nil && scanCtx.RequestUUIDResolver != nil {
		uuid := scanCtx.RequestUUIDResolver.ResolveRequestUUID(ctx.Request().ID())
		if uuid != "" {
			tags := []string{"auth-endpoint"}
			lower := strings.ToLower(authValue)
			if strings.HasPrefix(lower, "bearer ") {
				tags = append(tags, "bearer-auth")
			} else if strings.HasPrefix(lower, "basic ") {
				tags = append(tags, "basic-auth")
			}
			if err := scanCtx.RemarksAnnotator.AppendRemarks(context.Background(), map[string][]string{uuid: tags}); err != nil {
				zap.L().Debug("auth_headers_detect: failed to annotate", zap.Error(err))
			}
		}
	}

	return results, nil
}

func (m *Module) getHash(urlx *urlutil.URL, name, value string) string {
	return utils.Sha1(fmt.Sprintf("%s%s%s", urlx.Host, name, value))
}
