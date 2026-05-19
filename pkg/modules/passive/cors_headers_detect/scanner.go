package cors_headers_detect

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// Module implements the CORS Headers Detect passive scanner.
type Module struct {
	modkit.BasePassiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new CORS Headers Detect module.
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
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("passive_cors_headers_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes response for permissive CORS headers.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	if ctx.Response() == nil {
		return nil, nil
	}

	acao := ctx.Response().Header("Access-Control-Allow-Origin")
	if acao == "" {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s%s", urlx.Host, urlx.Path, acao))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	acac := ctx.Response().Header("Access-Control-Allow-Credentials")

	var issues []string

	// Wildcard origin
	if acao == "*" {
		issues = append(issues, "Wildcard (*) Access-Control-Allow-Origin")
	}

	// Wildcard with credentials
	if acao == "*" && strings.EqualFold(acac, "true") {
		issues = append(issues, "Wildcard origin with Access-Control-Allow-Credentials: true")
	}

	// Null origin
	if strings.EqualFold(acao, "null") {
		issues = append(issues, "Null origin accepted in Access-Control-Allow-Origin")
	}

	// Credentials enabled (even without wildcard, worth noting)
	if strings.EqualFold(acac, "true") && acao != "*" {
		issues = append(issues, fmt.Sprintf("Credentials enabled for origin: %s", acao))
	}

	if len(issues) == 0 {
		return nil, nil
	}

	// Annotate record with semantic tags
	if scanCtx != nil && scanCtx.RemarksAnnotator != nil && scanCtx.RequestUUIDResolver != nil {
		uuid := scanCtx.RequestUUIDResolver.ResolveRequestUUID(ctx.Request().ID())
		if uuid != "" {
			tags := []string{"has-cors"}
			if acao == "*" {
				tags = append(tags, "cors-wildcard")
			}
			if err := scanCtx.RemarksAnnotator.AppendRemarks(context.Background(), map[string][]string{uuid: tags}); err != nil {
				zap.L().Debug("cors_headers_detect: failed to annotate", zap.Error(err))
			}
		}
	}

	return []*output.ResultEvent{
		{
			Host:    urlx.Host,
			URL:     urlx.String(),
			Request: string(ctx.Request().Raw()),
			ExtractedResults: append([]string{
				fmt.Sprintf("ACAO: %s", acao),
				fmt.Sprintf("ACAC: %s", acac),
			}, issues...),
			Info: output.Info{
				Description: strings.Join(issues, "; "),
			},
		},
	}, nil
}
