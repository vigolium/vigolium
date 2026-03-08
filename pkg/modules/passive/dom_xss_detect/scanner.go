package dom_xss_detect

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
	urlutil "github.com/projectdiscovery/utils/url"
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
			modkit.PassiveScanScopeResponse,
		),
		ds: dedup.LazyDiskSet("passive_dom_xss_detect"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest analyzes response body for DOM XSS patterns.
func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return results, nil
	}

	if ctx.Response() == nil || ctx.Response().BodyToString() == "" {
		return results, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := m.getHash(urlx)
	if diskSet != nil && diskSet.IsSeen(hash) {
		return results, nil
	}

	body := ctx.Response().BodyToString()

	highlighted := analyse(body)
	if highlighted != "" {
		results = append(results, &output.ResultEvent{
			URL:     urlx.String(),
			Host:    urlx.Host,
			Request: string(ctx.Request().Raw()),
			Info: output.Info{
				Description: "Found DOM XSS vulnerabilities\n```" + highlighted + "```",
			},
		})
	}

	redirectInfo := analyseOpenRedirect(body)
	if redirectInfo != "" {
		results = append(results, &output.ResultEvent{
			URL:     urlx.String(),
			Host:    urlx.Host,
			Request: string(ctx.Request().Raw()),
			Info: output.Info{
				Description: "Found DOM-based Open Redirect patterns: " + redirectInfo,
			},
		})
	}

	return results, nil
}

func (m *Module) getHash(urlx *urlutil.URL) string {
	return utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
}
