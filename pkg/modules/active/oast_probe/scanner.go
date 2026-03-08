package oast_probe

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
	"github.com/pkg/errors"
)

// Headers to inject OAST URLs into for blind detection.
var oastHeaders = []string{
	"Referer",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"Origin",
	"X-Original-URL",
	"Authorization",
}

// Module implements the OAST probe active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds  dedup.Lazy[dedup.DiskSet]
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new OAST Probe module.
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
			modkit.URLParamTypes,
		),
		ds:  dedup.LazyDiskSet("oast_probe"),
		rhm: dedup.LazyDefaultRHM("oast_probe"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// CanProcess returns true only when the OAST provider is available.
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	// Let base checks run first (nil check, media filter, method filter)
	if !m.BaseActiveModule.CanProcess(ctx) {
		return false
	}
	return true
}

// ScanPerRequest injects OAST callback URLs into HTTP headers.
// Findings arrive asynchronously via the OAST polling callback.
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

	// Dedup by host+path to avoid repeated header injections for same endpoint
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	requestHash := ctx.Request().ID()

	for _, header := range oastHeaders {
		oastURL := oast.GenerateURL(urlx.String(), header, "header", ModuleID, requestHash)
		if oastURL == "" {
			continue
		}

		// Wrap in http:// for headers that expect URLs
		payload := "http://" + oastURL

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

	// Results arrive asynchronously via OAST polling callbacks
	return nil, nil
}

// ScanPerInsertionPoint injects OAST URLs into parameters that look like they accept URLs.
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

	// Dedup by request hash + param
	rhm := m.rhm.Get(scanCtx.DedupMgr())
	if rhm != nil {
		paramName := ip.Name()
		paramType := fmt.Sprintf("%d", ip.Type())
		if !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), paramName, ip.BaseValue(), paramType) {
			return nil, nil
		}
	}

	// Only test parameters that look like they might accept URLs
	if !looksLikeURLParam(ip.Name(), ip.BaseValue()) {
		return nil, nil
	}

	requestHash := ctx.Request().ID()
	oastURL := oast.GenerateURL(urlx.String(), ip.Name(), "parameter", ModuleID, requestHash)
	if oastURL == "" {
		return nil, nil
	}

	payload := "http://" + oastURL
	fuzzedRaw := ip.BuildRequest([]byte(payload))

	fuzzedReq, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
	if err != nil {
		return nil, nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil, nil
		}
		return nil, nil
	}
	resp.Close()

	// Results arrive asynchronously via OAST polling callbacks
	return nil, nil
}

// looksLikeURLParam checks if a parameter name or value suggests URL input.
func looksLikeURLParam(name, value string) bool {
	nameLower := strings.ToLower(name)
	urlParamNames := []string{
		"url", "uri", "link", "src", "href", "dest", "redirect",
		"path", "file", "page", "target", "callback", "endpoint",
		"resource", "fetch", "load", "proxy", "request",
	}
	for _, n := range urlParamNames {
		if strings.Contains(nameLower, n) {
			return true
		}
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") || strings.HasPrefix(value, "//") {
		return true
	}
	return false
}
