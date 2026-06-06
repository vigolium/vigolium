package oast_probe

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

// shapeKind selects how an OAST host is rendered into a header value. Different
// headers expect different forms: a URL, a bare host (IP-style routing headers
// that trigger a DNS lookup), a UAProf XML URL, or an RFC 7239 "for=" token.
type shapeKind int

const (
	shapeURL       shapeKind = iota // http://<host>
	shapeBare                       // <host>           (DNS-pingback routing headers)
	shapeWAP                        // http://<host>/wap.xml
	shapeForwarded                  // for=<host>       (RFC 7239 Forwarded)
)

func (k shapeKind) render(host string) string {
	switch k {
	case shapeBare:
		return host
	case shapeWAP:
		return "http://" + host + "/wap.xml"
	case shapeForwarded:
		return "for=" + host
	default:
		return "http://" + host
	}
}

// oastHeader is a header to inject an OAST callback into, plus how to shape it.
type oastHeader struct {
	name string
	kind shapeKind
}

// oastHeaders is the "Collaborator Everywhere" header fan-out (PortSwigger,
// "Cracking the lens"): routing, analytics, and proxy headers that backends behind
// a reverse proxy commonly fetch or resolve. The first six are the original set
// (URL-shaped, unchanged); the rest add the True-Client-IP / X-WAP-Profile /
// Forwarded family that the research found especially productive.
var oastHeaders = []oastHeader{
	{"Referer", shapeURL},
	{"X-Forwarded-For", shapeURL},
	{"X-Forwarded-Host", shapeURL},
	{"Origin", shapeURL},
	{"X-Original-URL", shapeURL},
	{"Authorization", shapeURL},
	// Collaborator-Everywhere additions:
	{"True-Client-IP", shapeBare},
	{"CF-Connecting-IP", shapeBare},
	{"X-Client-IP", shapeBare},
	{"X-ProxyUser-Ip", shapeBare},
	{"Forwarded", shapeForwarded},
	{"X-WAP-Profile", shapeWAP},
	{"Profile", shapeWAP},
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

	// Cache-Control: no-transform discourages intermediaries from mangling the
	// injected payload before it reaches the backend (the "Cracking the lens"
	// trick). It is identical for every probe, so build the base once instead of
	// re-inserting (and re-parsing the raw) on each header iteration.
	base, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), "Cache-Control", "no-transform")
	if err != nil {
		return nil, nil
	}

	for _, header := range oastHeaders {
		oastURL := oast.GenerateURL(urlx.String(), header.name, "header", ModuleID, requestHash)
		if oastURL == "" {
			continue
		}

		// Shape the OAST host for this header (URL / bare host / wap.xml / for=).
		payload := header.kind.render(oastURL)

		modifiedRaw, err := httpmsg.AddOrReplaceHeader(base, header.name, payload)
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
