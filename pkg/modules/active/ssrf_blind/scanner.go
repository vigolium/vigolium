package ssrf_blind

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

// blindSSRFPayload defines a payload template for blind SSRF testing.
// The %s placeholder is replaced with the OAST hostname.
type blindSSRFPayload struct {
	name string
	tmpl string // %s = OAST hostname
}

var payloads = []blindSSRFPayload{
	{name: "direct-http", tmpl: "http://%s"},
	{name: "direct-https", tmpl: "https://%s"},
	{name: "with-path", tmpl: "http://%s/test"},
	{name: "with-port", tmpl: "http://%s:80"},
	{name: "url-encoded", tmpl: "http://%%25%%36%%31%%25%%36%%65%%25%%37%%34%%25%%36%%38%%25%%37%%32%%25%%36%%46%%25%%37%%30%%25%%36%%39%%25%%36%%33.%s"},
}

// Module implements the blind SSRF active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds  dedup.Lazy[dedup.DiskSet]
	rhm dedup.Lazy[dedup.RequestHashManager]
}

// New creates a new blind SSRF module.
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
			modkit.ScanScopeInsertionPoint,
			modkit.AllParamTypes,
		),
		ds:  dedup.LazyDiskSet("ssrf_blind"),
		rhm: dedup.LazyDefaultRHM("ssrf_blind"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerInsertionPoint injects OAST URLs into URL-like parameters for blind SSRF detection.
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

	// Dedup by host+path+param via DiskSet
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s%s", urlx.Host, urlx.Path, ip.Name()))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	// Only test parameters that look like they might accept URLs
	if !looksLikeURLParam(ip.Name(), ip.BaseValue()) {
		return nil, nil
	}

	requestHash := ctx.Request().ID()

	for _, p := range payloads {
		oastURL := oast.GenerateURL(urlx.String(), ip.Name(), "parameter", ModuleID, requestHash)
		if oastURL == "" {
			continue
		}

		payload := fmt.Sprintf(p.tmpl, oastURL)
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
