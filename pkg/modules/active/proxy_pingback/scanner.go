package proxy_pingback

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

// Category 1: sub_path + oob_part combinations (5 × 3 = 15 probes).
var subPaths = []string{"/proxy", "/", "/internal_proxy", "/myproxy", "/common_proxy"}
var oobParts = []string{"/http/%s", "///%s", "/http://%s"}

// Category 2+3: proxy path segments (11 each = 22 probes).
var proxyPaths = []string{
	"httpproxy", "httpsproxy", "proxy", "http", "https",
	"callback", "get", "file", "callbacks", "url", "remote",
}

// Category 4: vendor-specific tileproxy paths (2 probes).
var tileproxyPaths = []string{
	"/handlers/bp.ext.file.tileproxy?url=http://%s/",
	"/bp.ext.file.tileproxy?url=http://%s/",
}

// Category 5: query parameter probes (15 probes).
// Each entry is {paramName, valueFormat} where %s is replaced with the OAST URL.
var paramProbes = []struct {
	name        string
	valueFormat string
}{
	{"u", "http://%s/"},
	{"href", "http://%s/"},
	{"action", "http://%s/"},
	{"host", "%s"},
	{"http_host", "%s"},
	{"email", "root@%s"},
	{"url", "http://%s/"},
	{"load", "http://%s/"},
	{"preview", "http://%s/"},
	{"target", "http://%s/"},
	{"proxy", "http://%s/"},
	{"from", "http://%s/"},
	{"src", "http://%s/"},
	{"ref", "http://%s/"},
	{"referrer", "http://%s/"},
}

// Module implements the proxy pingback active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Proxy Pingback module.
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
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("proxy_pingback"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest probes proxy-related paths with OAST callback URLs.
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

	// Dedup by host — each host is tested only once
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(urlx.Host)
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	requestHash := ctx.Request().ID()

	// Category 1: sub_path + oob_part clusterbomb (5 × 3 = 15 probes)
	for _, sub := range subPaths {
		for _, oob := range oobParts {
			oastURL := oast.GenerateURL(urlx.String(), sub, "path", ModuleID, requestHash)
			if oastURL == "" {
				continue
			}
			newPath := sub + fmt.Sprintf(oob, oastURL)
			if err := m.sendProbe(ctx, httpClient, newPath); err != nil {
				return nil, nil
			}
		}
	}

	// Category 2: /{proxy_path}/http://{oast} (11 probes)
	for _, pp := range proxyPaths {
		oastURL := oast.GenerateURL(urlx.String(), pp, "path", ModuleID, requestHash)
		if oastURL == "" {
			continue
		}
		newPath := fmt.Sprintf("/%s/http://%s", pp, oastURL)
		if err := m.sendProbe(ctx, httpClient, newPath); err != nil {
			return nil, nil
		}
	}

	// Category 3: /{proxy_path}/{oast} (11 probes)
	for _, pp := range proxyPaths {
		oastURL := oast.GenerateURL(urlx.String(), pp, "path", ModuleID, requestHash)
		if oastURL == "" {
			continue
		}
		newPath := fmt.Sprintf("/%s/%s", pp, oastURL)
		if err := m.sendProbe(ctx, httpClient, newPath); err != nil {
			return nil, nil
		}
	}

	// Category 4: vendor-specific tileproxy (2 probes)
	for _, tp := range tileproxyPaths {
		oastURL := oast.GenerateURL(urlx.String(), "tileproxy", "path", ModuleID, requestHash)
		if oastURL == "" {
			continue
		}
		newPath := fmt.Sprintf(tp, oastURL)
		if err := m.sendProbe(ctx, httpClient, newPath); err != nil {
			return nil, nil
		}
	}

	// Category 5: query parameter pingback (15 probes)
	for _, pp := range paramProbes {
		oastURL := oast.GenerateURL(urlx.String(), pp.name, "parameter", ModuleID, requestHash)
		if oastURL == "" {
			continue
		}
		value := fmt.Sprintf(pp.valueFormat, oastURL)
		if err := m.sendParamProbe(ctx, httpClient, pp.name, value); err != nil {
			return nil, nil
		}
	}

	// Category 6: Proxy-Authorization header with OAST URL
	oastURL := oast.GenerateURL(urlx.String(), "Proxy-Authorization", "header", ModuleID, requestHash)
	if oastURL != "" {
		if err := m.sendHeaderProbe(ctx, httpClient, "Proxy-Authorization", "Basic "+oastURL); err != nil {
			return nil, nil
		}
	}

	// Results arrive asynchronously via OAST polling callbacks
	return nil, nil
}

// sendProbe builds and sends a single GET request with the given path.
// Returns ErrUnresponsiveHost if the host is unresponsive; nil otherwise.
func (m *Module) sendProbe(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	newPath string,
) error {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, newPath)
	if err != nil {
		return nil
	}

	return m.executeProbe(ctx, httpClient, modifiedRaw)
}

// sendHeaderProbe adds a header to the original request and sends it.
func (m *Module) sendHeaderProbe(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	name, value string,
) error {
	modifiedRaw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), name, value)
	if err != nil {
		return nil
	}

	return m.executeProbe(ctx, httpClient, modifiedRaw)
}

// sendParamProbe appends a query parameter to the original request and sends it as GET.
// Returns ErrUnresponsiveHost if the host is unresponsive; nil otherwise.
func (m *Module) sendParamProbe(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	name, value string,
) error {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.AppendURLParameter(modifiedRaw, name, value)
	if err != nil {
		return nil
	}

	return m.executeProbe(ctx, httpClient, modifiedRaw)
}

// executeProbe parses and sends a modified raw request.
// Returns ErrUnresponsiveHost if the host is unresponsive; nil otherwise.
func (m *Module) executeProbe(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	modifiedRaw []byte,
) error {
	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return hosterrors.ErrUnresponsiveHost
		}
		return nil
	}
	resp.Close()
	return nil
}
