package web_cache_poisoning

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/utils"
)

const poisonMarker = "vigolium-cache-test.example.com"

// cacheProbe defines a web cache poisoning test case.
type cacheProbe struct {
	headerName string
	value      string
	desc       string
}

var probes = []cacheProbe{
	{
		headerName: "X-Forwarded-Host",
		value:      poisonMarker,
		desc:       "X-Forwarded-Host reflection in cached response",
	},
	{
		headerName: "X-Forwarded-Scheme",
		value:      "nothttps",
		desc:       "X-Forwarded-Scheme manipulation causing redirect to attacker-controlled scheme",
	},
	{
		headerName: "X-Original-URL",
		value:      "/vigolium-cache-test-path",
		desc:       "X-Original-URL override affecting cached content",
	},
	{
		headerName: "X-Rewrite-URL",
		value:      "/vigolium-cache-test-path",
		desc:       "X-Rewrite-URL override affecting cached content",
	},
	{
		headerName: "X-Forwarded-Port",
		value:      "1337",
		desc:       "X-Forwarded-Port injection reflected in response URLs",
	},
	{
		headerName: "Accept-Language",
		value:      "vigolium-cache-test-lang",
		desc:       "Accept-Language header reflected in cached response",
	},
}

// Module implements the Web Cache Poisoning active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Web Cache Poisoning module.
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
		ds: dedup.LazyDiskSet("web_cache_poisoning"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest tests the request for web cache poisoning via unkeyed headers.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	var results []*output.ResultEvent

	for _, probe := range probes {
		modifiedRaw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), probe.headerName, probe.value)
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
			continue
		}

		body := resp.Body().String()
		reflected := strings.Contains(body, probe.value)

		// Also check Location header for redirect-based poisoning
		if !reflected && resp.Response() != nil {
			location := resp.Response().Header.Get("Location")
			if strings.Contains(location, probe.value) {
				reflected = true
			}
		}

		// Check for cache indicators
		isCached := false
		if resp.Response() != nil {
			cacheControl := resp.Response().Header.Get("Cache-Control")
			age := resp.Response().Header.Get("Age")
			xCache := resp.Response().Header.Get("X-Cache")
			if age != "" || strings.Contains(xCache, "HIT") ||
				(!strings.Contains(cacheControl, "no-store") && !strings.Contains(cacheControl, "private")) {
				isCached = true
			}
		}

		if reflected {
			extracted := []string{
				fmt.Sprintf("Header: %s: %s", probe.headerName, probe.value),
			}
			if isCached {
				extracted = append(extracted, "Response appears cacheable")
			}

			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Request:          string(modifiedRaw),
				Response:         resp.FullResponseString(),
				ExtractedResults: extracted,
				Info: output.Info{
					Name:        fmt.Sprintf("Web Cache Poisoning: %s", probe.headerName),
					Description: probe.desc,
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}
