package web_cache_poisoning

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
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

// ConfirmsByBodyDifferential opts this module into the executor's body-
// differential safety net: a candidate finding is re-confirmed by replaying the
// unkeyed-header request and verifying it reproducibly introduces content absent
// from the clean baseline before being reported.
func (m *Module) ConfirmsByBodyDifferential() bool { return true }

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

		respObj := resp.Response()
		if respObj == nil {
			resp.Close()
			continue
		}

		body := resp.Body().String()
		reflectedInBody := strings.Contains(body, probe.value)
		reflectedInLocation := strings.Contains(respObj.Header.Get("Location"), probe.value)

		if !reflectedInBody && !reflectedInLocation {
			resp.Close()
			continue
		}

		// A reflected unkeyed-header value is only a poisoning risk if the response
		// is one a shared cache would actually store and replay to other users.
		// Without this gate the module fired on uncacheable responses — most
		// notably 302 login redirects that echo X-Forwarded-Host into a `continue`
		// return URL (normal SSO behavior, never cached by a shared cache).
		cacheable, evidence := genuinelyCacheable(respObj.Header.Get, respObj.StatusCode, probe.headerName)
		if !cacheable {
			resp.Close()
			continue
		}

		where := "response body"
		if !reflectedInBody {
			where = "Location header"
		}

		results = append(results, &output.ResultEvent{
			URL:      urlx.String(),
			Request:  string(modifiedRaw),
			Response: resp.FullResponseString(),
			ExtractedResults: []string{
				fmt.Sprintf("Header: %s: %s", probe.headerName, probe.value),
				"Reflected in " + where,
				"Cacheable: " + evidence,
			},
			Info: output.Info{
				Name:        fmt.Sprintf("Web Cache Poisoning: %s", probe.headerName),
				Description: probe.desc,
			},
		})
		resp.Close()
		return results, nil
	}

	return results, nil
}

// genuinelyCacheable reports whether a response is one a shared cache would
// actually store — and therefore could be poisoned — along with a short evidence
// string. It replaces the original heuristic, which marked any response lacking
// Cache-Control: no-store/private as cacheable and so fired on directive-less
// 302 redirects (the root of the X-Forwarded-Host-in-Location false positive). A
// reflected header value only matters when the response carrying it is stored
// and replayed to other users.
func genuinelyCacheable(get func(string) string, status int, injectedHeader string) (bool, string) {
	if get == nil {
		return false, ""
	}

	// Per-user (Set-Cookie) or explicitly-uncacheable responses are never stored
	// by a well-behaved shared cache.
	if get("Set-Cookie") != "" {
		return false, ""
	}
	cc := strings.ToLower(get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "no-cache") || strings.Contains(cc, "private") {
		return false, ""
	}

	// Vary: * is uncacheable; a Vary that already keys on the injected header
	// means the cache is keyed by it — so the header is not "unkeyed" and the
	// response cannot be poisoned through it.
	vary := strings.ToLower(get("Vary"))
	if strings.Contains(vary, "*") {
		return false, ""
	}
	if injectedHeader != "" && strings.Contains(vary, strings.ToLower(injectedHeader)) {
		return false, ""
	}

	// Strongest signal: the edge already served this from its cache.
	if c := infra.CacheState(get); c.Hit {
		return true, c.Evidence
	}

	// Otherwise require an explicit directive that authorizes shared caching; the
	// mere absence of no-store is not enough.
	positive := strings.Contains(cc, "public") || strings.Contains(cc, "s-maxage") || hasPositiveMaxAge(cc)

	// 3xx redirects are the common false-positive surface: 302/307 are not
	// heuristically cacheable, and 301/308 routinely reflect Host/forwarded
	// headers into a continue/return URL. Trust a cached redirect only when an
	// explicit directive marks it cacheable.
	if status >= 300 && status < 400 {
		if positive {
			return true, "redirect cacheable via Cache-Control: " + get("Cache-Control")
		}
		return false, ""
	}

	if positive {
		return true, "Cache-Control: " + get("Cache-Control")
	}
	return false, ""
}

// hasPositiveMaxAge reports whether a lowercased Cache-Control value carries
// max-age=N with N > 0. A max-age of 0 means "must revalidate" and is not a
// storable directive for our purposes. (s-maxage is checked separately by the
// caller; "max-age=" is not a substring of "s-maxage=".)
func hasPositiveMaxAge(cc string) bool {
	idx := strings.Index(cc, "max-age=")
	if idx < 0 {
		return false
	}
	rest := cc[idx+len("max-age="):]
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return false
	}
	n, err := strconv.Atoi(rest[:end])
	return err == nil && n > 0
}
