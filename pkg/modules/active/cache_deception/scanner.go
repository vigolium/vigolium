package cache_deception

import (
	"fmt"
	"math"
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

// pathConfusionTechnique defines a URL path mutation to test for cache deception.
type pathConfusionTechnique struct {
	suffix string
	desc   string
}

var techniques = []pathConfusionTechnique{
	// Static extension appending
	{".css", "Static extension append (.css)"},
	{".js", "Static extension append (.js)"},
	{".png", "Static extension append (.png)"},
	{".svg", "Static extension append (.svg)"},
	// Path separator confusion
	{"/..%2f..%2fstatic.css", "Path separator confusion (double dot-segment encoded)"},
	{"%2f.css", "Path separator confusion (encoded slash + extension)"},
	// Trailing path segment
	{"/nonexistent.css", "Dot segment trailing path confusion"},
}

// Module implements the Web Cache Deception active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Web Cache Deception module.
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
		ds: dedup.LazyDiskSet("cache_deception"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest tests the request for web cache deception via path confusion.
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

	// Dedup by host+path
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	// Get baseline response to compare against
	baseline, err := scanCtx.GetOrFetchBaseline(ctx, httpClient)
	if err != nil {
		if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
			return nil, nil
		}
		return nil, nil
	}

	// Skip if baseline response is too short — we need authenticated content
	if baseline.BodyLen < 200 {
		return nil, nil
	}

	// Skip redirect responses — not useful for cache deception
	if baseline.StatusCode >= 300 && baseline.StatusCode < 400 {
		return nil, nil
	}

	// Skip when the host returns the same body for any nonexistent path.
	// In that case the baseline is just an SPA / wildcard shell, not
	// authenticated content, and caching it isn't a vulnerability.
	wildcard, _ := scanCtx.WildcardProbe(ctx, httpClient)
	if wildcard.MatchesBody(baseline.StatusCode, baseline.Response.Body()) {
		return nil, nil
	}

	originalPath, err := httpmsg.GetPath(ctx.Request().Raw())
	if err != nil {
		return nil, nil
	}

	var results []*output.ResultEvent

	for _, tech := range techniques {
		confusedPath := originalPath + tech.suffix

		modifiedRaw, err := httpmsg.SetPath(ctx.Request().Raw(), confusedPath)
		if err != nil {
			continue
		}

		fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		// First request — potentially caches the response
		resp1, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}
		resp1.Close()

		// Second request — check if it was served from cache
		resp2, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		if resp2.Response() == nil {
			resp2.Close()
			continue
		}

		// Check if the response matches the original authenticated content
		resp2Body := resp2.Body().String()
		resp2StatusCode := resp2.Response().StatusCode
		resp2BodyLen := len(resp2Body)

		bodyMatch := resp2StatusCode == baseline.StatusCode &&
			resp2BodyLen > 0 &&
			math.Abs(float64(resp2BodyLen-baseline.BodyLen))/float64(baseline.BodyLen) <= 0.10

		// Check for cache indicators
		cacheHit := false
		var cacheEvidence string

		xCache := resp2.Response().Header.Get("X-Cache")
		if strings.Contains(strings.ToUpper(xCache), "HIT") {
			cacheHit = true
			cacheEvidence = fmt.Sprintf("X-Cache: %s", xCache)
		}

		cfCache := resp2.Response().Header.Get("CF-Cache-Status")
		if strings.Contains(strings.ToUpper(cfCache), "HIT") {
			cacheHit = true
			cacheEvidence = fmt.Sprintf("CF-Cache-Status: %s", cfCache)
		}

		age := resp2.Response().Header.Get("Age")
		if age != "" && age != "0" {
			cacheHit = true
			cacheEvidence = fmt.Sprintf("Age: %s", age)
		}

		xCacheStatus := resp2.Response().Header.Get("X-Cache-Status")
		if strings.Contains(strings.ToUpper(xCacheStatus), "HIT") {
			cacheHit = true
			cacheEvidence = fmt.Sprintf("X-Cache-Status: %s", xCacheStatus)
		}

		// Report if BOTH conditions met: response matches original AND cache indicators present
		if bodyMatch && cacheHit {
			results = append(results, &output.ResultEvent{
				URL:      urlx.String(),
				Matched:  urlx.String(),
				Request:  string(modifiedRaw),
				Response: resp2.FullResponse().String(),
				ExtractedResults: []string{
					fmt.Sprintf("Technique: %s", tech.desc),
					fmt.Sprintf("Confused path: %s", confusedPath),
					fmt.Sprintf("Cache evidence: %s", cacheEvidence),
					fmt.Sprintf("Body length match: original=%d confused=%d", baseline.BodyLen, resp2BodyLen),
				},
				Info: output.Info{
					Name:        fmt.Sprintf("Web Cache Deception: %s", tech.desc),
					Description: fmt.Sprintf("The URL %s is vulnerable to web cache deception. Appending '%s' to the path causes the authenticated response to be cached, as indicated by %s.", urlx.String(), tech.suffix, cacheEvidence),
				},
			})
			resp2.Close()
			return results, nil
		}
		resp2.Close()
	}

	return results, nil
}
