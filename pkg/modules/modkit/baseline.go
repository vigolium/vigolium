package modkit

import (
	"fmt"
	"time"

	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

const baselineTTL = 5 * time.Minute

// BaselineEntry caches a clean baseline response for a given endpoint.
type BaselineEntry struct {
	Response   *httpmsg.HttpResponse
	StatusCode int
	BodyLen    int
	FetchedAt  time.Time
}

// Expired returns true if the baseline entry is older than the TTL.
func (e *BaselineEntry) Expired() bool {
	return time.Since(e.FetchedAt) > baselineTTL
}

// GetOrFetchBaseline returns a cached baseline or fetches and caches one.
// Key: "METHOD:host/path" — different query params share the same baseline.
// Concurrent calls for the same key are coalesced via singleflight.
func (sc *ScanContext) GetOrFetchBaseline(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) (*BaselineEntry, error) {
	if sc == nil {
		return nil, fmt.Errorf("nil ScanContext")
	}

	key := ctx.Request().Method() + ":" + ctx.Service().Host() + ctx.Request().Path()

	cache := sc.getBaselineCache()
	if entry, ok := cache.Get(key); ok && !entry.Expired() {
		return entry, nil
	}

	// Use singleflight to coalesce concurrent fetches for the same endpoint.
	// This prevents duplicate HTTP requests when multiple modules request
	// the baseline for the same URL concurrently.
	result, err, _ := sc.baselineFlight.Do(key, func() (interface{}, error) {
		// Double-check cache inside singleflight (another goroutine may have populated it)
		if entry, ok := cache.Get(key); ok && !entry.Expired() {
			return entry, nil
		}

		respChain, _, err := httpClient.Execute(ctx, http.Options{})
		if err != nil {
			return nil, err
		}

		fullResp := respChain.FullResponseBytes()
		rawCopy := make([]byte, len(fullResp))
		copy(rawCopy, fullResp)
		respChain.Close()

		resp := httpmsg.NewHttpResponse(rawCopy)
		entry := &BaselineEntry{
			Response:   resp,
			StatusCode: resp.StatusCode(),
			BodyLen:    len(resp.Body()),
			FetchedAt:  time.Now(),
		}

		cache.Add(key, entry)
		return entry, nil
	})

	if err != nil {
		return nil, err
	}
	return result.(*BaselineEntry), nil
}
