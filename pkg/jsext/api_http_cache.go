package jsext

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/grafana/sobek"
	gohttp "github.com/vigolium/vigolium/pkg/http"
)

// httpCache stores cached HTTP responses.
type httpCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	ttl     time.Duration
	maxSize int
	enabled bool
}

type cacheEntry struct {
	raw       []byte
	elapsed   int64
	createdAt time.Time
}

func newHTTPCache() *httpCache {
	return &httpCache{
		entries: make(map[string]*cacheEntry),
		ttl:     5 * time.Minute,
		maxSize: 500,
	}
}

func (c *httpCache) get(key string) (*cacheEntry, bool) {
	if !c.enabled {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if time.Since(entry.createdAt) > c.ttl {
		return nil, false
	}
	return entry, true
}

func (c *httpCache) put(key string, entry *cacheEntry) {
	if !c.enabled {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict expired entries if at capacity
	if len(c.entries) >= c.maxSize {
		now := time.Now()
		for k, e := range c.entries {
			if now.Sub(e.createdAt) > c.ttl {
				delete(c.entries, k)
			}
		}
	}

	// If still at capacity, skip insertion
	if len(c.entries) >= c.maxSize {
		return
	}

	c.entries[key] = entry
}

func (c *httpCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*cacheEntry)
}

// cacheKey generates a hash key for a raw HTTP request.
func cacheKey(rawReq string) string {
	h := sha256.Sum256([]byte(rawReq))
	return hex.EncodeToString(h[:16])
}

// httpCacheFuncDefs returns JSFuncDefs for vigolium.http.cache, clearCache, cachedGet, cachedRequest.
func httpCacheFuncDefs() []JSFuncDef {
	cache := newHTTPCache() // shared across all cache functions

	return []JSFuncDef{
		{
			Namespace:   NsHTTP,
			Name:        "cache",
			Category:    CatHTTP,
			Signature:   ".cache(opts?: {ttl_ms?, max_entries?})",
			Returns:     "void",
			Description: "Enable HTTP response caching with optional TTL and size configuration.",
			Example:     "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					cache.enabled = true

					if optsVal := call.Argument(0); optsVal != nil && !sobek.IsUndefined(optsVal) && !sobek.IsNull(optsVal) {
						o := optsVal.ToObject(vm)
						if v := o.Get("ttl_ms"); v != nil && !sobek.IsUndefined(v) {
							ttlMs := v.ToInteger()
							if ttlMs > 0 && ttlMs <= 3600000 { // max 1 hour
								cache.ttl = time.Duration(ttlMs) * time.Millisecond
							}
						}
						if v := o.Get("max_entries"); v != nil && !sobek.IsUndefined(v) {
							maxEntries := int(v.ToInteger())
							if maxEntries > 0 && maxEntries <= 10000 {
								cache.maxSize = maxEntries
							}
						}
					}
					return sobek.Undefined()
				}
			},
		},
		{
			Namespace:   NsHTTP,
			Name:        "clearCache",
			Category:    CatHTTP,
			Signature:   ".clearCache()",
			Returns:     "void",
			Description: "Clear all cached HTTP responses.",
			Example:     "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					cache.clear()
					return sobek.Undefined()
				}
			},
		},
		{
			Namespace:   NsHTTP,
			Name:        "cachedGet",
			Category:    CatHTTP,
			Signature:   ".cachedGet(url: string, opts?: {headers})",
			Returns:     "HttpResponse",
			Description: "Send an HTTP GET request, returning a cached response if available.",
			Example:     "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					urlStr := call.Argument(0).String()

					rawReq := "GET " + urlStr + " HTTP/1.1\r\nHost: " + extractHost(urlStr) + "\r\n\r\n"
					key := cacheKey(rawReq)

					if entry, ok := cache.get(key); ok {
						return buildResponseObject(vm, entry.raw, entry.elapsed)
					}

					resp := doSimpleRequest(vm, opts.HTTPClient, "GET", urlStr, "", call.Argument(1))

					if cache.enabled && !sobek.IsUndefined(resp) && !sobek.IsNull(resp) {
						respObj := resp.ToObject(vm)
						if rawVal := respObj.Get("raw"); rawVal != nil && !sobek.IsUndefined(rawVal) {
							rawBytes := []byte(rawVal.String())
							elapsedMs := int64(0)
							if ev := respObj.Get("elapsed_ms"); ev != nil && !sobek.IsUndefined(ev) {
								elapsedMs = ev.ToInteger()
							}
							cache.put(key, &cacheEntry{
								raw:       rawBytes,
								elapsed:   elapsedMs,
								createdAt: time.Now(),
							})
						}
					}

					return resp
				}
			},
		},
		{
			Namespace:   NsHTTP,
			Name:        "cachedRequest",
			Category:    CatHTTP,
			Signature:   ".cachedRequest(opts: {method?, url, headers?, body?})",
			Returns:     "HttpResponse",
			Description: "Send an HTTP request with cache support (GET requests only are cached).",
			Example:     "",
			MakeHandler: func(vm *sobek.Runtime, opts APIOptions) func(sobek.FunctionCall) sobek.Value {
				return func(call sobek.FunctionCall) sobek.Value {
					optsVal := call.Argument(0)
					if sobek.IsUndefined(optsVal) || sobek.IsNull(optsVal) {
						return sobek.Undefined()
					}

					o := optsVal.ToObject(vm)
					method := "GET"
					if v := o.Get("method"); v != nil && !sobek.IsUndefined(v) {
						method = v.String()
					}

					if method != "GET" {
						return doRequestFromOpts(vm, opts.HTTPClient, o)
					}

					urlStr := ""
					if v := o.Get("url"); v != nil && !sobek.IsUndefined(v) {
						urlStr = v.String()
					}

					rawReq := "GET " + urlStr + " HTTP/1.1\r\nHost: " + extractHost(urlStr) + "\r\n\r\n"
					key := cacheKey(rawReq)

					if entry, ok := cache.get(key); ok {
						return buildResponseObject(vm, entry.raw, entry.elapsed)
					}

					resp := doRequestFromOpts(vm, opts.HTTPClient, o)

					if cache.enabled && !sobek.IsUndefined(resp) && !sobek.IsNull(resp) {
						respObj := resp.ToObject(vm)
						if rawVal := respObj.Get("raw"); rawVal != nil && !sobek.IsUndefined(rawVal) {
							rawBytes := []byte(rawVal.String())
							elapsedMs := int64(0)
							if ev := respObj.Get("elapsed_ms"); ev != nil && !sobek.IsUndefined(ev) {
								elapsedMs = ev.ToInteger()
							}
							cache.put(key, &cacheEntry{
								raw:       rawBytes,
								elapsed:   elapsedMs,
								createdAt: time.Now(),
							})
						}
					}

					return resp
				}
			},
		},
	}
}

// doRequestFromOpts is a helper that extracts method/url/body/headers from a JS object and sends the request.
func doRequestFromOpts(vm *sobek.Runtime, httpClient *gohttp.Requester, opts *sobek.Object) sobek.Value {
	method := "GET"
	if v := opts.Get("method"); v != nil && !sobek.IsUndefined(v) {
		method = v.String()
	}
	urlStr := ""
	if v := opts.Get("url"); v != nil && !sobek.IsUndefined(v) {
		urlStr = v.String()
	}
	body := ""
	if v := opts.Get("body"); v != nil && !sobek.IsUndefined(v) {
		body = v.String()
	}
	headers := make(map[string]string)
	if v := opts.Get("headers"); v != nil && !sobek.IsUndefined(v) {
		headersObj := v.ToObject(vm)
		for _, key := range headersObj.Keys() {
			headers[key] = headersObj.Get(key).String()
		}
	}
	return doRequest(vm, httpClient, method, urlStr, body, headers)
}
