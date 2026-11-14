package modkit

import (
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// measurementCacheSize bounds the per-scan endpoint memo cache (shared by
// EndpointMeasurement and EndpointMemo values).
const measurementCacheSize = 1024

// EndpointMeasurement memoizes a numeric property a module derives by probing the
// UNMODIFIED request, so it is measured once per record instead of once per
// insertion point. It is EndpointMemo for an int that is always cached.
//
// It exists because the executor dispatches every insertion point of a record as
// a separate concurrent task, while calibration probes (page jitter, control
// samples, timing baselines) replay the record's own unmodified request — which
// is identical for all of them. Without this, a browser-captured request with ~20
// insertion points pays 20x the round-trips to learn one number, and because the
// tasks start together a plain check-then-compute would have all 20 miss at the
// same instant. The singleflight group collapses those into one measurement.
//
// name namespaces the measurement so unrelated modules (or several measurements
// within one module) cannot collide on the shared per-record key.
//
// Deliberately no TTL: the cache lives on the ScanContext, so it dies with the
// scan and cannot leak across runs or serve one scan's calibration to another.
// A nil ScanContext falls back to measuring directly rather than sharing a
// degenerate key, which also keeps this usable from unit tests.
func (sc *ScanContext) EndpointMeasurement(name string, ctx *httpmsg.HttpRequestResponse, measure func() int) int {
	if measure == nil {
		return 0
	}
	v, _ := sc.EndpointMemo(name, ctx, 0, func() (any, bool) { return measure(), true }).(int)
	return v
}

func (sc *ScanContext) getHostMemoCache() *lru.Cache[string, any] {
	sc.hostMemoOnce.Do(func() {
		sc.hostMemoCache, _ = lru.New[string, any](perHostRegistryCacheSize)
	})
	return sc.hostMemoCache
}

// HostMemo memoizes an artifact a module derives once per host — a fetched JWKS
// key set, a parsed discovery document — so every record on that host reuses it
// instead of re-fetching. It is EndpointMeasurement's per-host sibling for
// non-numeric values: concurrent callers for the same (name, host) collapse into
// one compute via singleflight, the LRU is bounded like the other per-host
// registries, and the cache dies with the ScanContext so nothing leaks across
// scans.
//
// host should include the port (`example.com:8443`) when the module's notion of
// "host" depends on it. compute's result is cached as-is, including a nil or
// empty "nothing found" value, so a host without the artifact is not re-probed.
// A nil ScanContext (unit tests) computes directly.
func (sc *ScanContext) HostMemo(name, host string, compute func() any) any {
	if compute == nil {
		return nil
	}
	if sc == nil || host == "" {
		return compute()
	}
	key := name + "\x00" + strings.ToLower(host)
	cache := sc.getHostMemoCache()
	if v, ok := cache.Get(key); ok {
		return v
	}
	res, _, _ := sc.hostMemoFlight.Do(key, func() (interface{}, error) {
		if v, ok := cache.Get(key); ok {
			return v, nil
		}
		v := compute()
		cache.Add(key, v)
		return v, nil
	})
	return res
}
