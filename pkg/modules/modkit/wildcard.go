package modkit

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

const (
	wildcardCacheSize    = 1024
	wildcardTTL          = 5 * time.Minute
	wildcardBodyHeadSize = 256
	wildcardBodyLenTol   = 0.10
)

// WildcardEntry caches the result of probing a host with a random non-existent
// path. It lets modules detect SPA / wildcard reverse-proxy handlers that
// return the same 2xx shell for every URL, which would otherwise make any
// "2xx body" signal meaningless.
type WildcardEntry struct {
	Probed     bool
	StatusCode int
	BodyLen    int
	BodyHead   string
	FetchedAt  time.Time
}

// Expired returns true if the entry is older than the TTL.
func (e *WildcardEntry) Expired() bool {
	return time.Since(e.FetchedAt) > wildcardTTL
}

// IsWildcard reports whether the host appears to return a 2xx shell for an
// arbitrary nonexistent path. Modules should treat "2xx returned" signals on
// such a host as low-confidence.
func (e *WildcardEntry) IsWildcard() bool {
	return e != nil && e.Probed && e.StatusCode >= 200 && e.StatusCode < 300 && e.BodyLen > 0
}

// MatchesBody reports whether the given body looks like the wildcard shell —
// same status, body length within tolerance, and matching head bytes. Modules
// use this to reject findings whose "vulnerable" response is just the wildcard
// shell.
func (e *WildcardEntry) MatchesBody(statusCode int, body []byte) bool {
	if !e.IsWildcard() {
		return false
	}
	if statusCode != e.StatusCode {
		return false
	}
	if e.BodyLen == 0 || len(body) == 0 {
		return false
	}
	diff := math.Abs(float64(len(body)-e.BodyLen)) / float64(e.BodyLen)
	if diff > wildcardBodyLenTol {
		return false
	}
	head := body
	if len(head) > wildcardBodyHeadSize {
		head = head[:wildcardBodyHeadSize]
	}
	return string(head) == e.BodyHead
}

// WildcardProbe returns a cached wildcard-handler probe for the host of the
// given request, fetching one if necessary. Concurrent callers for the same
// host coalesce via singleflight.
func (sc *ScanContext) WildcardProbe(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
) (*WildcardEntry, error) {
	if sc == nil {
		return nil, fmt.Errorf("nil ScanContext")
	}
	if ctx == nil || ctx.Service() == nil {
		return nil, fmt.Errorf("missing request service")
	}
	host := ctx.Service().Host()
	if host == "" {
		return nil, fmt.Errorf("empty host")
	}

	cache := sc.getWildcardCache()
	if entry, ok := cache.Get(host); ok && !entry.Expired() {
		return entry, nil
	}

	result, err, _ := sc.wildcardFlight.Do(host, func() (interface{}, error) {
		if entry, ok := cache.Get(host); ok && !entry.Expired() {
			return entry, nil
		}

		entry := &WildcardEntry{FetchedAt: time.Now()}

		// Build a GET probe to a random nonexistent path. Use a clearly
		// synthetic prefix so any debug logs stay legible.
		probePath := "/" + randomToken(12) + "-vigolium-wp/" + randomToken(8)
		raw, perr := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
		if perr != nil {
			cache.Add(host, entry)
			return entry, nil
		}
		raw, perr = httpmsg.SetPath(raw, probePath)
		if perr != nil {
			cache.Add(host, entry)
			return entry, nil
		}

		probeReq, perr := httpmsg.ParseRawRequest(string(raw))
		if perr != nil {
			cache.Add(host, entry)
			return entry, nil
		}
		probeReq = probeReq.WithService(ctx.Service())

		resp, _, rerr := httpClient.Execute(probeReq, http.Options{NoRedirects: true})
		if rerr != nil || resp == nil {
			cache.Add(host, entry)
			return entry, nil
		}
		status := 0
		if resp.Response() != nil {
			status = resp.Response().StatusCode
		}
		body := resp.Body().Bytes()
		bodyCopy := make([]byte, len(body))
		copy(bodyCopy, body)
		resp.Close()

		head := bodyCopy
		if len(head) > wildcardBodyHeadSize {
			head = head[:wildcardBodyHeadSize]
		}
		entry.Probed = true
		entry.StatusCode = status
		entry.BodyLen = len(bodyCopy)
		entry.BodyHead = string(head)
		cache.Add(host, entry)
		return entry, nil
	})

	if err != nil {
		return nil, err
	}
	return result.(*WildcardEntry), nil
}

func (sc *ScanContext) getWildcardCache() *lru.Cache[string, *WildcardEntry] {
	sc.wildcardOnce.Do(func() {
		sc.wildcardCache, _ = lru.New[string, *WildcardEntry](wildcardCacheSize)
	})
	return sc.wildcardCache
}

func randomToken(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		// Fall back to a deterministic token — the path just needs to be
		// unlikely to collide with a real route.
		return fmt.Sprintf("rnd%dxx", time.Now().UnixNano()&0xffff)
	}
	return hex.EncodeToString(b)[:n]
}
