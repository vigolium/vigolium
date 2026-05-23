package dedup

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func newTestRHM(t *testing.T, opt Option) *RequestHashManager {
	t.Helper()
	rhm, err := newRequestHashManager(opt)
	require.NoError(t, err)
	require.NotNil(t, rhm)
	t.Cleanup(rhm.Close)
	return rhm
}

func mustURL(t *testing.T, raw string) *urlutil.URL {
	t.Helper()
	u, err := urlutil.Parse(raw)
	require.NoError(t, err)
	return u
}

func mustHTTPRequest(t *testing.T, raw string) *httpmsg.HttpRequest {
	t.Helper()
	return httpmsg.NewHttpRequest([]byte(raw))
}

// TestRHM_ShouldCheck_DedupesSameRequest is the core contract: ShouldCheck is
// true the first time (caller should test it) and false on an identical repeat
// (already covered, suppress).
func TestRHM_ShouldCheck_DedupesSameRequest(t *testing.T) {
	rhm := newTestRHM(t, DefaultOption)

	u := mustURL(t, "https://example.com/path?id=1")
	req := mustHTTPRequest(t, "GET /path?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	param := httpmsg.NewURLParam("id", "1")

	assert.True(t, rhm.ShouldCheck(u, req, param), "first occurrence must be checked")
	assert.False(t, rhm.ShouldCheck(u, req, param), "identical repeat must be suppressed")
	assert.False(t, rhm.ShouldCheck(u, req, param), "still suppressed on third call")
}

// TestRHM_ShouldCheck_DifferentParamsNotDeduped verifies a different injecting
// parameter produces a distinct hash and is therefore independently checkable.
func TestRHM_ShouldCheck_DifferentParamsNotDeduped(t *testing.T) {
	rhm := newTestRHM(t, DefaultOption)

	u := mustURL(t, "https://example.com/path?id=1&q=x")
	req := mustHTTPRequest(t, "GET /path?id=1&q=x HTTP/1.1\r\nHost: example.com\r\n\r\n")

	pID := httpmsg.NewURLParam("id", "1")
	pQ := httpmsg.NewURLParam("q", "x")

	assert.True(t, rhm.ShouldCheck(u, req, pID))
	assert.True(t, rhm.ShouldCheck(u, req, pQ), "a different injecting param must not be deduped against the first")
	// And each is now individually suppressed.
	assert.False(t, rhm.ShouldCheck(u, req, pID))
	assert.False(t, rhm.ShouldCheck(u, req, pQ))
}

// TestRHM_ShouldCheck_DifferentPathAndHost confirms host and path participate in
// the hash under DefaultOption: same param, different path/host => not deduped.
func TestRHM_ShouldCheck_DifferentPathAndHost(t *testing.T) {
	rhm := newTestRHM(t, DefaultOption)
	param := httpmsg.NewURLParam("id", "1")

	u1 := mustURL(t, "https://example.com/a?id=1")
	u2 := mustURL(t, "https://example.com/b?id=1")
	u3 := mustURL(t, "https://other.com/a?id=1")
	req := mustHTTPRequest(t, "GET /a?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")

	assert.True(t, rhm.ShouldCheck(u1, req, param))
	assert.True(t, rhm.ShouldCheck(u2, req, param), "different path must be a distinct hash")
	assert.True(t, rhm.ShouldCheck(u3, req, param), "different host must be a distinct hash")
}

// TestRHM_ShouldCheck2_MethodOverride exercises the method-override variant: the
// override participates in the hash, so the same request under two methods is
// not deduped, but repeating the same override is.
func TestRHM_ShouldCheck2_MethodOverride(t *testing.T) {
	rhm := newTestRHM(t, DefaultOption)

	u := mustURL(t, "https://example.com/path?id=1")
	req := mustHTTPRequest(t, "GET /path?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	param := httpmsg.NewURLParam("id", "1")

	assert.True(t, rhm.ShouldCheck2(u, req, param, "POST"))
	assert.False(t, rhm.ShouldCheck2(u, req, param, "POST"), "same override repeats are suppressed")
	assert.True(t, rhm.ShouldCheck2(u, req, param, "PUT"), "a different method override is a distinct hash")

	// The empty override falls back to the request's own method (GET), which is
	// distinct from the explicit POST/PUT above.
	assert.True(t, rhm.ShouldCheck2(u, req, param, ""))
}

// TestRHM_ShouldCheck3_DirectParams exercises the variant that takes raw
// component strings instead of a Param/request pair.
func TestRHM_ShouldCheck3_DirectParams(t *testing.T) {
	rhm := newTestRHM(t, DefaultOption)
	u := mustURL(t, "https://example.com/path?id=1")

	first := rhm.ShouldCheck3(u, "GET", "", "id", "1", "0")
	assert.True(t, first)
	assert.False(t, rhm.ShouldCheck3(u, "GET", "", "id", "1", "0"), "identical direct params dedupe")

	// Changing the position string yields a new hash (position is in DefaultOption).
	assert.True(t, rhm.ShouldCheck3(u, "GET", "", "id", "1", "1"))
}

// TestRHM_ShouldCheckInsertionPoint validates the insertion-point entrypoint and
// that the param type is folded into the position component of the hash.
func TestRHM_ShouldCheckInsertionPoint(t *testing.T) {
	rhm := newTestRHM(t, DefaultOption)
	u := mustURL(t, "https://example.com/path?id=1")
	req := mustHTTPRequest(t, "GET /path?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")

	urlType := strconv.Itoa(int(httpmsg.ParamURL.ToInsertionPointType()))
	cookieType := strconv.Itoa(int(httpmsg.ParamCookie.ToInsertionPointType()))

	assert.True(t, rhm.ShouldCheckInsertionPoint(u, req, "id", "1", urlType))
	assert.False(t, rhm.ShouldCheckInsertionPoint(u, req, "id", "1", urlType), "repeat insertion point suppressed")
	assert.True(t, rhm.ShouldCheckInsertionPoint(u, req, "id", "1", cookieType), "different param type is a distinct hash")
}

// TestRHM_GetNotCheckedParams verifies the bulk filter: it returns only the
// params not yet seen, records them as it goes, and returns nil for empty input.
func TestRHM_GetNotCheckedParams(t *testing.T) {
	rhm := newTestRHM(t, DefaultOption)
	u := mustURL(t, "https://example.com/path?a=1&b=2&c=3")
	req := mustHTTPRequest(t, "GET /path?a=1&b=2&c=3 HTTP/1.1\r\nHost: example.com\r\n\r\n")

	params := []*httpmsg.Param{
		httpmsg.NewURLParam("a", "1"),
		httpmsg.NewURLParam("b", "2"),
		httpmsg.NewURLParam("c", "3"),
	}

	// First pass: all three are new.
	got := rhm.GetNotCheckedParams(u, req, params)
	require.Len(t, got, 3)

	// Second pass with the same params: all already recorded -> none returned.
	got = rhm.GetNotCheckedParams(u, req, params)
	assert.Empty(t, got, "params already seen must be filtered out")

	// A mix of one new + two seen returns only the new one.
	mixed := []*httpmsg.Param{
		httpmsg.NewURLParam("a", "1"),         // seen
		httpmsg.NewURLParam("brand-new", "9"), // new
	}
	got = rhm.GetNotCheckedParams(u, req, mixed)
	require.Len(t, got, 1)
	assert.Equal(t, "brand-new", got[0].Name())

	// Empty input returns nil.
	assert.Nil(t, rhm.GetNotCheckedParams(u, req, nil))
}

// TestRHM_GetNotCheckedInsertionPoints validates the insertion-point bulk filter
// the same way: dedupes already-seen points and returns nil for empty input.
func TestRHM_GetNotCheckedInsertionPoints(t *testing.T) {
	rhm := newTestRHM(t, DefaultOption)
	u := mustURL(t, "https://example.com/path?a=1&b=2")
	rawReq := []byte("GET /path?a=1&b=2 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	req := httpmsg.NewHttpRequest(rawReq)

	points := []httpmsg.InsertionPoint{
		httpmsg.NewParameterInsertionPoint(rawReq, httpmsg.NewURLParam("a", "1")),
		httpmsg.NewParameterInsertionPoint(rawReq, httpmsg.NewURLParam("b", "2")),
	}

	got := rhm.GetNotCheckedInsertionPoints(u, req, points)
	require.Len(t, got, 2, "all insertion points are new on first pass")

	got = rhm.GetNotCheckedInsertionPoints(u, req, points)
	assert.Empty(t, got, "already-seen insertion points must be filtered out")

	assert.Nil(t, rhm.GetNotCheckedInsertionPoints(u, req, nil))
}

// TestRHM_ShouldCheck_NilParam confirms a nil param is handled (hashes with
// empty name/value/position) and is deduped against a repeat nil-param request.
func TestRHM_ShouldCheck_NilParam(t *testing.T) {
	rhm := newTestRHM(t, DefaultOption)
	u := mustURL(t, "https://example.com/path")
	req := mustHTTPRequest(t, "GET /path HTTP/1.1\r\nHost: example.com\r\n\r\n")

	assert.True(t, rhm.ShouldCheck(u, req, nil))
	assert.False(t, rhm.ShouldCheck(u, req, nil), "nil-param request hashes consistently and dedupes")
}

// TestRHM_Option_BodyToggle confirms the Body option actually changes hashing:
// with Body disabled (default) two requests differing only in body collapse to
// the same hash; with Body enabled they do not.
func TestRHM_Option_BodyToggle(t *testing.T) {
	param := httpmsg.NewBodyParam("x", "1")
	u := mustURL(t, "https://example.com/p")

	reqBody := func(b string) *httpmsg.HttpRequest {
		return httpmsg.NewHttpRequest([]byte("POST /p HTTP/1.1\r\nHost: example.com\r\nContent-Length: " +
			strconv.Itoa(len(b)) + "\r\n\r\n" + b))
	}

	// Body OFF (default): bodies differ but hash ignores body => second is deduped.
	off := newTestRHM(t, DefaultOption)
	assert.True(t, off.ShouldCheck(u, reqBody("one"), param))
	assert.False(t, off.ShouldCheck(u, reqBody("two"), param), "with Body disabled, differing bodies collapse")

	// Body ON: the same two requests are now distinct.
	opt := DefaultOption
	opt.Body = true
	on := newTestRHM(t, opt)
	assert.True(t, on.ShouldCheck(u, reqBody("one"), param))
	assert.True(t, on.ShouldCheck(u, reqBody("two"), param), "with Body enabled, differing bodies are distinct")
}

// TestRHM_Concurrent_SameRequest stresses the dedup path: many goroutines firing
// the identical request must collectively get exactly one "should check" true.
// This proves the DiskSet-backed dedup behind RequestHashManager serializes the
// check-then-add correctly under contention. Run under -race.
//
// Each goroutine builds its own *urlutil.URL/HttpRequest/Param: in the real
// executor every request carries its own freshly-parsed URL, and urlutil's
// OrderedParams.Iterate mutates internal state during iteration, so a single
// shared URL is not the contract under test here — the dedup manager's
// concurrency guarantee is on its own state.
func TestRHM_Concurrent_SameRequest(t *testing.T) {
	rhm := newTestRHM(t, DefaultOption)

	const n = 128
	var trueCount atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u, err := urlutil.Parse("https://example.com/path?id=1")
			if err != nil {
				t.Errorf("parse URL: %v", err)
				return
			}
			req := httpmsg.NewHttpRequest([]byte("GET /path?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"))
			param := httpmsg.NewURLParam("id", "1")
			if rhm.ShouldCheck(u, req, param) {
				trueCount.Add(1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(1), trueCount.Load(), "exactly one concurrent caller should be told to check")
}
