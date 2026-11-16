// Package modtest provides shared helpers for unit-testing scanner modules
// against an in-process httptest.Server.
//
// Unlike the e2e harness (test/e2e/helper_test.go) these helpers carry no build
// tag, so they are available to fast `-short` unit tests. They wire up a real
// *http.Requester against the shared loopback dialer and build the
// *httpmsg.HttpRequestResponse / insertion points a module's scan method
// expects, letting a test exercise true detection logic without Docker.
//
// Typical use:
//
//	srv := httptest.NewServer(handler)
//	defer srv.Close()
//	client := modtest.Requester(t)
//	rr := modtest.Request(t, srv.URL+"/?id=1")
//	ip := modtest.InsertionPoint(t, rr, "id")
//	res, err := mymod.New().ScanPerInsertionPoint(rr, ip, client, &modkit.ScanContext{})
package modtest

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	httputil "github.com/projectdiscovery/utils/http"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	httpRequester "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
	"go.uber.org/goleak"
)

// VerifyNoLeaks runs goleak.VerifyTestMain with the standard ignore list for the
// process-lifetime infra goroutines that Requester starts via network.Init (the
// active mem guardian and a leveldb store) — singletons with no stop hook. Use it
// as the whole body of a package's TestMain when that package's tests drive a
// real Requester:
//
//	func TestMain(m *testing.M) { modtest.VerifyNoLeaks(m) }
//
// extra adds a suite's own ignores on top of the standard list.
func VerifyNoLeaks(m *testing.M, extra ...goleak.Option) {
	goleak.VerifyTestMain(m, append(leakIgnores(), extra...)...)
}

// leakIgnores is the standard ignore list for process-lifetime infra goroutines.
func leakIgnores() []goleak.Option {
	return []goleak.Option{
		goleak.IgnoreTopFunction("go.opencensus.io/stats/view.(*worker).start"),
		goleak.IgnoreTopFunction("github.com/vigolium/vigolium/pkg/core/network.StartActiveMemGuardian.func1"),
		goleak.IgnoreAnyFunction("github.com/vigolium/vigolium/pkg/core/network.runGuardian"),
		goleak.IgnoreAnyFunction("github.com/syndtr/goleveldb/leveldb.(*DB).mpoolDrain"),
		goleak.IgnoreAnyFunction("github.com/syndtr/goleveldb/leveldb.(*DB).tCompaction"),
		goleak.IgnoreAnyFunction("github.com/syndtr/goleveldb/leveldb.(*DB).mCompaction"),
		goleak.IgnoreAnyFunction("github.com/syndtr/goleveldb/leveldb.(*DB).compactionError"),
		goleak.IgnoreAnyFunction("github.com/syndtr/goleveldb/leveldb.(*session).refLoop"),
		goleak.IgnoreAnyFunction("github.com/syndtr/goleveldb/leveldb/util.(*BufferPool).drain"),
	}
}

// Requester returns an *http.Requester wired to the shared loopback dialer,
// suitable for driving a module's scan method against an httptest.Server.
//
// network.Init is reference-counted and idempotent: the dialer is created once
// per process and reused. We intentionally never Close it here — sequential and
// parallel tests share the dialer, and tearing it down mid-suite would break a
// concurrently running test.
func Requester(t testing.TB) *httpRequester.Requester {
	t.Helper()
	return newRequester(t, false)
}

// RequesterNoThrottlePause is Requester whose host limiter never pauses a host
// on 429/503. For sweeps that fire many modules at a deliberately
// throttling fixture and only assert what the modules conclude.
func RequesterNoThrottlePause(t testing.TB) *httpRequester.Requester {
	t.Helper()
	return newRequester(t, true)
}

func newRequester(t testing.TB, noThrottlePause bool) *httpRequester.Requester {
	t.Helper()

	opts := types.DefaultOptions()
	// Timeout is a time.Duration: a bare `30` is 30 NANOSECONDS, which the rawhttp
	// client (Options.RawRequest) honours strictly as an instant connection
	// deadline — making every raw request fail with "context deadline exceeded".
	// The retryablehttp path tolerated it, which hid the bug. Use a real 30s so
	// both transports work against the loopback test server.
	opts.Timeout = 30 * time.Second
	opts.Retries = 1
	opts.MaxHostError = 100
	opts.MaxPerHost = 10

	if err := network.Init(opts); err != nil {
		t.Fatalf("modtest: network.Init: %v", err)
	}
	if network.CurrentDialer() == nil {
		t.Fatal("modtest: network dialer is nil after Init")
	}

	limiter := hostlimit.NewHostRateLimiter(hostlimit.HostRateLimiterConfig{MaxPerHost: opts.MaxPerHost, DisableThrottlePause: noThrottlePause})
	// Stop the limiter's background eviction goroutine when the test finishes so
	// packages that assert no goroutine leaks (goleak.VerifyTestMain) stay clean.
	t.Cleanup(func() { _ = limiter.Close() })

	svc := &services.Services{
		Options:     opts,
		HostLimiter: limiter,
		HostErrors:  hosterrors.New(opts.MaxHostError, hosterrors.DefaultMaxHostsCount, nil),
	}

	client, err := httpRequester.NewRequester(opts, svc)
	if err != nil {
		t.Fatalf("modtest: NewRequester: %v", err)
	}
	return client
}

// Request builds a GET *httpmsg.HttpRequestResponse targeting the absolute
// rawURL (e.g. an httptest.Server URL plus path/query). The HttpService is
// derived from the URL so a module's fuzzed requests route back to the test
// server. The response is left nil; modules that need a baseline fetch it
// themselves via the requester.
func Request(t testing.TB, rawURL string) *httpmsg.HttpRequestResponse {
	t.Helper()
	return RequestMethod(t, "GET", rawURL, "")
}

// RequestMethod is like Request but lets a test pick the method and supply a
// request body (used for POST/PUT insertion-point coverage). The body is sent as
// application/x-www-form-urlencoded; an empty body omits the Content-Length/body
// section. For a JSON body (INS_PARAM_JSON insertion points) use RequestJSON.
func RequestMethod(t testing.TB, method, rawURL, body string) *httpmsg.HttpRequestResponse {
	t.Helper()
	return requestWithContentType(t, method, rawURL, "application/x-www-form-urlencoded", body)
}

// RequestJSON builds a POST request whose body is sent as application/json, so
// JSON fields become INS_PARAM_JSON insertion points. Use it for tests that
// target JSON parameters; RequestMethod sends form-urlencoded (INS_PARAM_BODY).
func RequestJSON(t testing.TB, rawURL, jsonBody string) *httpmsg.HttpRequestResponse {
	t.Helper()
	return requestWithContentType(t, "POST", rawURL, "application/json", jsonBody)
}

// requestWithContentType builds an HttpRequestResponse for the given method and
// body, tagging a non-empty body with contentType. An empty body omits the
// Content-Type/Content-Length/body section entirely.
func requestWithContentType(t testing.TB, method, rawURL, contentType, body string) *httpmsg.HttpRequestResponse {
	t.Helper()

	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("modtest: parse URL %q: %v", rawURL, err)
	}

	port, err := portForURL(u)
	if err != nil {
		t.Fatalf("modtest: %v", err)
	}

	svc, err := httpmsg.NewService(u.Hostname(), port, u.Scheme)
	if err != nil {
		t.Fatalf("modtest: NewService for %q: %v", rawURL, err)
	}

	target := u.RequestURI()
	if target == "" {
		target = "/"
	}

	raw := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n", method, target, u.Host)
	if body != "" {
		raw += fmt.Sprintf("Content-Type: %s\r\nContent-Length: %d\r\n\r\n%s", contentType, len(body), body)
	} else {
		raw += "\r\n"
	}

	req := httpmsg.NewHttpRequestWithService(svc, []byte(raw))
	return httpmsg.NewHttpRequestResponse(req, nil)
}

// Response returns a copy of rr with a synthetic 200 OK response (carrying the
// given content-type and body) attached. It mirrors the captured baseline
// response the executor supplies before active scanning. Modules that use the
// original response as a baseline (e.g. ssrf_detection) need this; modules that
// fetch their own baseline can ignore it and pass the bare Request.
func Response(rr *httpmsg.HttpRequestResponse, contentType, body string) *httpmsg.HttpRequestResponse {
	rawResp := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s",
		contentType, len(body), body,
	)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(rr.Request(), resp)
}

// InsertionPoint returns the parameter insertion point named name from rr, or
// fails the test if no such point exists. Nested points are included so JSON /
// form sub-fields can be targeted by name.
func InsertionPoint(t testing.TB, rr *httpmsg.HttpRequestResponse, name string) httpmsg.InsertionPoint {
	t.Helper()

	points, err := httpmsg.CreateAllInsertionPoints(rr.Request().Raw(), true)
	if err != nil {
		t.Fatalf("modtest: CreateAllInsertionPoints: %v", err)
	}
	for _, ip := range points {
		if ip.Name() == name {
			return ip
		}
	}

	var got []string
	for _, ip := range points {
		got = append(got, ip.Name())
	}
	t.Fatalf("modtest: no insertion point named %q (have %v)", name, got)
	return nil
}

// InsertionPointByType returns the first insertion point of the given type from
// rr, or fails the test if none exists. Use it for the positional points that
// InsertionPoint cannot address readably: URL path folders and filenames are
// named by ordinal ("1", "2", …), so selecting them by name is both opaque and
// brittle whenever a test URL's path depth changes.
func InsertionPointByType(t testing.TB, rr *httpmsg.HttpRequestResponse, typ httpmsg.InsertionPointType) httpmsg.InsertionPoint {
	t.Helper()

	points, err := httpmsg.CreateAllInsertionPoints(rr.Request().Raw(), true)
	if err != nil {
		t.Fatalf("modtest: CreateAllInsertionPoints: %v", err)
	}
	for _, ip := range points {
		if ip.Type() == typ {
			return ip
		}
	}

	var got []string
	for _, ip := range points {
		got = append(got, ip.Type().String())
	}
	t.Fatalf("modtest: no insertion point of type %s (have %v)", typ, got)
	return nil
}

// portForURL resolves the numeric port for u, defaulting to the scheme's
// well-known port when none is present in the URL.
func portForURL(u *url.URL) (int, error) {
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return 0, fmt.Errorf("invalid port %q: %w", p, err)
		}
		return n, nil
	}
	if u.Scheme == "https" {
		return 443, nil
	}
	return 80, nil
}

// ResponseChain builds a filled *httputil.ResponseChain from a status, header
// set and body, mirroring what the requester hands a module.
//
// It exists for tests of the response-classification helpers modules layer on
// top of a response — block/edge detection, keep-alive gates, content checks —
// which need a chain but no server. The returned chain is closed on cleanup.
func ResponseChain(t testing.TB, status int, header http.Header, body string) *httputil.ResponseChain {
	t.Helper()
	if header == nil {
		header = http.Header{}
	}
	resp := &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
	rc := httputil.NewResponseChain(resp, 0)
	if err := rc.Fill(); err != nil {
		t.Fatalf("fill response chain: %v", err)
	}
	t.Cleanup(rc.Close)
	return rc
}
