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
	"net/url"
	"strconv"
	"testing"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/core/network"
	hostlimit "github.com/vigolium/vigolium/pkg/core/ratelimit"
	"github.com/vigolium/vigolium/pkg/core/services"
	httpRequester "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types"
)

// Requester returns an *http.Requester wired to the shared loopback dialer,
// suitable for driving a module's scan method against an httptest.Server.
//
// network.Init is reference-counted and idempotent: the dialer is created once
// per process and reused. We intentionally never Close it here — sequential and
// parallel tests share the dialer, and tearing it down mid-suite would break a
// concurrently running test.
func Requester(t testing.TB) *httpRequester.Requester {
	t.Helper()

	opts := types.DefaultOptions()
	opts.Timeout = 30
	opts.Retries = 1
	opts.MaxHostError = 100
	opts.MaxPerHost = 10

	if err := network.Init(opts); err != nil {
		t.Fatalf("modtest: network.Init: %v", err)
	}
	if network.CurrentDialer() == nil {
		t.Fatal("modtest: network dialer is nil after Init")
	}

	svc := &services.Services{
		Options:     opts,
		HostLimiter: hostlimit.NewHostRateLimiter(hostlimit.HostRateLimiterConfig{MaxPerHost: opts.MaxPerHost}),
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
// request body (used for POST/PUT insertion-point coverage). An empty body
// omits the Content-Length/body section.
func RequestMethod(t testing.TB, method, rawURL, body string) *httpmsg.HttpRequestResponse {
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
		raw += fmt.Sprintf("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
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
