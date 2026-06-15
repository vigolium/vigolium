package api_rate_limit_bypass

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
)

const rateLimitRequestCount = 10

// bypassHeaders defines the IP spoofing headers to test for rate limit bypass.
var bypassHeaders = []struct {
	name  string
	value string
}{
	{"X-Forwarded-For", "127.0.0.1"},
	{"X-Real-IP", "127.0.0.1"},
	{"X-Originating-IP", "127.0.0.1"},
	{"X-Remote-IP", "127.0.0.1"},
	{"X-Client-IP", "127.0.0.1"},
	{"X-Forwarded-For", "10.0.0.1"},
	{"True-Client-IP", "127.0.0.1"},
	{"X-Custom-IP-Authorization", "127.0.0.1"},
}

// Module implements the API Rate Limit Bypass active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new API Rate Limit Bypass module.
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
			modkit.ScanScopeHost,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("api_rate_limit_bypass"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// IncludesBaseCanProcess returns false because this module uses a custom CanProcess.
func (m *Module) IncludesBaseCanProcess() bool { return false }

// CanProcess returns true if the request has a response (to confirm the host is live).
func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	if ctx.Response() == nil {
		return false
	}
	return true
}

// ScanPerHost tests for rate limit bypass once per unique host.
func (m *Module) ScanPerHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	// Dedup by host
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	// Step 1: Send rapid requests to trigger rate limiting
	rateLimited := false
	for i := 0; i < rateLimitRequestCount; i++ {
		fuzzedReq, err := httpmsg.ParseRawRequest(string(ctx.Request().Raw()))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return nil, nil
			}
			continue
		}

		if resp.Response() != nil && resp.Response().StatusCode == 429 {
			rateLimited = true
			resp.Close()
			break
		}
		resp.Close()
	}

	if !rateLimited {
		// No rate limiting detected, nothing to bypass
		return nil, nil
	}

	// Step 2: Try bypass headers to circumvent rate limiting
	var results []*output.ResultEvent
	target := ctx.Target()

	for _, header := range bypassHeaders {
		modifiedRaw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), header.name, header.value)
		if err != nil {
			continue
		}

		fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true})
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, nil
			}
			continue
		}

		// A genuine bypass means the request now succeeds. Other 4xx/5xx codes
		// (403, 503, etc.) mean the WAF blocked via a different mechanism — still
		// blocked, not bypassed. Redirects (3xx) typically point at an auth flow
		// or rate-limit landing page and don't prove access.
		bypassed := resp.Response() != nil &&
			resp.Response().StatusCode >= 200 &&
			resp.Response().StatusCode < 300

		if bypassed {
			bypassStatus := resp.Response().StatusCode
			resp.Close()
			// A single 2xx after a 429 does not prove the header bypassed anything:
			// rate-limit windows are short, so the limiter may simply have reset
			// between probes. Re-confirm with a differential — a plain request (no
			// bypass header) must STILL be throttled while the header request
			// succeeds again — before reporting.
			if !m.confirmRateLimitBypass(ctx, httpClient, header.name, header.value) {
				continue
			}
			results = append(results, &output.ResultEvent{
				URL:     target,
				Matched: target,
				Request: string(modifiedRaw),
				ExtractedResults: []string{
					fmt.Sprintf("Bypass header: %s: %s", header.name, header.value),
					fmt.Sprintf("Response status: %d (plain request still 429)", bypassStatus),
				},
				Info: output.Info{
					Name:        fmt.Sprintf("Rate Limit Bypass via %s", header.name),
					Description: fmt.Sprintf("The server rate limiting can be bypassed by adding the %s header with value %s. This allows an attacker to circumvent rate limiting protections.", header.name, header.value),
				},
			})
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}

// confirmRateLimitBypass re-verifies that the header genuinely bypasses the
// limiter rather than the window having reset between probes. It SANDWICHES the
// header success between two throttled plain samples: a plain request (no bypass
// header) must still be 429, then the header request must succeed (2xx), then a
// plain request must STILL be 429. All are re-issued with NoClustering so each is
// a fresh observation. The trailing plain-429 check is the key guard — if the
// limiter window simply reset between probes (the dominant false-positive cause),
// the reset would let the plain request through too, so a still-throttled plain
// request after the apparent bypass proves the differential is real and not just a
// cleared window. Fails closed when the differential cannot be established.
func (m *Module) confirmRateLimitBypass(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	name, value string,
) bool {
	// 1) Before: without the bypass header, the limiter must be active.
	if !m.plainStillLimited(ctx, httpClient) {
		return false
	}
	// 2) With the bypass header, the request must succeed (the apparent bypass).
	if st, ok := m.sendStatus(ctx, httpClient, name, value); !ok || st < 200 || st >= 300 {
		return false
	}
	// 3) After: without the header, the limiter must STILL be active. A window that
	//    reset between steps 1 and 2 (and only looked like a bypass) would also let
	//    this plain request through — so requiring it to stay 429 rejects that FP.
	return m.plainStillLimited(ctx, httpClient)
}

// plainStillLimited reports whether the unmodified request (no bypass header) is
// still being throttled. It samples up to three times and accepts a single 429 so
// a leaky-bucket limiter that occasionally lets a request through is not misread
// as "no longer limited".
func (m *Module) plainStillLimited(ctx *httpmsg.HttpRequestResponse, httpClient *http.Requester) bool {
	for i := 0; i < 3; i++ {
		if st, ok := m.sendStatus(ctx, httpClient, "", ""); ok && st == 429 {
			return true
		}
	}
	return false
}

// sendStatus issues one request and returns its status code. When name is
// non-empty the given header is added/replaced first. ok is false on any
// parse/HTTP/empty-response error.
func (m *Module) sendStatus(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	name, value string,
) (int, bool) {
	raw := ctx.Request().Raw()
	if name != "" {
		var err error
		raw, err = httpmsg.AddOrReplaceHeader(raw, name, value)
		if err != nil {
			return 0, false
		}
	}
	req, err := httpmsg.ParseRawRequest(string(raw))
	if err != nil {
		return 0, false
	}
	req = req.WithService(ctx.Service())
	resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return 0, false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return 0, false
	}
	return resp.Response().StatusCode, true
}
