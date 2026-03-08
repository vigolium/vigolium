package api_rate_limit_bypass

import (
	"fmt"

	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/pkg/errors"
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

		if resp.Response() != nil && resp.Response().StatusCode != 429 {
			results = append(results, &output.ResultEvent{
				URL:     target,
				Matched: target,
				Request: string(modifiedRaw),
				ExtractedResults: []string{
					fmt.Sprintf("Bypass header: %s: %s", header.name, header.value),
					fmt.Sprintf("Response status: %d (was 429 without header)", resp.Response().StatusCode),
				},
				Info: output.Info{
					Name:        fmt.Sprintf("Rate Limit Bypass via %s", header.name),
					Description: fmt.Sprintf("The server rate limiting can be bypassed by adding the %s header with value %s. This allows an attacker to circumvent rate limiting protections.", header.name, header.value),
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}
