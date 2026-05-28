package proxy_header_trust

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

const (
	injectedHost = "vigolium-probe.example"
	injectedIP   = "127.0.0.1"
)

// isAccessDenied returns true for status codes that indicate the request was
// rejected by an auth/WAF/rate-limit layer rather than served by the app.
func isAccessDenied(status int) bool {
	return status == 401 || status == 403 || status == 429 || status == 503
}

// Module implements the Proxy Header Trust active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Proxy Header Trust module.
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
		ds: dedup.LazyDiskSet("proxy_header_trust"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil {
		return false
	}
	return ctx.Response() != nil
}

// ScanPerRequest tests the host for proxy header trust issues.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	service := ctx.Service()
	if service == nil {
		return nil, nil
	}

	host := service.Host()

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	// Send baseline request.
	baselineRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil, nil
	}
	baselineRaw, err = httpmsg.SetPath(baselineRaw, "/")
	if err != nil {
		return nil, nil
	}

	baselineReq, err := httpmsg.ParseRawRequest(string(baselineRaw))
	if err != nil {
		return nil, nil
	}
	baselineReq = baselineReq.WithService(ctx.Service())

	baselineResp, _, err := httpClient.Execute(baselineReq, http.Options{})
	if err != nil {
		return nil, nil
	}

	baselineStatus := 0
	baselineLocation := ""
	if baselineResp.Response() != nil {
		baselineStatus = baselineResp.Response().StatusCode
		baselineLocation = baselineResp.Response().Header.Get("Location")
	}
	baselineBody := baselineResp.Body().String()
	_ = baselineLocation

	baselineResp.Close()

	urlx, _ := ctx.URL()
	var results []*output.ResultEvent

	// Test 1: X-Forwarded-Host reflection.
	if result := m.testForwardedHost(ctx, httpClient, urlx.String()); result != nil {
		results = append(results, result)
	}

	// Test 2: X-Forwarded-Proto behavior change.
	if result := m.testForwardedProto(ctx, httpClient, baselineStatus, urlx.String()); result != nil {
		results = append(results, result)
	}

	// Test 3: X-Forwarded-For IP trust bypass.
	if result := m.testForwardedFor(ctx, httpClient, baselineStatus, baselineBody, urlx.String()); result != nil {
		results = append(results, result)
	}

	return results, nil
}

func (m *Module) testForwardedHost(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	targetURL string,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, "/")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "X-Forwarded-Host", injectedHost)
	if err != nil {
		return nil
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	probeBody := resp.Body().String()
	probeLocation := ""
	if resp.Response() != nil {
		probeLocation = resp.Response().Header.Get("Location")
	}

	var finding string

	if strings.Contains(probeLocation, injectedHost) {
		finding = fmt.Sprintf("Injected host %q reflected in Location header: %s", injectedHost, probeLocation)
	} else if strings.Contains(probeBody, injectedHost) {
		finding = fmt.Sprintf("Injected host %q reflected in response body", injectedHost)
	}

	if finding == "" {
		return nil
	}

	return &output.ResultEvent{
		URL:      targetURL,
		Request:  string(modifiedRaw),
		Response: resp.FullResponseString(),
		ExtractedResults: []string{
			"Header: X-Forwarded-Host: " + injectedHost,
			"Finding: " + finding,
		},
		Info: output.Info{
			Name:        "Proxy Header Trust: X-Forwarded-Host Injection",
			Description: "X-Forwarded-Host header is trusted for URL generation, allowing host-based attacks such as password reset poisoning and cache poisoning",
			Severity:    severity.High,
			Confidence:  ModuleConfidence,
			Tags:        []string{"proxy", "forwarded-headers", "ip-spoofing", "host-injection"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
		},
	}
}

func (m *Module) testForwardedProto(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	baselineStatus int,
	targetURL string,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, "/")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "X-Forwarded-Proto", "https")
	if err != nil {
		return nil
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	probeStatus := resp.Response().StatusCode
	probeLocation := resp.Response().Header.Get("Location")

	var finding string

	isBaselineRedirect := baselineStatus >= 300 && baselineStatus < 400
	isProbeRedirect := probeStatus >= 300 && probeStatus < 400

	if isBaselineRedirect && !isProbeRedirect {
		finding = fmt.Sprintf("X-Forwarded-Proto: https removed redirect (baseline status %d, probe status %d)", baselineStatus, probeStatus)
	} else if !isBaselineRedirect && isProbeRedirect {
		finding = fmt.Sprintf("X-Forwarded-Proto: https caused new redirect (status %d, Location: %s)", probeStatus, probeLocation)
	} else if baselineStatus != probeStatus && !isAccessDenied(probeStatus) {
		// Skip 200→429/403 transitions — that's the WAF reacting to the header,
		// not the server trusting it.
		finding = fmt.Sprintf("X-Forwarded-Proto: https changed response status from %d to %d", baselineStatus, probeStatus)
	}

	if finding == "" {
		return nil
	}

	return &output.ResultEvent{
		URL:      targetURL,
		Request:  string(modifiedRaw),
		Response: resp.FullResponseString(),
		ExtractedResults: []string{
			"Header: X-Forwarded-Proto: https",
			"Finding: " + finding,
		},
		Info: output.Info{
			Name:        "Proxy Header Trust: X-Forwarded-Proto Confusion",
			Description: "X-Forwarded-Proto header is trusted, causing protocol confusion that may affect redirect behavior, cookie security flags, or HTTPS enforcement",
			Severity:    severity.Medium,
			Confidence:  ModuleConfidence,
			Tags:        []string{"proxy", "forwarded-headers", "ip-spoofing", "host-injection"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
		},
	}
}

func (m *Module) testForwardedFor(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	baselineStatus int,
	baselineBody string,
	targetURL string,
) *output.ResultEvent {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, "/")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "X-Forwarded-For", injectedIP)
	if err != nil {
		return nil
	}

	fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
	if err != nil {
		return nil
	}
	fuzzedReq = fuzzedReq.WithService(ctx.Service())

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	probeStatus := resp.Response().StatusCode
	probeBody := resp.Body().String()

	var finding string

	// A true IP-trust bypass goes from blocked→allowed: the spoofed source IP was
	// trusted and granted access. The reverse (200→429/403) is the WAF detecting
	// the spoofed header and throttling — that's the opposite of trust.
	baselineBlocked := isAccessDenied(baselineStatus)
	probeAllowed := probeStatus >= 200 && probeStatus < 300
	if baselineBlocked && probeAllowed {
		finding = fmt.Sprintf("X-Forwarded-For IP spoofing bypassed access control (status %d → %d)", baselineStatus, probeStatus)
	}

	// Significant body length difference suggests different content served.
	if finding == "" && len(baselineBody) > 0 {
		diff := len(probeBody) - len(baselineBody)
		if diff < 0 {
			diff = -diff
		}
		threshold := len(baselineBody) * 30 / 100
		if threshold < 50 {
			threshold = 50
		}
		if diff > threshold {
			finding = fmt.Sprintf("X-Forwarded-For IP spoofing caused significant response size change (baseline=%d, probe=%d)", len(baselineBody), len(probeBody))
		}
	}

	if finding == "" {
		return nil
	}

	return &output.ResultEvent{
		URL:      targetURL,
		Request:  string(modifiedRaw),
		Response: resp.FullResponseString(),
		ExtractedResults: []string{
			"Header: X-Forwarded-For: " + injectedIP,
			"Finding: " + finding,
		},
		Info: output.Info{
			Name:        "Proxy Header Trust: X-Forwarded-For IP Bypass",
			Description: "X-Forwarded-For header is trusted for IP-based access controls, allowing attackers to bypass rate limiting or IP restrictions by spoofing their source address",
			Severity:    severity.High,
			Confidence:  ModuleConfidence,
			Tags:        []string{"proxy", "forwarded-headers", "ip-spoofing", "host-injection"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
		},
	}
}
