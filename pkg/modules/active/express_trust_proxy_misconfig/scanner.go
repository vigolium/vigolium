package express_trust_proxy_misconfig

import (
	"fmt"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

const (
	injectedHost = "vgn-trust-test.example"
	injectedIP   = "127.0.0.1"
	injectedPort = "1337"
)

// trustProxyProbe defines a trust proxy misconfiguration test case.
type trustProxyProbe struct {
	headerName string
	value      string
	desc       string
}

var probes = []trustProxyProbe{
	{
		headerName: "X-Forwarded-Proto",
		value:      "http",
		desc:       "X-Forwarded-Proto protocol confusion — may cause redirect to HTTPS or strip cookie Secure flag",
	},
	{
		headerName: "X-Forwarded-Host",
		value:      injectedHost,
		desc:       "X-Forwarded-Host trusted for URL generation — injected host appears in response",
	},
	{
		headerName: "X-Forwarded-For",
		value:      injectedIP,
		desc:       "X-Forwarded-For IP spoofing — may bypass IP-based access controls or rate limiting",
	},
	{
		headerName: "X-Forwarded-Port",
		value:      injectedPort,
		desc:       "X-Forwarded-Port injection — injected port appears in generated URLs or redirects",
	},
}

// Module implements the Express Trust Proxy Misconfiguration active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

// New creates a new Express Trust Proxy Misconfiguration module.
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
		ds: dedup.LazyDiskSet("express_trust_proxy_misconfig"),
	}
	m.ModuleTags = ModuleTags
	return m
}

// ScanPerRequest tests the request for Express trust proxy misconfiguration.
func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	if utils.IsMediaAndJSURL(urlx.Path) {
		return nil, nil
	}

	diskSet := m.ds.Get(scanCtx.DedupMgr())
	hash := utils.Sha1(fmt.Sprintf("%s%s", urlx.Host, urlx.Path))
	if diskSet != nil && diskSet.IsSeen(hash) {
		return nil, nil
	}

	// Send baseline request to capture normal behavior.
	baselineReq, err := httpmsg.ParseRawRequest(string(ctx.Request().Raw()))
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
	baselineHeaders := baselineResp.Headers().String()
	baselineHasSecureCookie := strings.Contains(baselineHeaders, "Secure")
	_ = baselineLocation

	baselineResp.Close()

	var results []*output.ResultEvent

	for _, probe := range probes {
		modifiedRaw, err := httpmsg.AddOrReplaceHeader(ctx.Request().Raw(), probe.headerName, probe.value)
		if err != nil {
			continue
		}

		fuzzedReq, err := httpmsg.ParseRawRequest(string(modifiedRaw))
		if err != nil {
			continue
		}
		fuzzedReq = fuzzedReq.WithService(ctx.Service())

		resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
		if err != nil {
			continue
		}

		probeBody := resp.Body().String()
		probeHeaders := resp.Headers().String()
		probeStatus := 0
		probeLocation := ""
		if resp.Response() != nil {
			probeStatus = resp.Response().StatusCode
			probeLocation = resp.Response().Header.Get("Location")
		}

		var finding string

		switch probe.headerName {
		case "X-Forwarded-Proto":
			finding = checkProtocolConfusion(
				baselineStatus, probeStatus,
				baselineHasSecureCookie, probeHeaders,
				probeLocation,
			)

		case "X-Forwarded-Host":
			finding = checkHostInjection(probeBody, probeHeaders, probeLocation)

		case "X-Forwarded-For":
			finding = checkIPBypass(baselineStatus, probeStatus, baselineBody, probeBody)

		case "X-Forwarded-Port":
			finding = checkPortInjection(probeBody, probeLocation)
		}

		if finding != "" {
			extracted := []string{
				fmt.Sprintf("Header: %s: %s", probe.headerName, probe.value),
				fmt.Sprintf("Finding: %s", finding),
			}

			results = append(results, &output.ResultEvent{
				URL:              urlx.String(),
				Request:          string(modifiedRaw),
				Response:         resp.FullResponse().String(),
				ExtractedResults: extracted,
				Info: output.Info{
					Name:        fmt.Sprintf("Express Trust Proxy Misconfiguration: %s", probe.headerName),
					Description: probe.desc,
					Severity:    severity.Medium,
				},
			})
			resp.Close()
			return results, nil
		}
		resp.Close()
	}

	return results, nil
}

// checkProtocolConfusion detects if X-Forwarded-Proto: http causes redirect
// behavior changes or strips the Secure flag from Set-Cookie headers.
func checkProtocolConfusion(
	baselineStatus, probeStatus int,
	baselineHasSecureCookie bool,
	probeHeaders string,
	probeLocation string,
) string {
	// Check if the probe triggered a new redirect that the baseline didn't have.
	isBaselineRedirect := baselineStatus >= 300 && baselineStatus < 400
	isProbeRedirect := probeStatus >= 300 && probeStatus < 400

	if !isBaselineRedirect && isProbeRedirect {
		if strings.Contains(strings.ToLower(probeLocation), "https") {
			return fmt.Sprintf("Proto downgrade caused HTTPS redirect (status %d, Location: %s)", probeStatus, probeLocation)
		}
		return fmt.Sprintf("Proto downgrade caused redirect (status %d)", probeStatus)
	}

	// Check if Secure flag disappeared from cookies.
	if baselineHasSecureCookie && !strings.Contains(probeHeaders, "Secure") {
		return "Proto downgrade stripped Secure flag from Set-Cookie header"
	}

	return ""
}

// checkHostInjection detects if X-Forwarded-Host value appears in response
// body or Location header, indicating trusted host generation.
func checkHostInjection(
	probeBody, probeHeaders string,
	probeLocation string,
) string {
	if strings.Contains(probeBody, injectedHost) {
		return fmt.Sprintf("Injected host %q reflected in response body", injectedHost)
	}

	if strings.Contains(probeLocation, injectedHost) {
		return fmt.Sprintf("Injected host %q reflected in Location header: %s", injectedHost, probeLocation)
	}

	if strings.Contains(probeHeaders, injectedHost) {
		return fmt.Sprintf("Injected host %q reflected in response headers", injectedHost)
	}

	return ""
}

// checkIPBypass detects if X-Forwarded-For: 127.0.0.1 causes a different
// response status or significantly different content, indicating IP-based
// access control bypass.
func checkIPBypass(
	baselineStatus, probeStatus int,
	baselineBody, probeBody string,
) string {
	// Status code change suggests access control difference.
	if baselineStatus != probeStatus {
		return fmt.Sprintf("IP spoofing changed response status from %d to %d", baselineStatus, probeStatus)
	}

	// Significant body length difference suggests different content served.
	baseLen := len(baselineBody)
	probeLen := len(probeBody)
	if baseLen > 0 {
		diff := probeLen - baseLen
		if diff < 0 {
			diff = -diff
		}
		// Flag if body length differs by more than 30%.
		threshold := baseLen * 30 / 100
		if threshold < 50 {
			threshold = 50
		}
		if diff > threshold {
			return fmt.Sprintf("IP spoofing caused significant response size change (baseline=%d, probe=%d)", baseLen, probeLen)
		}
	}

	return ""
}

// checkPortInjection detects if X-Forwarded-Port value appears in generated
// URLs within the response body or in redirect Location headers.
func checkPortInjection(
	probeBody string,
	probeLocation string,
) string {
	portPattern := ":" + injectedPort

	if strings.Contains(probeLocation, portPattern) {
		return fmt.Sprintf("Injected port %s reflected in Location header: %s", injectedPort, probeLocation)
	}

	if strings.Contains(probeBody, portPattern) {
		return fmt.Sprintf("Injected port %s reflected in response body URLs", injectedPort)
	}

	return ""
}
