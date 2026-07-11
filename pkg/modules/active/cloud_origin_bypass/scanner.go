package cloud_origin_bypass

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

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
		ds: dedup.LazyDiskSet("cloud_origin_bypass"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) IncludesBaseCanProcess() bool { return false }

func (m *Module) CanProcess(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Request() == nil || ctx.Response() == nil {
		return false
	}
	return true
}

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
	diskSet := m.ds.Get(scanCtx.DedupMgr())
	if diskSet != nil && diskSet.IsSeen(host) {
		return nil, nil
	}

	// Step 1: Check if CDN is present
	if !isCDNPresent(ctx) {
		return nil, nil
	}

	// Collect CDN security headers
	cdnSecHeaders := collectSecurityHeaders(ctx)

	// Step 2: Extract origin storage URLs from response body
	body := ctx.Response().BodyToString()
	if len(body) == 0 || len(body) > 2<<20 {
		return nil, nil
	}

	originURLs := extractOriginURLs(body)
	if len(originURLs) == 0 {
		return nil, nil
	}

	// Deduplicate origin hosts
	seen := make(map[string]bool)
	var uniqueOrigins []string
	for _, u := range originURLs {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		originHost := parsed.Host
		if !seen[originHost] {
			seen[originHost] = true
			uniqueOrigins = append(uniqueOrigins, u)
		}
	}

	// Cap at 5 origins to avoid excessive requests
	if len(uniqueOrigins) > 5 {
		uniqueOrigins = uniqueOrigins[:5]
	}

	var results []*output.ResultEvent

	// Step 3: Fetch each origin and compare security headers
	for _, originURL := range uniqueOrigins {
		result := m.checkOrigin(ctx, httpClient, originURL, cdnSecHeaders, host)
		if result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

func isCDNPresent(ctx *httpmsg.HttpRequestResponse) bool {
	for _, h := range cdnHeaders {
		if ctx.Response().Header(h) != "" {
			return true
		}
	}
	via := strings.ToLower(ctx.Response().Header("Via"))
	if via != "" {
		for _, pattern := range cdnViaPatterns {
			if strings.Contains(via, strings.ToLower(pattern)) {
				return true
			}
		}
	}
	return false
}

func collectSecurityHeaders(ctx *httpmsg.HttpRequestResponse) map[string]string {
	headers := make(map[string]string)
	for _, h := range securityHeaders {
		val := ctx.Response().Header(h)
		if val != "" {
			headers[h] = val
		}
	}
	return headers
}

func extractOriginURLs(body string) []string {
	seen := make(map[string]bool)
	var urls []string
	for _, re := range originURLPatterns {
		matches := re.FindAllString(body, 10)
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				urls = append(urls, m)
			}
		}
	}
	return urls
}

func (m *Module) checkOrigin(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	originURL string,
	cdnSecHeaders map[string]string,
	cdnHost string,
) *output.ResultEvent {
	parsed, err := url.Parse(originURL)
	if err != nil {
		return nil
	}

	path := parsed.Path
	if path == "" {
		path = "/"
	}

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "GET")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, path)
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "Host", parsed.Host)
	if err != nil {
		return nil
	}

	useHTTPS := parsed.Scheme == "https"
	port := 443
	if !useHTTPS {
		port = 80
	}
	originService := httpmsg.NewServiceSecure(parsed.Host, port, useHTTPS)
	// SetMethod/SetPath/AddOrReplaceHeader produce well-formed raw, so wrap
	// directly instead of re-parsing on this hot path.
	fuzzedReq := httpmsg.NewRequestResponseRaw(modifiedRaw, originService)

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil || resp.Response().StatusCode >= 400 {
		return nil
	}

	// Compare security headers
	var missingHeaders []string
	for _, h := range securityHeaders {
		if _, hasCDN := cdnSecHeaders[h]; hasCDN {
			originVal := resp.Response().Header.Get(h)
			if originVal == "" {
				missingHeaders = append(missingHeaders, h)
			}
		}
	}

	if len(missingHeaders) == 0 {
		return nil
	}

	target := ctx.Target()
	evidence := []string{
		fmt.Sprintf("CDN Host: %s", cdnHost),
		fmt.Sprintf("Origin URL: %s", originURL),
		fmt.Sprintf("Missing headers at origin: %s", strings.Join(missingHeaders, ", ")),
	}

	return &output.ResultEvent{
		URL:     target,
		Matched: target,
		Request: string(modifiedRaw),
		// The full raw origin response is the proof (it's the request that reached
		// the origin directly and is missing the CDN's security headers). resp is
		// still open here (deferred Close), so capture it as the finding's response
		// rather than letting the executor backfill an unrelated baseline.
		Response:         resp.FullResponseString(),
		ExtractedResults: evidence,
		Info: output.Info{
			Name:        "Cloud Origin Bypass: Missing Security Headers",
			Description: fmt.Sprintf("Cloud storage origin %s is directly reachable and missing %d security header(s) present on CDN: %s", parsed.Host, len(missingHeaders), strings.Join(missingHeaders, ", ")),
			Severity:    severity.Medium,
			Confidence:  severity.Firm,
			Tags:        []string{"cloud-storage", "cdn-bypass", "security-headers"},
			Reference:   []string{"https://owasp.org/www-project-web-security-testing-guide/"},
		},
	}
}
