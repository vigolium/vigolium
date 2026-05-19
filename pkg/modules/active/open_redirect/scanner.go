package open_redirect

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/antchfx/htmlquery"
	"github.com/pkg/errors"
	httpUtils "github.com/projectdiscovery/utils/http"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/samber/lo"
	"github.com/vigolium/vigolium/pkg/core/hosterrors"
	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

type Module struct {
	modkit.BaseActiveModule
	rhm                        dedup.Lazy[dedup.RequestHashManager]
	bruteForceDS               dedup.Lazy[dedup.DiskSet]
	maxTimeToBruteForcePerHost int
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
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		rhm: dedup.LazyRHM("open_redirect", dedup.Option{
			Method:                 true,
			Host:                   true,
			InjectingParamName:     true,
			InjectingParamPosition: true,
			AllParamKeys:           true,
		}),
		bruteForceDS:               dedup.LazyDiskSet("open_redirect_bruteforce"),
		maxTimeToBruteForcePerHost: 20,
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	scanCtx *modkit.ScanContext,
) ([]*output.ResultEvent, error) {
	var results []*output.ResultEvent

	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}

	if !infra.IsValidForInjectionVulns(urlx, ctx) {
		return results, nil
	}

	rhm := m.rhm.Get(scanCtx.DedupMgr())

	/* -------------------------------------------------------------------------- */
	/*                          Try with default queries                          */
	/* -------------------------------------------------------------------------- */
	// Create insertion points for URL parameters (uses cached provider when available)
	points, err := scanCtx.GetInsertionPoints(ctx.Request().Raw(), ctx.Request().ID(), false)
	if err != nil {
		return results, errors.Wrap(err, "failed to create insertion points")
	}

	// Filter to URL parameters only
	var urlPoints []httpmsg.InsertionPoint
	for _, ip := range points {
		if ip.Type() == httpmsg.INS_PARAM_URL {
			urlPoints = append(urlPoints, ip)
		}
	}

	// Filter out already checked insertion points
	if rhm != nil {
		urlPoints = rhm.GetNotCheckedInsertionPoints(urlx, ctx.Request(), urlPoints)
	}

	checkedParams := make(map[string]bool)
	if len(urlPoints) > 0 {
		for _, ip := range urlPoints {
			paramValue := ip.BaseValue()

			if !matchTopParams(ip.Name()) && !matchValueIsURL(paramValue) {
				continue
			}
			foundIssues, match, err := checkWithAllModules(ctx.Request().Raw(), ip, urlx, ctx.Service(), httpClient)
			if err == nil && match {
				results = append(results, foundIssues...)
				return results, nil
			}
			if !checkedParams[ip.Name()] {
				checkedParams[ip.Name()] = true
			}
		}
	}

	/* -------------------------------------------------------------------------- */
	/*                  Try with swap method with params in body                  */
	/* -------------------------------------------------------------------------- */
	// Get body parameters
	var bodyPoints []httpmsg.InsertionPoint
	for _, ip := range points {
		if ip.Type() == httpmsg.INS_PARAM_BODY {
			bodyPoints = append(bodyPoints, ip)
		}
	}

	if len(bodyPoints) > 0 {
		newParamNames := []string{}
		for _, ip := range bodyPoints {
			if checkedParams[ip.Name()] {
				continue
			}
			paramValue := ip.BaseValue()
			if !matchTopParams(ip.Name()) && !matchValueIsURL(paramValue) {
				continue
			}
			// we already have the duplicate checking in this, so with the base request, new param will make this unique
			paramType := fmt.Sprintf("%d", ip.Type())
			if rhm != nil && !rhm.ShouldCheckInsertionPoint(urlx, ctx.Request(), ip.Name(), ip.BaseValue(), paramType) {
				continue
			}

			newParamNames = append(newParamNames, ip.Name())
		}
		if len(newParamNames) == 0 {
			return results, nil
		}

		for _, paramName := range newParamNames {
			// Create a new request with the param moved to URL query
			newRaw, err := httpmsg.AppendURLParameter(ctx.Request().Raw(), paramName, "1")
			if err != nil {
				continue
			}

			// Create insertion points for the new request
			newPoints, err := httpmsg.CreateAllInsertionPoints(newRaw, false)
			if err != nil {
				continue
			}

			// Find the insertion point for the param we just added
			var toBeCheckedIP httpmsg.InsertionPoint
			for _, ip := range newPoints {
				if ip.Type() == httpmsg.INS_PARAM_URL && ip.Name() == paramName {
					toBeCheckedIP = ip
					break
				}
			}
			if toBeCheckedIP == nil {
				continue
			}

			foundIssues, match, err := checkWithAllModules(newRaw, toBeCheckedIP, urlx, ctx.Service(), httpClient)
			if err == nil && match {
				results = append(results, foundIssues...)
				return results, nil
			}
		}
	}

	/* ------------------------------------------------------------------------- */
	/*                          Try to using top params                          */
	/* ------------------------------------------------------------------------- */
	bruteForceHash := getBruteForceHash(urlx)
	if bruteForceHash == "" {
		return results, nil
	}
	bruteForceDiskSet := m.bruteForceDS.Get(scanCtx.DedupMgr())
	if bruteForceDiskSet == nil {
		return results, nil
	}
	_, shouldContinue := bruteForceDiskSet.IncrementAndCheck(bruteForceHash, m.maxTimeToBruteForcePerHost)
	if !shouldContinue {
		return results, nil
	}

	foundParams, err := bulkCheck(ctx.Request().Raw(), urlx, ctx.Service(), httpClient, topParams...)
	if err != nil || len(foundParams) == 0 {
		return results, err
	}
	for _, paramName := range foundParams {
		// Create a new request with the param added
		newRaw, err := httpmsg.AppendURLParameter(ctx.Request().Raw(), paramName, "1")
		if err != nil {
			continue
		}

		// Create insertion points for the new request
		newPoints, err := httpmsg.CreateAllInsertionPoints(newRaw, false)
		if err != nil {
			continue
		}

		// Find the insertion point for the param we just added
		var toBeCheckedIP httpmsg.InsertionPoint
		for _, ip := range newPoints {
			if ip.Type() == httpmsg.INS_PARAM_URL && ip.Name() == paramName {
				toBeCheckedIP = ip
				break
			}
		}
		if toBeCheckedIP == nil {
			continue
		}

		foundIssues, match, err := checkWithAllModules(newRaw, toBeCheckedIP, urlx, ctx.Service(), httpClient)
		if err == nil && match {
			results = append(results, foundIssues...)
			return results, nil
		}
	}

	return results, nil
}

func getBruteForceHash(urlx *urlutil.URL) string {
	hash := urlx.Host
	h := sha1.New()
	h.Write([]byte(hash))
	return hex.EncodeToString(h.Sum(nil))
}

func bulkCheck(rawRequest []byte, urlx *urlutil.URL, httpService *httpmsg.Service, httpClient *http.Requester, paramNames ...string) ([]string, error) {
	paramChunks := lo.Chunk(paramNames, 32)
	foundParams := []string{}

	for _, paramChunk := range paramChunks {
		// Build request with multiple params added at once
		modifiedRaw := rawRequest
		var err error
		for _, paramName := range paramChunk {
			paramValue := fmt.Sprintf("https://%s.%s", paramName, urlx.Hostname())
			modifiedRaw, err = httpmsg.AppendURLParameter(modifiedRaw, paramName, paramValue)
			if err != nil {
				continue
			}
		}

		// Parse the modified raw request
		req, err := httpmsg.ParseRawRequest(string(modifiedRaw))
		if err != nil {
			continue
		}
		req.WithService(httpService)

		resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true})
		if err != nil {
			continue
		}
		checkOutput(resp, func(nextLoc string) bool {
			nextLocURL, err := urlutil.Parse(nextLoc)
			if err != nil {
				return true
			}
			paramName := getParamFromURL(nextLocURL.Hostname())
			if paramName == "" {
				return true
			}
			if lo.Contains(paramChunk, paramName) {
				foundParams = append(foundParams, paramName)
				return true
			}
			return false
		})

		resp.Close()
	}
	return foundParams, nil
}

func getParamFromURL(hostname string) string {
	if hostname == "" {
		return ""
	}

	// split by dot, get the first one
	split := strings.Split(hostname, ".")
	if len(split) == 0 {
		return ""
	}
	return split[0]
}

func checkWithAllModules(rawRequest []byte, ip httpmsg.InsertionPoint, urlx *urlutil.URL, httpService *httpmsg.Service, httpClient *http.Requester) (results []*output.ResultEvent, match bool, err error) {
	subdomainResults, match, err := checkRedirectSubdomain(rawRequest, ip, urlx, httpService, httpClient)
	if err == nil && match {
		results = append(results, subdomainResults...)
	}

	differentDomainResults, match, err := checkRedirectDifferentDomain(rawRequest, ip, urlx, httpService, httpClient)
	if err == nil && match {
		results = append(results, differentDomainResults...)
	}

	basedOnParamValueResults, match, err := checkRedirectBasedOnParamValue(rawRequest, ip, urlx, httpService, httpClient)
	if err == nil && match {
		results = append(results, basedOnParamValueResults...)
	}
	if len(results) == 0 {
		return results, false, nil
	}
	return results, true, nil
}

// https://xxx.{target.com}
// \/\/{target.com}
// {target.com}
func checkRedirectSubdomain(rawRequest []byte, ip httpmsg.InsertionPoint, urlx *urlutil.URL, httpService *httpmsg.Service, httpClient *http.Requester) (results []*output.ResultEvent, match bool, err error) {
	match = false
	results = []*output.ResultEvent{}
	hostname := urlx.Hostname()
	mainDomain, err := publicsuffix.Domain(hostname)
	if err != nil {
		return results, false, err
	}
	redirectDomain := fmt.Sprintf("xxx.%s", mainDomain)
	var payloads []string
	payloads = append(payloads, fmt.Sprintf("https://%s", redirectDomain))
	payloads = append(payloads, fmt.Sprintf("//%s", redirectDomain))
	payloads = append(payloads, redirectDomain)

scan:
	for _, payload := range payloads {
		// Build request with payload injected
		fuzzedRaw := ip.BuildRequest([]byte(payload))

		// Parse the fuzzed raw request
		req, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
		if err != nil {
			continue
		}
		req.WithService(httpService)

		resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true})
		if err != nil {
			continue
		}
		checkOutput(resp, func(nextLoc string) bool {
			if getDomainRedirectRegex(redirectDomain).MatchString(nextLoc) {
				results = append(results, &output.ResultEvent{
					URL:              urlx.String(),
					Request:          string(fuzzedRaw),
					Response:         resp.Headers().String(),
					FuzzingParameter: ip.Name(),
					ExtractedResults: []string{payload},
					Info: output.Info{
						Description: "Open redirect to subdomain",
						Severity:    severity.Medium,
					},
				})
				match = true
				return false
			}
			return true
		})
		resp.Close()
		if match {
			break scan
		}
	}
	return results, match, nil
}

func checkRedirectDifferentDomain(rawRequest []byte, ip httpmsg.InsertionPoint, urlx *urlutil.URL, httpService *httpmsg.Service, httpClient *http.Requester) (results []*output.ResultEvent, match bool, err error) {
	match = false
	results = []*output.ResultEvent{}
	redirectDomain := "bttandfriends.com"
	var payloads []string
	payloads = append(payloads, fmt.Sprintf("https://%s", redirectDomain))
	payloads = append(payloads, fmt.Sprintf("//%s", redirectDomain))
	payloads = append(payloads, redirectDomain)
	payloads = append(payloads, fmt.Sprintf(`/\%s`, redirectDomain))
	payloads = append(payloads, fmt.Sprintf("///%s", redirectDomain))

scan:
	for _, payload := range payloads {
		// Build request with payload injected
		fuzzedRaw := ip.BuildRequest([]byte(payload))

		// Parse the fuzzed raw request
		req, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
		if err != nil {
			continue
		}
		req.WithService(httpService)

		resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true})
		if err != nil {
			continue
		}
		checkOutput(resp, func(nextLoc string) bool {
			if getDomainRedirectRegex(redirectDomain).MatchString(nextLoc) {
				results = append(results, &output.ResultEvent{
					URL:              urlx.String(),
					Request:          string(fuzzedRaw),
					Response:         resp.Headers().String(),
					FuzzingParameter: ip.Name(),
					ExtractedResults: []string{payload},
					Info: output.Info{
						Description: "Open redirect to different domain",
						Severity:    severity.High,
					},
				})
				match = true
				return false
			}
			return true
		})

		resp.Close()
		if match {
			break scan
		}
	}
	return results, match, nil
}

func checkRedirectBasedOnParamValue(rawRequest []byte, ip httpmsg.InsertionPoint, urlx *urlutil.URL, httpService *httpmsg.Service, httpClient *http.Requester) (results []*output.ResultEvent, match bool, err error) {
	match = false
	results = []*output.ResultEvent{}

	paramValue := ip.BaseValue()
	if !matchValueIsURL(paramValue) {
		return results, false, nil
	}
	paramURLx, err := urlutil.Parse(paramValue)
	if err != nil {
		return results, false, err
	}
	paramHostname := paramURLx.Hostname()
	paramMainDomain, err := publicsuffix.Domain(paramHostname)
	if err != nil {
		return results, false, err
	}
	differentDomain := "bttandfriends.com"
	nonExistsSubDomain := fmt.Sprintf("xxx.%s", paramMainDomain)
	var payloads []string
	payloads = append(payloads, nonExistsSubDomain)
	payloads = append(payloads, differentDomain)
	payloads = append(payloads, fmt.Sprintf("%s__REPLACE_1__.%s", differentDomain, paramHostname)) // https://bttandfriends.com%ff%40.www.scanme.sh/
	payloads = append(payloads, fmt.Sprintf(`%s#.%s`, differentDomain, paramHostname))             // https://bttandfriends.com%23www.scanme.sh/

	for _, payload := range payloads {
		injectURL := paramURLx.Clone()
		injectURL.Unsafe = true
		injectURL.Host = payload
		finalURL := injectURL.String()
		finalURL = strings.ReplaceAll(finalURL, "__REPLACE_1__", "ÿ@")

		// Build request with payload injected
		fuzzedRaw := ip.BuildRequest([]byte(finalURL))

		// Parse the fuzzed raw request
		req, err := httpmsg.ParseRawRequest(string(fuzzedRaw))
		if err != nil {
			continue
		}
		req.WithService(httpService)

		resp, _, err := httpClient.Execute(req, http.Options{NoRedirects: true, RawRequest: true}) // raw request
		if err != nil {
			if errors.Is(err, hosterrors.ErrUnresponsiveHost) {
				return results, false, nil
			}
			continue
		}
		checkOutput(resp, func(nextLoc string) bool {
			matchDifferentDomain := getDomainRedirectRegex(differentDomain).MatchString(nextLoc)
			matchNonExistsSubDomain := getDomainRedirectRegex(nonExistsSubDomain).MatchString(nextLoc)
			var newSeverity severity.Severity
			var description string
			if matchDifferentDomain {
				newSeverity = severity.High
				description = "Open redirect to different domain"
			} else {
				newSeverity = severity.Medium
				description = "Open redirect to subdomain"
			}
			if matchDifferentDomain || matchNonExistsSubDomain {
				results = append(results, &output.ResultEvent{
					URL:              urlx.String(),
					Request:          string(fuzzedRaw),
					Response:         resp.Headers().String(),
					FuzzingParameter: ip.Name(),
					ExtractedResults: []string{finalURL},
					Info: output.Info{
						Description: description,
						Severity:    newSeverity,
					},
				})
				match = true
				return false
			}
			return true
		})

		resp.Close()

	}
	return results, match, nil
}

var jsRedirectPatterns = []struct {
	pattern *regexp.Regexp
	method  string
}{
	// location='http://evil.com/';
	// location.href='http://evil.com/';
	{regexp.MustCompile(`(?i)location(?:\.href)?\s*=\s*['"]([^'"]+)['"]`), "location or location.href"},
	// location.reload('http://evil.com/');
	// location.replace('http://evil.com/');
	// location.assign('http://evil.com/');
	{regexp.MustCompile(`(?i)location\.(replace|reload|assign)\s*\(\s*['"]([^'"]+)['"]\s*\)`), "location methods (replace, reload, assign)"},
	// window.open('http://evil.com/');
	// window.navigate('http://evil.com/');
	{regexp.MustCompile(`(?i)window\.(open|navigate)\s*\(\s*['"]([^'"]+)['"]\s*\)`), "window methods (open, navigate)"},
	// window.parent.location='http://evil.com/';
	{regexp.MustCompile(`(?i)window\.parent\.location\s*=\s*['"]([^'"]+)['"]`), "window.parent.location"},
}

func checkOutput(respChain *httpUtils.ResponseChain, callback func(nextLoc string) bool) {
	resp := respChain.Response()
	// ! Note: do not check status cod
	var shouldContinue bool

	// (1) Check if redirection by "Location" header
	// http://en.wikipedia.org/wiki/HTTP_location
	// HTTP/1.1 302 Found
	// Location: http://www.example.org/index.php
	locHeader := resp.Header.Get("Location")
	if locHeader != "" {
		shouldContinue = callback(locHeader)
	}
	if !shouldContinue {
		return
	}
	// (2) Check if redirection by "Refresh" header
	// http://en.wikipedia.org/wiki/URL_redirection
	// HTTP/1.1 200 ok
	// Refresh: 0; url=http://www.example.com/
	refreshHeader := resp.Header.Get("Refresh")
	if refreshHeader != "" {
		shouldContinue = callback(refreshHeader)
	}
	if !shouldContinue {
		return
	}
	// (3) Check if redirection occurs by "Meta" content header
	// http://code.google.com/p/html5security/wiki/RedirectionMethods
	// <meta http-equiv="location" content="URL=http://evil.com" />
	// <meta http-equiv="refresh" content="0;url=http://evil.com/" />
	ctHeader := resp.Header.Get("Content-Type")
	if strings.Contains(ctHeader, "/html") {
		html, err := htmlquery.Parse(respChain.Body())
		if err != nil {
			return
		}

		meta := htmlquery.Find(html, "//meta")
		for _, m := range meta {
			if strings.EqualFold(htmlquery.SelectAttr(m, "http-equiv"), "location") {
				content := strings.ToLower(htmlquery.SelectAttr(m, "content"))
				if content == "" {
					continue
				}

				shouldContinue = callback(getLocationUrl(content))
				if !shouldContinue {
					return
				}
			}

			if strings.EqualFold(htmlquery.SelectAttr(m, "http-equiv"), "refresh") {
				content := strings.ToLower(htmlquery.SelectAttr(m, "content"))
				if content == "" {
					continue
				}

				shouldContinue = callback(getRefreshUrl(content))
				if !shouldContinue {
					return
				}
			}
		}
		if !shouldContinue {
			return
		}

		// (4) Check if redirection occurs by Base Tag
		// http://code.google.com/p/html5security/wiki/RedirectionMethods
		// <base href="http://evil.com/" />

		// (5) Check if redirection occurs by Javascript
		// http://code.google.com/p/html5security/wiki/RedirectionMethods
		scripts := htmlquery.Find(html, "//script")
		for _, s := range scripts {
			scriptContent := htmlquery.InnerText(s)
			// Check for JavaScript based redirections
			for _, jsPattern := range jsRedirectPatterns {
				matches := jsPattern.pattern.FindStringSubmatch(scriptContent)
				if len(matches) > 1 {
					url := matches[1]
					shouldContinue = callback(url)
					if !shouldContinue {
						return
					}
				}
			}
		}
	}
}

var refreshPattern = regexp.MustCompile(`(?i)\s*\d+\s*;\s*url\s*=\s*["']?([^"']*)["']?`)

func getRefreshUrl(value string) string {
	matches := refreshPattern.FindStringSubmatch(value)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

var locationPattern = regexp.MustCompile(`(?i)^\s*url\s*=\s*["']?([^"']*)["']?`)

func getLocationUrl(value string) string {
	matches := locationPattern.FindStringSubmatch(value)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func getDomainRedirectRegex(domain string) *regexp.Regexp {
	return regexp.MustCompile(fmt.Sprintf(`(?i)^(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]*)%s\/?(\/|[^.].*)?$`, domain))
}
