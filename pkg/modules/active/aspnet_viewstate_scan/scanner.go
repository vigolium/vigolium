package aspnet_viewstate_scan

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

var (
	viewstateRe      = regexp.MustCompile(`name="__VIEWSTATE"[^>]*value="([^"]*)"`)
	vsGeneratorRe    = regexp.MustCompile(`name="__VIEWSTATEGENERATOR"[^>]*value="([^"]*)"`)
	formActionRe     = regexp.MustCompile(`<form[^>]*action="([^"]*)"[^>]*method="post"`)
	formActionRe2    = regexp.MustCompile(`<form[^>]*method="post"[^>]*action="([^"]*)"`)
	cookielessSessRe = regexp.MustCompile(`/\(S\([a-zA-Z0-9_-]+\)\)/`)
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
			modkit.ScanScopeRequest,
			modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("aspnet_viewstate_scan"),
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

	if !ctx.HasResponse() {
		return nil, nil
	}

	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if !strings.Contains(ct, "text/html") {
		return nil, nil
	}

	body := ctx.Response().BodyToString()

	var results []*output.ResultEvent

	// Check for cookieless sessions in URL or response body
	urlx, err := ctx.URL()
	if err != nil {
		return nil, nil
	}

	if cookielessSessRe.MatchString(urlx.String()) || cookielessSessRe.MatchString(body) {
		results = append(results, &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     host,
			URL:      urlx.String(),
			Matched:  urlx.String(),
			ExtractedResults: []string{
				"Cookieless session token detected in URL",
			},
			Info: output.Info{
				Name:        "ASP.NET Cookieless Session Detected",
				Description: "The application uses cookieless sessions, embedding session tokens directly in URLs. This exposes session IDs in browser history, referrer headers, and logs.",
				Severity:    severity.Medium,
				Confidence:  severity.Certain,
				Tags:        []string{"aspnet", "session", "cookieless", "information-disclosure"},
				Reference:   []string{"https://learn.microsoft.com/en-us/dotnet/api/system.web.httpcookiemode"},
			},
		})
	}

	// Need ViewState for remaining tests
	vsMatch := viewstateRe.FindStringSubmatch(body)
	if len(vsMatch) < 2 || len(vsMatch[1]) < 20 {
		return results, nil
	}

	vsValue := vsMatch[1]

	// Determine form action URL
	formAction := urlx.Path
	if m := formActionRe.FindStringSubmatch(body); len(m) > 1 {
		formAction = m[1]
	} else if m := formActionRe2.FindStringSubmatch(body); len(m) > 1 {
		formAction = m[1]
	}

	// Test 1: ViewState MAC disabled
	if result := m.testMACDisabled(ctx, httpClient, vsValue, formAction); result != nil {
		results = append(results, result)
	}

	// Test 2: Event validation disabled
	if result := m.testEventValidationDisabled(ctx, httpClient, vsValue, formAction, body); result != nil {
		results = append(results, result)
	}

	return results, nil
}

func (m *Module) testMACDisabled(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	vsValue string,
	formAction string,
) *output.ResultEvent {
	// Tamper ViewState by bitflipping middle bytes
	decoded, err := base64.StdEncoding.DecodeString(vsValue)
	if err != nil || len(decoded) < 10 {
		return nil
	}

	// Bitflip bytes in the middle of the ViewState
	tampered := make([]byte, len(decoded))
	copy(tampered, decoded)
	mid := len(tampered) / 2
	tampered[mid] ^= 0xFF
	tampered[mid+1] ^= 0xFF
	if mid+2 < len(tampered) {
		tampered[mid+2] ^= 0xFF
	}
	tamperedVS := base64.StdEncoding.EncodeToString(tampered)

	// Build POST body
	postBody := url.Values{
		"__VIEWSTATE": {tamperedVS},
	}.Encode()

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "POST")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, formAction)
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetBody(modifiedRaw, []byte(postBody))
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "Content-Type", "application/x-www-form-urlencoded")
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

	respBody := resp.Body().String()
	status := resp.Response().StatusCode

	// If we get MAC failure error, MAC is enabled (good)
	macFailMarkers := []string{
		"Validation of viewstate MAC failed",
		"The state information is invalid for this page",
		"Invalid viewstate",
	}
	for _, marker := range macFailMarkers {
		if strings.Contains(respBody, marker) {
			// Check if verbose error is disclosed (secondary finding)
			if strings.Contains(respBody, "Stack Trace:") || strings.Contains(respBody, "StackTrace") {
				urlx, _ := ctx.URL()
				return &output.ResultEvent{
					ModuleID: ModuleID,
					Host:     urlx.Host,
					URL:      urlx.Scheme + "://" + urlx.Host + formAction,
					Matched:  urlx.Scheme + "://" + urlx.Host + formAction,
					Request:  string(modifiedRaw),
					Response: resp.FullResponse().String(),
					ExtractedResults: []string{
						"Verbose ViewState MAC error with stack trace",
					},
					Info: output.Info{
						Name:        "ASP.NET Verbose ViewState Error",
						Description: "ViewState MAC validation fails with verbose error information including stack traces, revealing internal application details.",
						Severity:    severity.Medium,
						Confidence:  severity.Firm,
						Tags:        []string{"aspnet", "viewstate", "verbose-error", "information-disclosure"},
						Reference:   []string{"https://learn.microsoft.com/en-us/previous-versions/aspnet/bb386448(v=vs.100)"},
					},
				}
			}
			return nil // MAC is enabled, no finding
		}
	}

	// If status is 200 and no MAC error, MAC may be disabled
	if status == 200 && !strings.Contains(respBody, "Error") && len(respBody) > 100 {
		urlx, _ := ctx.URL()
		return &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     urlx.Host,
			URL:      urlx.Scheme + "://" + urlx.Host + formAction,
			Matched:  urlx.Scheme + "://" + urlx.Host + formAction,
			Request:  string(modifiedRaw),
			Response: resp.FullResponse().String(),
			ExtractedResults: []string{
				"Tampered ViewState accepted without MAC validation error",
			},
			Info: output.Info{
				Name:        "ASP.NET ViewState MAC Disabled",
				Description: "The application accepted a tampered ViewState without MAC validation, indicating EnableViewStateMac is set to false. This allows ViewState deserialization attacks.",
				Severity:    severity.High,
				Confidence:  severity.Firm,
				Tags:        []string{"aspnet", "viewstate", "mac-disabled", "deserialization"},
				Reference:   []string{"https://learn.microsoft.com/en-us/previous-versions/aspnet/bb386448(v=vs.100)"},
			},
		}
	}

	return nil
}

func (m *Module) testEventValidationDisabled(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	vsValue string,
	formAction string,
	body string,
) *output.ResultEvent {
	// Extract ViewStateGenerator and EventValidation if present
	vsGen := ""
	if m := vsGeneratorRe.FindStringSubmatch(body); len(m) > 1 {
		vsGen = m[1]
	}

	// Build POST with forged EVENTTARGET
	formValues := url.Values{
		"__VIEWSTATE":     {vsValue},
		"__EVENTTARGET":   {"FakeControl123"},
		"__EVENTARGUMENT": {"test"},
	}
	if vsGen != "" {
		formValues.Set("__VIEWSTATEGENERATOR", vsGen)
	}
	// Intentionally omit __EVENTVALIDATION

	postBody := formValues.Encode()

	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "POST")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, formAction)
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetBody(modifiedRaw, []byte(postBody))
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "Content-Type", "application/x-www-form-urlencoded")
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

	respBody := resp.Body().String()
	status := resp.Response().StatusCode

	// If event validation is enabled, we should see an error
	eventValFailMarkers := []string{
		"Invalid postback or callback argument",
		"Event validation is enabled",
	}
	for _, marker := range eventValFailMarkers {
		if strings.Contains(respBody, marker) {
			return nil // Event validation is enabled (good)
		}
	}

	// If status 200 and no validation error, event validation may be disabled
	if status == 200 && len(respBody) > 100 {
		urlx, _ := ctx.URL()
		return &output.ResultEvent{
			ModuleID: ModuleID,
			Host:     urlx.Host,
			URL:      urlx.Scheme + "://" + urlx.Host + formAction,
			Matched:  urlx.Scheme + "://" + urlx.Host + formAction,
			Request:  string(modifiedRaw),
			Response: resp.FullResponse().String(),
			ExtractedResults: []string{
				"Forged __EVENTTARGET=FakeControl123 accepted without validation error",
			},
			Info: output.Info{
				Name:        "ASP.NET Event Validation Disabled",
				Description: "The application accepted a forged event target without event validation, indicating EnableEventValidation is disabled. This may allow parameter tampering and unauthorized control invocation.",
				Severity:    severity.Medium,
				Confidence:  severity.Firm,
				Tags:        []string{"aspnet", "viewstate", "event-validation", "tampering"},
				Reference:   []string{"https://learn.microsoft.com/en-us/dotnet/api/system.web.ui.page.enableeventvalidation"},
			},
		}
	}

	return nil
}
