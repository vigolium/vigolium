package aspnet_viewstate_scan

import (
	"encoding/base64"
	"fmt"
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
	viewstateRe       = regexp.MustCompile(`name="__VIEWSTATE"[^>]*value="([^"]*)"`)
	vsGeneratorRe     = regexp.MustCompile(`name="__VIEWSTATEGENERATOR"[^>]*value="([^"]*)"`)
	eventValidationRe = regexp.MustCompile(`name="__EVENTVALIDATION"[^>]*value="([^"]*)"`)
	postbackTargetRe  = regexp.MustCompile(`(?i)__doPostBack\(\s*['"]([^'"]+)['"]`)
	formActionRe      = regexp.MustCompile(`<form[^>]*action="([^"]*)"[^>]*method="post"`)
	formActionRe2     = regexp.MustCompile(`<form[^>]*method="post"[^>]*action="([^"]*)"`)
	cookielessSessRe  = regexp.MustCompile(`/\(S\([a-zA-Z0-9_-]+\)\)/`)
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
	if result := m.testMACDisabled(ctx, httpClient, vsValue, formAction, body); result != nil {
		results = append(results, result)
	}

	// Event validation cannot be confirmed merely because an unknown target gets
	// a 200; WebForms often ignores unknown events and renders the same page. Keep
	// only the configuration-level candidate when a real postback target exists
	// but the page emits no __EVENTVALIDATION field.
	if result := eventValidationCandidate(ctx, body); result != nil {
		results = append(results, result)
	}

	return results, nil
}

func (m *Module) testMACDisabled(
	ctx *httpmsg.HttpRequestResponse,
	httpClient *http.Requester,
	vsValue string,
	formAction string,
	body string,
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

	baseValues := hiddenStateValues(body)
	baseValues.Set("__VIEWSTATE", vsValue)
	valid := m.postForm(ctx, httpClient, formAction, baseValues)
	if valid == nil || !normalWebFormsResponse(valid) {
		return nil
	}

	tamperedValues := cloneValues(baseValues)
	tamperedValues.Set("__VIEWSTATE", tamperedVS)
	tamperedProbe := m.postForm(ctx, httpClient, formAction, tamperedValues)
	if tamperedProbe == nil {
		return nil
	}

	if containsViewStateRejection(tamperedProbe.body) {
		if containsStackTrace(tamperedProbe.body) {
			urlx, _ := ctx.URL()
			return &output.ResultEvent{
				ModuleID:      ModuleID,
				Host:          urlx.Host,
				URL:           urlx.Scheme + "://" + urlx.Host + formAction,
				Matched:       urlx.Scheme + "://" + urlx.Host + formAction,
				Request:       tamperedProbe.request,
				Response:      tamperedProbe.response,
				RecordKind:    output.RecordKindFinding,
				EvidenceGrade: output.EvidenceGradeImpact,
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
		return nil
	}

	if !normalWebFormsResponse(tamperedProbe) || !modkit.BodiesSimilar(valid.body, tamperedProbe.body) {
		return nil
	}

	malformedValues := cloneValues(baseValues)
	malformedValues.Set("__VIEWSTATE", "not-base64-"+strings.Repeat("!", 24))
	malformed := m.postForm(ctx, httpClient, formAction, malformedValues)
	if malformed == nil || !probeRejectedOrDistinct(valid, malformed) {
		return nil
	}

	urlx, _ := ctx.URL()
	return &output.ResultEvent{
		ModuleID:           ModuleID,
		Host:               urlx.Host,
		URL:                urlx.Scheme + "://" + urlx.Host + formAction,
		Matched:            urlx.Scheme + "://" + urlx.Host + formAction,
		Request:            tamperedProbe.request,
		Response:           tamperedProbe.response,
		AdditionalEvidence: []string{valid.request, valid.response, malformed.request, malformed.response},
		RecordKind:         output.RecordKindCandidate,
		EvidenceGrade:      output.EvidenceGradeDifferential,
		ExtractedResults: []string{
			"Valid and bit-flipped ViewState produced equivalent processed WebForms responses",
			"Malformed non-base64 control was rejected or produced a distinct response",
		},
		Info: output.Info{
			Name:        "ASP.NET ViewState Integrity Validation Candidate",
			Description: "A bit-flipped, syntactically valid ViewState was processed like the valid control while a malformed control was rejected. This differential suggests missing integrity validation, but a semantic state change or safe deserialization proof is required before treating it as confirmed exploitation.",
			Severity:    severity.High,
			Confidence:  severity.Firm,
			Tags:        []string{"aspnet", "viewstate", "mac-disabled", "deserialization"},
			Reference:   []string{"https://learn.microsoft.com/en-us/previous-versions/aspnet/bb386448(v=vs.100)"},
		},
	}
}

type formProbe struct {
	status   int
	body     string
	request  string
	response string
}

func (m *Module) postForm(ctx *httpmsg.HttpRequestResponse, client *http.Requester, action string, values url.Values) *formProbe {
	modifiedRaw, err := httpmsg.SetMethod(ctx.Request().Raw(), "POST")
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetPath(modifiedRaw, action)
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.SetBody(modifiedRaw, []byte(values.Encode()))
	if err != nil {
		return nil
	}
	modifiedRaw, err = httpmsg.AddOrReplaceHeader(modifiedRaw, "Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return nil
	}
	request := httpmsg.NewRequestResponseRaw(modifiedRaw, ctx.Service())
	resp, _, err := client.Execute(request, http.Options{NoClustering: true})
	if err != nil {
		return nil
	}
	defer resp.Close()
	if resp.Response() == nil {
		return nil
	}
	return &formProbe{
		status:   resp.Response().StatusCode,
		body:     resp.Body().String(),
		request:  string(modifiedRaw),
		response: resp.FullResponseString(),
	}
}

func hiddenStateValues(body string) url.Values {
	values := make(url.Values)
	for name, re := range map[string]*regexp.Regexp{
		"__VIEWSTATEGENERATOR": vsGeneratorRe,
		"__EVENTVALIDATION":    eventValidationRe,
	} {
		if match := re.FindStringSubmatch(body); len(match) > 1 {
			values.Set(name, match[1])
		}
	}
	return values
}

func cloneValues(values url.Values) url.Values {
	clone := make(url.Values, len(values))
	for key, entries := range values {
		clone[key] = append([]string(nil), entries...)
	}
	return clone
}

func normalWebFormsResponse(probe *formProbe) bool {
	return probe != nil && probe.status >= 200 && probe.status < 300 && viewstateRe.MatchString(probe.body) && !containsViewStateRejection(probe.body)
}

func containsViewStateRejection(body string) bool {
	lower := strings.ToLower(body)
	for _, marker := range []string{
		"validation of viewstate mac failed", "state information is invalid",
		"invalid viewstate", "viewstate is invalid", "failed to load viewstate",
		"viewstateexception", "invalid postback or callback argument",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func containsStackTrace(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "stack trace:") || strings.Contains(lower, "stacktrace") || strings.Contains(lower, "system.web.")
}

func probeRejectedOrDistinct(valid, control *formProbe) bool {
	if control.status < 200 || control.status >= 300 || containsViewStateRejection(control.body) || !viewstateRe.MatchString(control.body) {
		return true
	}
	return !modkit.BodiesSimilar(valid.body, control.body)
}

func eventValidationCandidate(ctx *httpmsg.HttpRequestResponse, body string) *output.ResultEvent {
	if eventValidationRe.MatchString(body) {
		return nil
	}
	match := postbackTargetRe.FindStringSubmatch(body)
	if len(match) < 2 {
		return nil
	}
	urlx, err := ctx.URL()
	if err != nil {
		return nil
	}
	return &output.ResultEvent{
		ModuleID:      ModuleID,
		Host:          urlx.Host,
		URL:           urlx.String(),
		Matched:       urlx.String(),
		RecordKind:    output.RecordKindCandidate,
		EvidenceGrade: output.EvidenceGradeCandidate,
		ExtractedResults: []string{
			fmt.Sprintf("real_postback_target=%s", match[1]),
			"__EVENTVALIDATION field absent",
		},
		Info: output.Info{
			Name:        "ASP.NET Event Validation Configuration Candidate",
			Description: "The page exposes a real __doPostBack target but does not emit __EVENTVALIDATION. This is configuration evidence only; a safe target-specific effect comparison is required to confirm exploitable parameter tampering.",
			Severity:    severity.Medium,
			Confidence:  severity.Firm,
			Tags:        []string{"aspnet", "viewstate", "event-validation", "tampering"},
			Reference:   []string{"https://learn.microsoft.com/en-us/dotnet/api/system.web.ui.page.enableeventvalidation"},
		},
	}
}
