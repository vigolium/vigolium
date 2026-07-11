package jsonp_callback

import (
	"encoding/json"
	"fmt"
	stdhttp "net/http"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"github.com/vigolium/vigolium/pkg/dedup"
	vighttp "github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
	"github.com/vigolium/vigolium/pkg/utils"
)

var callbackParamNames = []string{"callback", "cb", "jsonp", "jsonpcallback", "func", "_callback", "handler"}

var callbackNamePattern = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$`)

var credentialHeaders = []string{
	"Authorization", "Proxy-Authorization", "Cookie", "X-API-Key", "Api-Key",
	"X-Api-Token", "X-Auth-Token", "X-Access-Token", "X-Session-Token",
}

type jsonpDocument struct {
	callback string
	value    any
}

type jsonpCapture struct {
	document   jsonpDocument
	status     int
	ctype      string
	nosniff    bool
	blocked    bool
	request    string
	response   string
	body       string
	executable bool
}

// Module implements the JSONP Callback Injection active scanner.
type Module struct {
	modkit.BaseActiveModule
	ds dedup.Lazy[dedup.DiskSet]
}

func New() *Module {
	m := &Module{
		BaseActiveModule: modkit.NewBaseActiveModule(
			ModuleID, ModuleName, ModuleDesc, ModuleShort, ModuleConfirmation,
			ModuleSeverity, ModuleConfidence,
			modkit.ScanScopeRequest, modkit.AllInsertionPointTypes,
		),
		ds: dedup.LazyDiskSet("jsonp_callback"),
	}
	m.ModuleTags = ModuleTags
	return m
}

func (m *Module) ScanPerRequest(ctx *httpmsg.HttpRequestResponse, httpClient *vighttp.Requester, scanCtx *modkit.ScanContext) ([]*output.ResultEvent, error) {
	if ctx == nil || ctx.Request() == nil || ctx.Response() == nil || httpClient == nil {
		return nil, nil
	}
	urlx, err := ctx.URL()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get URL")
	}
	if !isJSONLikeResponse(ctx) {
		return nil, nil
	}
	if scanCtx != nil {
		dedupKey := utils.Sha1(fmt.Sprintf("%s:%s", urlx.Host, urlx.Path))
		diskSet := m.ds.Get(scanCtx.DedupMgr())
		if diskSet != nil && diskSet.IsSeen(dedupKey) {
			return nil, nil
		}
	}

	// Existing JSONP is checked before the callback-parameter gate. Previously a
	// normal ?callback= URL was skipped before its already-wrapped response could
	// be classified at all.
	if document, ok := parseJSONP(ctx.Response().BodyToString()); ok {
		capture := captureFromObserved(ctx, document)
		// GET JSONP should reproduce once; a non-GET response is retained only as
		// an observation because a cross-origin script element cannot replay POST.
		if strings.EqualFold(ctx.Request().Method(), "GET") {
			confirmation, probeErr := m.execute(ctx, httpClient, ctx.Request().Raw())
			if probeErr != nil || confirmation.document.callback != document.callback {
				return nil, nil
			}
			stableSensitive := intersectStrings(sensitiveEvidence(document.value), sensitiveEvidence(confirmation.document.value))
			anonymous, anonymousRejected := m.confirmAnonymousLacksSensitive(ctx, httpClient, ctx.Request().Raw(), stableSensitive)
			return []*output.ResultEvent{m.result(urlx.String(), "", false, capture, confirmation, anonymous, anonymousRejected, stableSensitive, crossSiteSessionCookieKnown(ctx, scanCtx))}, nil
		}
		stableSensitive := sensitiveEvidence(document.value)
		return []*output.ResultEvent{m.result(urlx.String(), "", false, capture, capture, nil, false, stableSensitive, false)}, nil
	}

	if !strings.EqualFold(ctx.Request().Method(), "GET") || hasCallbackParameter(ctx.Request().Raw()) {
		return nil, nil
	}

	for _, paramName := range callbackParamNames {
		first, second, ok := m.confirmDynamicCallback(ctx, httpClient, paramName)
		if !ok {
			continue
		}
		stableSensitive := intersectStrings(sensitiveEvidence(first.document.value), sensitiveEvidence(second.document.value))
		anonymous, anonymousRejected := m.confirmAnonymousLacksSensitive(ctx, httpClient, first.requestBytes(), stableSensitive)
		return []*output.ResultEvent{m.result(urlx.String(), paramName, true, first, second, anonymous, anonymousRejected, stableSensitive, crossSiteSessionCookieKnown(ctx, scanCtx))}, nil
	}
	return nil, nil
}

func (capture jsonpCapture) requestBytes() []byte { return []byte(capture.request) }

func (m *Module) confirmDynamicCallback(ctx *httpmsg.HttpRequestResponse, client *vighttp.Requester, paramName string) (jsonpCapture, jsonpCapture, bool) {
	var captures [2]jsonpCapture
	for i := range captures {
		callback := modkit.FreshCanary()
		raw := utils.AppendToQuery(ctx.Request().Raw(), paramName+"="+callback)
		capture, err := m.execute(ctx, client, raw)
		if err != nil || capture.document.callback != callback {
			return jsonpCapture{}, jsonpCapture{}, false
		}
		captures[i] = capture
	}
	return captures[0], captures[1], true
}

func (m *Module) execute(ctx *httpmsg.HttpRequestResponse, client *vighttp.Requester, raw []byte) (jsonpCapture, error) {
	req := httpmsg.NewRequestResponseRaw(raw, ctx.Service())
	resp, _, err := client.Execute(req, vighttp.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return jsonpCapture{}, err
	}
	defer resp.Close()
	if resp.Response() == nil {
		return jsonpCapture{}, nil
	}
	body := strings.TrimSpace(resp.BodyString())
	document, _ := parseJSONP(body)
	capture := jsonpCapture{
		document: document,
		status:   resp.Response().StatusCode,
		ctype:    resp.Response().Header.Get("Content-Type"),
		nosniff:  strings.EqualFold(strings.TrimSpace(resp.Response().Header.Get("X-Content-Type-Options")), "nosniff"),
		blocked:  infra.IsBlockedResponse(resp),
		request:  string(raw),
		response: resp.FullResponseString(),
		body:     body,
	}
	capture.executable = browserExecutableJSONP(capture.ctype, capture.nosniff, resp.Response().Header.Get("Content-Disposition"))
	if capture.blocked || capture.status < 200 || capture.status >= 300 {
		capture.document = jsonpDocument{}
	}
	return capture, nil
}

func captureFromObserved(ctx *httpmsg.HttpRequestResponse, document jsonpDocument) jsonpCapture {
	ctype := ctx.Response().Header("Content-Type")
	nosniff := strings.EqualFold(strings.TrimSpace(ctx.Response().Header("X-Content-Type-Options")), "nosniff")
	return jsonpCapture{
		document:   document,
		status:     ctx.Response().StatusCode(),
		ctype:      ctype,
		nosniff:    nosniff,
		request:    string(ctx.Request().Raw()),
		response:   string(ctx.Response().Raw()),
		body:       strings.TrimSpace(ctx.Response().BodyToString()),
		executable: browserExecutableJSONP(ctype, nosniff, ctx.Response().Header("Content-Disposition")),
	}
}

// confirmAnonymousLacksSensitive is an authorization control, not a generic
// network-failure oracle. Both rounds must explicitly reject (401/403) or return
// a successful response without any of the sensitive paths seen credentialed.
func (m *Module) confirmAnonymousLacksSensitive(ctx *httpmsg.HttpRequestResponse, client *vighttp.Requester, raw []byte, sensitive []string) ([]jsonpCapture, bool) {
	if len(sensitive) == 0 {
		return nil, false
	}
	anonymous, err := client.CloneWithoutCredentials()
	if err != nil {
		return nil, false
	}
	clean, err := stripCredentials(raw)
	if err != nil {
		return nil, false
	}
	var captures []jsonpCapture
	for i := 0; i < 2; i++ {
		capture, probeErr := m.execute(ctx, anonymous, clean)
		if probeErr != nil || capture.status == 0 || capture.status >= 500 {
			return nil, false
		}
		negative := capture.status == stdhttp.StatusUnauthorized || capture.status == stdhttp.StatusForbidden
		if capture.status >= 200 && capture.status < 300 {
			negative = !hasAnyString(sensitiveEvidence(capture.document.value), sensitive)
		}
		if !negative {
			return nil, false
		}
		captures = append(captures, capture)
	}
	return captures, true
}

func (m *Module) result(target, param string, dynamic bool, first, second jsonpCapture, anonymous []jsonpCapture, anonymousRejected bool, sensitive []string, crossSiteCookie bool) *output.ResultEvent {
	kind := output.RecordKindObservation
	grade := output.EvidenceGradeObservation
	sev := severity.Info
	name := "JSONP Response Observed"
	description := "The endpoint returned a valid JSON value wrapped in a JavaScript callback. JSONP may be intentional for public data; callback wrapping alone does not establish cross-origin theft of authenticated information."
	if dynamic {
		name = "Dynamic JSONP Callback Support Observed"
		description = "Two fresh callback identifiers were each returned as exact wrappers around valid JSON. This confirms dynamic JSONP support, not arbitrary JavaScript injection or sensitive cross-origin data access."
	}
	if len(sensitive) > 0 && first.executable {
		kind = output.RecordKindCandidate
		grade = output.EvidenceGradeDifferential
		sev = severity.High
		name = "Sensitive JSONP Data Exposure Candidate"
		description = "The browser-executable JSONP payload reproducibly contained non-empty sensitive-looking values. Public JSONP may still be intentional; authenticated cross-origin access was not proven."
	}
	if len(sensitive) > 0 && (!first.executable || !second.executable) {
		description = "The endpoint wrapped non-empty sensitive-looking values in JSONP syntax, but its MIME/nosniff or disposition policy did not provide a confirmed browser-executable script response. This remains an observation."
	}
	if len(sensitive) > 0 && first.executable && second.executable && crossSiteCookie && anonymousRejected {
		kind = output.RecordKindFinding
		grade = output.EvidenceGradeImpact
		sev = severity.High
		name = "Credentialed Sensitive JSONP Exposure Confirmed"
		description = "A browser-executable JSONP response returned sensitive values with a known SameSite=None; Secure session cookie, while two isolated credential-free controls did not. This confirms credential-dependent cross-origin script-readable data exposure."
	}

	additional := []string{output.BuildEvidence("fresh callback confirmation", second.request, second.response)}
	for i, control := range anonymous {
		additional = append(additional, output.BuildEvidence(fmt.Sprintf("credential-free control %d", i+1), control.request, control.response))
	}
	extracted := []string{
		fmt.Sprintf("Dynamic callback parameter: %t", dynamic),
		"Callback: " + first.document.callback,
		fmt.Sprintf("Browser-executable response: %t", first.executable && second.executable),
		"Sensitive value paths: " + strings.Join(sensitive, ", "),
	}
	if param != "" {
		extracted = append(extracted, "Callback parameter: "+param)
	}

	return &output.ResultEvent{
		ModuleID:           ModuleID,
		RecordKind:         kind,
		EvidenceGrade:      grade,
		URL:                target,
		Matched:            target,
		Request:            first.request,
		Response:           first.response,
		AdditionalEvidence: additional,
		FuzzingParameter:   param,
		ExtractedResults:   extracted,
		Info: output.Info{
			Name:        name,
			Description: description,
			Severity:    sev,
			Confidence:  ModuleConfidence,
			Tags:        ModuleTags,
			Reference:   []string{"https://owasp.org/www-community/attacks/Cross_Site_Script_Inclusion"},
		},
		Metadata: map[string]any{
			"valid_json_argument":           true,
			"fresh_callback_rounds":         map[bool]int{true: 2, false: 1}[dynamic],
			"browser_executable":            first.executable && second.executable,
			"sensitive_value_paths":         sensitive,
			"cross_site_session_cookie":     crossSiteCookie,
			"credential_free_control_clean": anonymousRejected,
		},
	}
}

func parseJSONP(body string) (jsonpDocument, bool) {
	trimmed := strings.TrimSpace(body)
	trimmed = strings.TrimSuffix(trimmed, ";")
	trimmed = strings.TrimSpace(trimmed)
	open := strings.IndexByte(trimmed, '(')
	if open <= 0 || !strings.HasSuffix(trimmed, ")") {
		return jsonpDocument{}, false
	}
	callback := strings.TrimSpace(trimmed[:open])
	if !callbackNamePattern.MatchString(callback) {
		return jsonpDocument{}, false
	}
	payload := strings.TrimSpace(trimmed[open+1 : len(trimmed)-1])
	if !json.Valid([]byte(payload)) {
		return jsonpDocument{}, false
	}
	var value any
	if json.Unmarshal([]byte(payload), &value) != nil {
		return jsonpDocument{}, false
	}
	switch value.(type) {
	case map[string]any, []any:
		return jsonpDocument{callback: callback, value: value}, true
	default:
		return jsonpDocument{}, false
	}
}

func isJSONLikeResponse(ctx *httpmsg.HttpRequestResponse) bool {
	if ctx == nil || ctx.Response() == nil {
		return false
	}
	ct := strings.ToLower(ctx.Response().Header("Content-Type"))
	if strings.Contains(ct, "json") || strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") {
		return true
	}
	body := strings.TrimSpace(ctx.Response().BodyToString())
	if json.Valid([]byte(body)) {
		return true
	}
	_, ok := parseJSONP(body)
	return ok
}

func hasCallbackParameter(raw []byte) bool {
	for _, name := range callbackParamNames {
		has, err := httpmsg.HasURLParameter(raw, name)
		if err == nil && has {
			return true
		}
	}
	return false
}

func browserExecutableJSONP(contentType string, nosniff bool, disposition string) bool {
	if strings.Contains(strings.ToLower(disposition), "attachment") {
		return false
	}
	ct := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	javascript := strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript")
	if javascript {
		return true
	}
	return !nosniff
}

func sensitiveEvidence(value any) []string {
	seen := map[string]bool{}
	var evidence []string
	var walk func(any, string)
	walk = func(current any, path string) {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				childPath := key
				if path != "" {
					childPath = path + "." + key
				}
				if sensitiveValue(key, child) && !seen[childPath] {
					seen[childPath] = true
					evidence = append(evidence, childPath)
				}
				walk(child, childPath)
			}
		case []any:
			for _, child := range typed {
				walk(child, path+"[]")
			}
		}
	}
	walk(value, "")
	return evidence
}

func sensitiveValue(key string, value any) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	text = strings.TrimSpace(text)
	if text == "" || strings.Trim(text, "*xX-") == "" {
		return false
	}
	lowerKey := strings.ToLower(key)
	switch {
	case strings.Contains(lowerKey, "email"):
		return strings.Contains(text, "@") && strings.Contains(text[strings.LastIndex(text, "@"):], ".")
	case strings.Contains(lowerKey, "password") || lowerKey == "passwd" || lowerKey == "pass":
		return len(text) >= 4
	case strings.Contains(lowerKey, "token") || strings.Contains(lowerKey, "api_key") || strings.Contains(lowerKey, "apikey") || strings.Contains(lowerKey, "secret"):
		lower := strings.ToLower(text)
		return len(text) >= 6 && !strings.Contains(lower, "placeholder") && lower != "redacted"
	case strings.Contains(lowerKey, "ssn") || strings.Contains(lowerKey, "social_security") || strings.Contains(lowerKey, "credit_card") || strings.Contains(lowerKey, "card_number"):
		return countDigits(text) >= 9
	case strings.Contains(lowerKey, "phone") || strings.Contains(lowerKey, "mobile") || strings.Contains(lowerKey, "telephone"):
		return countDigits(text) >= 7
	}
	return false
}

func countDigits(value string) int {
	count := 0
	for _, char := range value {
		if char >= '0' && char <= '9' {
			count++
		}
	}
	return count
}

func containsSensitiveData(body string) bool {
	if document, ok := parseJSONP(body); ok {
		return len(sensitiveEvidence(document.value)) > 0
	}
	var value any
	return json.Unmarshal([]byte(strings.TrimSpace(body)), &value) == nil && len(sensitiveEvidence(value)) > 0
}

func crossSiteSessionCookieKnown(ctx *httpmsg.HttpRequestResponse, scanCtx *modkit.ScanContext) bool {
	if ctx == nil || ctx.Request() == nil || scanCtx == nil || strings.TrimSpace(ctx.Request().Header("Cookie")) == "" {
		return false
	}
	scanCtx.ObserveResponseCookies(ctx)
	for _, policy := range scanCtx.RequestCookiePolicies(ctx) {
		if modkit.LikelySessionCookie(policy.Name) && policy.SameSite == "none" && policy.Secure {
			return true
		}
	}
	return false
}

func stripCredentials(raw []byte) ([]byte, error) {
	clean := append([]byte(nil), raw...)
	var err error
	for _, name := range credentialHeaders {
		clean, err = httpmsg.RemoveHeader(clean, name)
		if err != nil {
			return nil, err
		}
	}
	return clean, nil
}

func intersectStrings(left, right []string) []string {
	rightSet := make(map[string]bool, len(right))
	for _, value := range right {
		rightSet[value] = true
	}
	var intersection []string
	for _, value := range left {
		if rightSet[value] {
			intersection = append(intersection, value)
		}
	}
	return intersection
}

func hasAnyString(values, expected []string) bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	for _, value := range expected {
		if set[value] {
			return true
		}
	}
	return false
}
