package firebase_auth_misconfig

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/vigolium/vigolium/pkg/dedup"
	"github.com/vigolium/vigolium/pkg/http"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/infra"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

var (
	apiKeyRe = regexp.MustCompile(`["']apiKey["']\s*:\s*["'](AIza[a-zA-Z0-9_-]{35})["']`)
)

const (
	identityToolkitBase = "https://identitytoolkit.googleapis.com/v1"
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
		ds: dedup.LazyDiskSet("firebase_auth_misconfig"),
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
	if !ctx.HasResponse() {
		return nil, nil
	}

	body := ctx.Response().BodyToString()
	if body == "" {
		return nil, nil
	}

	// Extract API keys
	matches := apiKeyRe.FindAllStringSubmatch(body, 5)
	if len(matches) == 0 {
		return nil, nil
	}

	seen := make(map[string]struct{})
	var apiKeys []string
	for _, match := range matches {
		if len(match) > 1 {
			key := match[1]
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				apiKeys = append(apiKeys, key)
			}
		}
	}

	var diskSet *dedup.DiskSet
	if scanCtx != nil {
		diskSet = m.ds.Get(scanCtx.DedupMgr())
	}
	probeClient, err := httpClient.CloneWithoutCredentials()
	if err != nil {
		return nil, nil
	}

	urlx, _ := ctx.URL()
	sourceURL := ""
	if urlx != nil {
		sourceURL = urlx.String()
	}

	var results []*output.ResultEvent
	for _, apiKey := range apiKeys {
		if diskSet != nil && diskSet.IsSeen(apiKey) {
			continue
		}

		// Test 1: Anonymous signup
		if result := m.testAnonymousAuth(probeClient, apiKey, sourceURL); result != nil {
			results = append(results, result)
		}

		// Test 2: Email enumeration
		if result := m.testEmailEnumeration(probeClient, apiKey, sourceURL); result != nil {
			results = append(results, result)
		}

		// Test 3: Provider discovery
		if result := m.testProviderDiscovery(probeClient, apiKey, sourceURL); result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

func (m *Module) testAnonymousAuth(
	httpClient *http.Requester,
	apiKey string,
	sourceURL string,
) *output.ResultEvent {
	targetURL := fmt.Sprintf("%s/accounts:signUp?key=%s", identityToolkitBase, apiKey)
	reqBody := `{"returnSecureToken":true}`

	rawReq := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: identitytoolkit.googleapis.com\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		targetURL, len(reqBody), reqBody)

	fuzzedReq, err := httpmsg.ParseRawRequest(rawReq)
	if err != nil {
		return nil
	}

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil || infra.IsBlockedResponse(resp) {
		return nil
	}

	respBody := resp.Body().String()

	// Successful anonymous signup returns idToken
	idToken, anonymousCreated := anonymousAccountToken(respBody)
	if resp.Response().StatusCode == 200 && anonymousCreated {
		// Clean up: delete the test account
		deleted := m.deleteTestAccount(httpClient, apiKey, idToken)

		return &output.ResultEvent{
			ModuleID:      ModuleID,
			RecordKind:    output.RecordKindObservation,
			EvidenceGrade: output.EvidenceGradeObservation,
			URL:           sourceURL,
			Matched:       fmt.Sprintf("Anonymous auth enabled (apiKey: %s...)", apiKey[:10]),
			Request:       rawReq,
			Response:      resp.FullResponseString(),
			Info: output.Info{
				Name:        "Firebase Anonymous Authentication Feature Observed",
				Description: fmt.Sprintf("Firebase accepted an anonymous signup using the publishable API key %s...; cleanup was attempted. Anonymous auth is a supported feature, and no protected resource was shown to trust the token.", apiKey[:10]),
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"firebase", "authentication", "misconfiguration"},
			},
			Metadata: map[string]any{
				"apiKey":                       apiKey,
				"endpoint":                     "accounts:signUp",
				"type":                         "anonymous",
				"api_key_intentionally_public": true,
				"protected_access_confirmed":   false,
				"test_account_deleted":         deleted,
			},
		}
	}

	return nil
}

func (m *Module) testEmailEnumeration(
	httpClient *http.Requester,
	apiKey string,
	sourceURL string,
) *output.ResultEvent {
	targetURL := fmt.Sprintf("%s/accounts:signInWithPassword?key=%s", identityToolkitBase, apiKey)
	reqBody := `{"email":"vgm-test-nonexistent@example.com","password":"vgm-test-pwd-12345","returnSecureToken":true}`

	rawReq := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: identitytoolkit.googleapis.com\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		targetURL, len(reqBody), reqBody)

	fuzzedReq, err := httpmsg.ParseRawRequest(rawReq)
	if err != nil {
		return nil
	}

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil || infra.IsBlockedResponse(resp) {
		return nil
	}

	respBody := resp.Body().String()

	// A structured EMAIL_NOT_FOUND response proves only that this random address
	// is absent. Without a known-existing control, it does not prove a usable
	// existing-vs-nonexisting enumeration differential.
	if identityErrorMessage(respBody) == "EMAIL_NOT_FOUND" {
		return &output.ResultEvent{
			ModuleID:      ModuleID,
			RecordKind:    output.RecordKindObservation,
			EvidenceGrade: output.EvidenceGradeObservation,
			URL:           sourceURL,
			Matched:       fmt.Sprintf("Email-existence error observed (apiKey: %s...)", apiKey[:10]),
			Request:       rawReq,
			Response:      resp.FullResponseString(),
			Info: output.Info{
				Name:        "Firebase Email-Existence Error Observed",
				Description: "Identity Toolkit returned structured EMAIL_NOT_FOUND for a fresh nonexistent address. This reveals error semantics, but no known-existing address was tested, so an account-enumeration differential was not confirmed.",
				Severity:    severity.Info,
				Confidence:  severity.Certain,
				Tags:        []string{"firebase", "authentication", "enumeration"},
			},
			Metadata: map[string]any{
				"apiKey":                   apiKey,
				"endpoint":                 "accounts:signInWithPassword",
				"existing_account_control": false,
			},
		}
	}

	return nil
}

func (m *Module) testProviderDiscovery(
	httpClient *http.Requester,
	apiKey string,
	sourceURL string,
) *output.ResultEvent {
	targetURL := fmt.Sprintf("%s/accounts:createAuthUri?key=%s", identityToolkitBase, apiKey)
	reqBody := `{"identifier":"vgm-test@example.com","continueUri":"https://example.com"}`

	rawReq := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: identitytoolkit.googleapis.com\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		targetURL, len(reqBody), reqBody)

	fuzzedReq, err := httpmsg.ParseRawRequest(rawReq)
	if err != nil {
		return nil
	}

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil || infra.IsBlockedResponse(resp) {
		return nil
	}

	respBody := resp.Body().String()

	// Empty provider arrays and registered:false are normal discovery responses,
	// not identity correlation. Require a parsed registered account plus at least
	// one concrete provider/method.
	providers, leaked := providerDiscoveryDetails(respBody)
	if resp.Response().StatusCode == 200 && leaked {
		return &output.ResultEvent{
			ModuleID:         ModuleID,
			RecordKind:       output.RecordKindCandidate,
			EvidenceGrade:    output.EvidenceGradeDifferential,
			URL:              sourceURL,
			Matched:          fmt.Sprintf("Provider discovery returned %s (apiKey: %s...)", strings.Join(providers, ", "), apiKey[:10]),
			Request:          rawReq,
			Response:         resp.FullResponseString(),
			ExtractedResults: providers,
			Info: output.Info{
				Name:        "Firebase Provider Discovery Candidate",
				Description: "Identity Toolkit reported the tested identifier as registered and returned non-empty authentication providers. This demonstrates identity metadata disclosure for that identifier, but broader account enumeration was not tested.",
				Severity:    severity.Low,
				Confidence:  severity.Firm,
				Tags:        []string{"firebase", "authentication", "enumeration"},
			},
			Metadata: map[string]any{
				"apiKey":     apiKey,
				"endpoint":   "accounts:createAuthUri",
				"registered": true,
				"providers":  providers,
			},
		}
	}

	return nil
}

func anonymousAccountToken(body string) (string, bool) {
	var response struct {
		IDToken string `json:"idToken"`
		LocalID string `json:"localId"`
	}
	if json.Unmarshal([]byte(body), &response) != nil {
		return "", false
	}
	return response.IDToken, response.IDToken != "" && response.LocalID != ""
}

func identityErrorMessage(body string) string {
	var response struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal([]byte(body), &response) != nil {
		return ""
	}
	return response.Error.Message
}

func providerDiscoveryDetails(body string) ([]string, bool) {
	var response struct {
		Registered    bool     `json:"registered"`
		AllProviders  []string `json:"allProviders"`
		SigninMethods []string `json:"signinMethods"`
	}
	if json.Unmarshal([]byte(body), &response) != nil || !response.Registered {
		return nil, false
	}
	seen := map[string]bool{}
	providers := make([]string, 0, len(response.AllProviders)+len(response.SigninMethods))
	for _, provider := range append(response.AllProviders, response.SigninMethods...) {
		provider = strings.TrimSpace(provider)
		if provider == "" || seen[provider] {
			continue
		}
		seen[provider] = true
		providers = append(providers, provider)
	}
	return providers, len(providers) > 0
}

func (m *Module) deleteTestAccount(
	httpClient *http.Requester,
	apiKey string,
	idToken string,
) bool {
	if idToken == "" {
		return false
	}
	targetURL := fmt.Sprintf("%s/accounts:delete?key=%s", identityToolkitBase, apiKey)
	reqBody := fmt.Sprintf(`{"idToken":"%s"}`, idToken)

	rawReq := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: identitytoolkit.googleapis.com\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		targetURL, len(reqBody), reqBody)

	fuzzedReq, err := httpmsg.ParseRawRequest(rawReq)
	if err != nil {
		return false
	}

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{NoRedirects: true, NoClustering: true})
	if err != nil {
		return false
	}
	defer resp.Close()
	if resp.Response() == nil {
		return false
	}
	return resp.Response().StatusCode >= 200 && resp.Response().StatusCode < 300
}
