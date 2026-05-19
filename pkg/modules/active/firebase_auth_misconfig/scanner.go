package firebase_auth_misconfig

import (
	"fmt"
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

	diskSet := m.ds.Get(scanCtx.DedupMgr())

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
		if result := m.testAnonymousAuth(httpClient, apiKey, sourceURL); result != nil {
			results = append(results, result)
		}

		// Test 2: Email enumeration
		if result := m.testEmailEnumeration(httpClient, apiKey, sourceURL); result != nil {
			results = append(results, result)
		}

		// Test 3: Provider discovery
		if result := m.testProviderDiscovery(httpClient, apiKey, sourceURL); result != nil {
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

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	respBody := resp.Body().String()

	// Successful anonymous signup returns idToken
	if resp.Response().StatusCode == 200 && strings.Contains(respBody, "idToken") {
		// Clean up: delete the test account
		m.deleteTestAccount(httpClient, apiKey, respBody)

		return &output.ResultEvent{
			URL:     sourceURL,
			Matched: fmt.Sprintf("Anonymous auth enabled (apiKey: %s...)", apiKey[:10]),
			Request: rawReq,
			Info: output.Info{
				Name:        "Firebase Anonymous Authentication Enabled",
				Description: fmt.Sprintf("Firebase project allows anonymous sign-in via API key %s... — attackers can obtain authenticated access without a real identity, potentially bypassing auth != null rules", apiKey[:10]),
				Severity:    severity.Medium,
				Confidence:  severity.Certain,
				Tags:        []string{"firebase", "authentication", "misconfiguration"},
			},
			Metadata: map[string]any{
				"apiKey":   apiKey,
				"endpoint": "accounts:signUp",
				"type":     "anonymous",
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

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	respBody := resp.Body().String()

	// If we get EMAIL_NOT_FOUND, it means the endpoint differentiates
	// between existing and non-existing emails (email enumeration)
	if strings.Contains(respBody, "EMAIL_NOT_FOUND") {
		return &output.ResultEvent{
			URL:     sourceURL,
			Matched: fmt.Sprintf("Email enumeration possible (apiKey: %s...)", apiKey[:10]),
			Request: rawReq,
			Info: output.Info{
				Name:        "Firebase Email Enumeration",
				Description: "Firebase Identity Toolkit endpoint returns distinguishable errors for existing vs non-existing emails (EMAIL_NOT_FOUND vs INVALID_PASSWORD), enabling user enumeration",
				Severity:    severity.Low,
				Confidence:  severity.Certain,
				Tags:        []string{"firebase", "authentication", "enumeration"},
			},
			Metadata: map[string]any{
				"apiKey":   apiKey,
				"endpoint": "accounts:signInWithPassword",
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

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return nil
	}
	defer resp.Close()

	if resp.Response() == nil {
		return nil
	}

	respBody := resp.Body().String()

	// If endpoint returns registered status and providers, it leaks user info
	if resp.Response().StatusCode == 200 && strings.Contains(respBody, "registered") {
		// Only flag if the endpoint reveals provider info (allProviders or signinMethods)
		if strings.Contains(respBody, "allProviders") || strings.Contains(respBody, "signinMethods") {
			return &output.ResultEvent{
				URL:     sourceURL,
				Matched: fmt.Sprintf("Provider discovery enabled (apiKey: %s...)", apiKey[:10]),
				Request: rawReq,
				Info: output.Info{
					Name:        "Firebase Provider Discovery Enabled",
					Description: "Firebase Identity Toolkit createAuthUri endpoint reveals whether accounts exist and their linked authentication providers, enabling identity correlation",
					Severity:    severity.Low,
					Confidence:  severity.Firm,
					Tags:        []string{"firebase", "authentication", "enumeration"},
				},
				Metadata: map[string]any{
					"apiKey":   apiKey,
					"endpoint": "accounts:createAuthUri",
				},
			}
		}
	}

	return nil
}

func (m *Module) deleteTestAccount(
	httpClient *http.Requester,
	apiKey string,
	signUpResponse string,
) {
	// Extract idToken from signup response
	idTokenIdx := strings.Index(signUpResponse, `"idToken"`)
	if idTokenIdx == -1 {
		return
	}

	// Simple extraction: find the value after "idToken":"
	rest := signUpResponse[idTokenIdx:]
	start := strings.Index(rest, `":"`)
	if start == -1 {
		return
	}
	rest = rest[start+3:]
	end := strings.Index(rest, `"`)
	if end == -1 {
		return
	}
	idToken := rest[:end]

	targetURL := fmt.Sprintf("%s/accounts:delete?key=%s", identityToolkitBase, apiKey)
	reqBody := fmt.Sprintf(`{"idToken":"%s"}`, idToken)

	rawReq := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: identitytoolkit.googleapis.com\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		targetURL, len(reqBody), reqBody)

	fuzzedReq, err := httpmsg.ParseRawRequest(rawReq)
	if err != nil {
		return
	}

	resp, _, err := httpClient.Execute(fuzzedReq, http.Options{})
	if err != nil {
		return
	}
	resp.Close()
}
