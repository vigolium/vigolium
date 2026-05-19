package yamlext

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func makeRequestResponse(method, url string, respStatus int, respHeaders map[string]string, respBody string) *httpmsg.HttpRequestResponse {
	reqRaw := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: example.com\r\n\r\n", method, url)
	svc, _ := httpmsg.ParseService("http://example.com")
	req := httpmsg.NewHttpRequestWithService(svc, []byte(reqRaw))

	respRaw := fmt.Sprintf("HTTP/1.1 %d OK\r\n", respStatus)
	for k, v := range respHeaders {
		respRaw += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	respRaw += "\r\n" + respBody
	resp := httpmsg.NewHttpResponse([]byte(respRaw))

	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestYAMLPassiveModule_FlatMatchers(t *testing.T) {
	def := &ExtensionDef{
		ID:                "test-flat",
		Name:              "Test Flat Matchers",
		Type:              "passive",
		Severity:          "info",
		Scope:             "response",
		ScanTypes:         []string{"per_request"},
		MatchersCondition: "or",
		Matchers: []MatcherDef{
			{Type: "body", Contains: "secret_key"},
		},
		Finding: &FindingDef{
			Name:        "Secret key found",
			Description: "Body contains a secret key",
			Matched:     "{{matched}}",
		},
	}

	mod, err := NewYAMLPassiveModule(def, nil)
	require.NoError(t, err)
	assert.Equal(t, "ext-test-flat", mod.ID())

	ctx := makeRequestResponse("GET", "/api", 200, nil, "data: secret_key=abc123")
	results, err := mod.ScanPerRequest(ctx, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "Secret key found", results[0].Info.Name)
	assert.Equal(t, "secret_key", results[0].Matched)
}

func TestYAMLPassiveModule_FlatMatchers_NoMatch(t *testing.T) {
	def := &ExtensionDef{
		ID:        "test-flat-nomatch",
		Name:      "Test No Match",
		Type:      "passive",
		Severity:  "info",
		ScanTypes: []string{"per_request"},
		Matchers: []MatcherDef{
			{Type: "body", Contains: "not_present"},
		},
		Finding: &FindingDef{Name: "Found"},
	}

	mod, err := NewYAMLPassiveModule(def, nil)
	require.NoError(t, err)

	ctx := makeRequestResponse("GET", "/api", 200, nil, "safe content")
	results, err := mod.ScanPerRequest(ctx, nil)
	require.NoError(t, err)
	assert.Nil(t, results)
}

func TestYAMLPassiveModule_Rules(t *testing.T) {
	def := &ExtensionDef{
		ID:        "test-rules",
		Name:      "Test Rules",
		Type:      "passive",
		Severity:  "info",
		Scope:     "response",
		ScanTypes: []string{"per_request"},
		Rules: []RuleDef{
			{
				Match: RuleMatchDef{ResponseHeader: "X-Powered-By"},
				Finding: FindingDef{
					Name:        "X-Powered-By exposed",
					Description: "Server leaks technology",
					Matched:     "{{matched}}",
					Severity:    "info",
				},
			},
			{
				Match: RuleMatchDef{BodyContains: "debug_mode"},
				Finding: FindingDef{
					Name:     "Debug mode",
					Severity: "low",
				},
			},
		},
	}

	mod, err := NewYAMLPassiveModule(def, nil)
	require.NoError(t, err)

	// Both rules should match
	ctx := makeRequestResponse("GET", "/api", 200,
		map[string]string{"X-Powered-By": "Express"},
		"debug_mode=true")
	results, err := mod.ScanPerRequest(ctx, nil)
	require.NoError(t, err)
	require.Len(t, results, 2)

	assert.Equal(t, "X-Powered-By exposed", results[0].Info.Name)
	assert.Equal(t, "Debug mode", results[1].Info.Name)
}

func TestYAMLPassiveModule_Rules_PartialMatch(t *testing.T) {
	def := &ExtensionDef{
		ID:        "test-rules-partial",
		Name:      "Test Rules Partial",
		Type:      "passive",
		Severity:  "info",
		ScanTypes: []string{"per_request"},
		Rules: []RuleDef{
			{
				Match:   RuleMatchDef{ResponseHeader: "X-Powered-By"},
				Finding: FindingDef{Name: "Header found"},
			},
			{
				Match:   RuleMatchDef{BodyContains: "not_present"},
				Finding: FindingDef{Name: "Body found"},
			},
		},
	}

	mod, err := NewYAMLPassiveModule(def, nil)
	require.NoError(t, err)

	ctx := makeRequestResponse("GET", "/api", 200,
		map[string]string{"X-Powered-By": "Express"},
		"safe content")
	results, err := mod.ScanPerRequest(ctx, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "Header found", results[0].Info.Name)
}

func TestYAMLPassiveModule_ScanPerHost(t *testing.T) {
	def := &ExtensionDef{
		ID:        "test-host",
		Name:      "Test Per Host",
		Type:      "passive",
		Severity:  "info",
		ScanTypes: []string{"per_host"},
		Matchers: []MatcherDef{
			{Type: "body", Contains: "marker"},
		},
		Finding: &FindingDef{Name: "Marker found"},
	}

	mod, err := NewYAMLPassiveModule(def, nil)
	require.NoError(t, err)

	ctx := makeRequestResponse("GET", "/", 200, nil, "has marker here")
	results, err := mod.ScanPerHost(ctx, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
}

func TestYAMLPassiveModule_NilResponse(t *testing.T) {
	def := &ExtensionDef{
		ID:        "test-nil-resp",
		Name:      "Test Nil Response",
		Type:      "passive",
		Severity:  "info",
		ScanTypes: []string{"per_request"},
		Matchers: []MatcherDef{
			{Type: "body", Contains: "test"},
		},
		Finding: &FindingDef{Name: "Found"},
	}

	mod, err := NewYAMLPassiveModule(def, nil)
	require.NoError(t, err)

	// Request without response
	reqRaw := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	req := httpmsg.NewHttpRequest([]byte(reqRaw))
	ctx := httpmsg.NewHttpRequestResponse(req, nil)

	results, err := mod.ScanPerRequest(ctx, nil)
	require.NoError(t, err)
	assert.Nil(t, results)
}
