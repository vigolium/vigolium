package yamlext

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

func TestYAMLActiveModule_ScanPerRequest_FlatMatchers(t *testing.T) {
	def := &ExtensionDef{
		ID:        "test-active-flat",
		Name:      "Test Active Flat",
		Type:      "active",
		Severity:  "low",
		ScanTypes: []string{"per_request"},
		Matchers: []MatcherDef{
			{Type: "body", Regex: `(?i)SQLSTATE\[`},
		},
		Finding: &FindingDef{
			Name:        "SQL error found",
			Description: "Response contains SQL error",
		},
	}

	mod, err := NewYAMLActiveModule(def, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "ext-test-active-flat", mod.ID())
	assert.Equal(t, severity.Low, mod.Severity())

	ctx := makeRequestResponse("GET", "/api", 200, nil, "Error: SQLSTATE[42S02]")
	results, err := mod.ScanPerRequest(ctx, nil, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "SQL error found", results[0].Info.Name)
}

func TestYAMLActiveModule_ScanPerRequest_Rules(t *testing.T) {
	def := &ExtensionDef{
		ID:        "test-active-rules",
		Name:      "Error Pattern Detector",
		Type:      "active",
		Severity:  "low",
		ScanTypes: []string{"per_request"},
		Rules: []RuleDef{
			{
				Match: RuleMatchDef{BodyRegex: `(?i)Traceback \(most recent call last\)`},
				Finding: FindingDef{
					Name:     "Python traceback",
					Severity: "low",
				},
			},
			{
				Match: RuleMatchDef{BodyRegex: `(?i)goroutine \d+ \[running\]`},
				Finding: FindingDef{
					Name:     "Go panic",
					Severity: "low",
				},
			},
		},
	}

	mod, err := NewYAMLActiveModule(def, nil, nil)
	require.NoError(t, err)

	// Python traceback match
	ctx := makeRequestResponse("GET", "/api", 500, nil,
		"Traceback (most recent call last):\n  File 'app.py', line 42")
	results, err := mod.ScanPerRequest(ctx, nil, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "Python traceback", results[0].Info.Name)
}

func TestYAMLActiveModule_ScanPerRequest_NoMatch(t *testing.T) {
	def := &ExtensionDef{
		ID:        "test-active-nomatch",
		Name:      "Test No Match",
		Type:      "active",
		Severity:  "low",
		ScanTypes: []string{"per_request"},
		Matchers: []MatcherDef{
			{Type: "body", Contains: "not_present"},
		},
		Finding: &FindingDef{Name: "Found"},
	}

	mod, err := NewYAMLActiveModule(def, nil, nil)
	require.NoError(t, err)

	ctx := makeRequestResponse("GET", "/api", 200, nil, "safe content")
	results, err := mod.ScanPerRequest(ctx, nil, nil)
	require.NoError(t, err)
	assert.Nil(t, results)
}

func TestYAMLActiveModule_ScanPerHost(t *testing.T) {
	def := &ExtensionDef{
		ID:        "test-active-host",
		Name:      "Test Per Host",
		Type:      "active",
		Severity:  "info",
		ScanTypes: []string{"per_host"},
		Matchers: []MatcherDef{
			{Type: "header", Name: "X-Debug", Contains: "true"},
		},
		Finding: &FindingDef{
			Name: "Debug header found",
		},
	}

	mod, err := NewYAMLActiveModule(def, nil, nil)
	require.NoError(t, err)

	ctx := makeRequestResponse("GET", "/", 200,
		map[string]string{"X-Debug": "true"}, "")
	results, err := mod.ScanPerHost(ctx, nil, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "Debug header found", results[0].Info.Name)
}

func TestYAMLActiveModule_NilResponse(t *testing.T) {
	def := &ExtensionDef{
		ID:        "test-nil-resp",
		Name:      "Test Nil",
		Type:      "active",
		Severity:  "info",
		ScanTypes: []string{"per_request"},
		Matchers: []MatcherDef{
			{Type: "body", Contains: "test"},
		},
		Finding: &FindingDef{Name: "Found"},
	}

	mod, err := NewYAMLActiveModule(def, nil, nil)
	require.NoError(t, err)

	// No payloads needed for per_request, but no response
	reqRaw := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	req := httpmsg.NewHttpRequest([]byte(reqRaw))
	ctx := httpmsg.NewHttpRequestResponse(req, nil)

	results, err := mod.ScanPerRequest(ctx, nil, nil)
	require.NoError(t, err)
	assert.Nil(t, results)
}

func TestYAMLActiveModule_FindingSeverityOverride(t *testing.T) {
	def := &ExtensionDef{
		ID:        "test-sev-override",
		Name:      "Test Severity Override",
		Type:      "active",
		Severity:  "info",
		ScanTypes: []string{"per_request"},
		Matchers: []MatcherDef{
			{Type: "body", Contains: "critical_error"},
		},
		Finding: &FindingDef{
			Name:     "Critical error",
			Severity: "high", // Override module severity
		},
	}

	mod, err := NewYAMLActiveModule(def, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, severity.Info, mod.Severity()) // Module-level is info

	ctx := makeRequestResponse("GET", "/api", 200, nil, "critical_error found here")
	results, err := mod.ScanPerRequest(ctx, nil, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, severity.High, results[0].Info.Severity) // Finding-level is high
}
