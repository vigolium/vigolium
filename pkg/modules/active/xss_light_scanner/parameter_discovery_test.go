package xss_light_scanner

import (
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/httpmsg"
)

// ============================================================================
// generateCanaryForParam Tests
// ============================================================================

func TestGenerateCanaryForParam(t *testing.T) {
	tests := []struct {
		name      string
		index     int
		paramName string
		expected  string
	}{
		{"first param debug", 0, "debug", "pd0d"},
		{"second param test", 1, "test", "pd1t"},
		{"third param q", 2, "q", "pd2q"},
		{"param with uppercase", 5, "Title", "pd5T"},
		{"empty param name", 10, "", "pd10x"},
		{"large index", 100, "search", "pd100s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateCanaryForParam(tt.index, tt.paramName)
			if got != tt.expected {
				t.Errorf("generateCanaryForParam(%d, %q) = %q, want %q",
					tt.index, tt.paramName, got, tt.expected)
			}
		})
	}
}

func TestGenerateCanaryForParam_UniqueValues(t *testing.T) {
	// Verify each param gets a unique canary
	params := []string{"debug", "test", "q", "search", "url", "path"}
	seen := make(map[string]string)

	for i, param := range params {
		canary := generateCanaryForParam(i, param)
		if existingParam, exists := seen[canary]; exists {
			t.Errorf("Duplicate canary %q for params %q and %q", canary, existingParam, param)
		}
		seen[canary] = param
	}
}

// ============================================================================
// Query String Building Tests
// ============================================================================

func TestBuildQueryParts(t *testing.T) {
	params := []string{"debug", "test", "q"}

	// Simulate the query building logic from DiscoverEchoParams
	queryParts := make([]string, 0, len(params))
	for i, param := range params {
		canary := generateCanaryForParam(i, param)
		queryParts = append(queryParts, httpmsg.EncodeQueryValue(param)+"="+httpmsg.EncodeQueryValue(canary))
	}

	result := strings.Join(queryParts, "&")

	// Expected: debug=pd0d&test=pd1t&q=pd2q
	expected := "debug=pd0d&test=pd1t&q=pd2q"
	if result != expected {
		t.Errorf("Query string = %q, want %q", result, expected)
	}
}

func TestBuildQueryParts_SpecialCharacters(t *testing.T) {
	// Test params with special characters that need encoding
	params := []string{"q", "search", "url"}

	queryParts := make([]string, 0, len(params))
	for i, param := range params {
		canary := generateCanaryForParam(i, param)
		queryParts = append(queryParts, httpmsg.EncodeQueryValue(param)+"="+httpmsg.EncodeQueryValue(canary))
	}

	result := strings.Join(queryParts, "&")

	// Each part should have = between name and value
	parts := strings.Split(result, "&")
	for _, part := range parts {
		if !strings.Contains(part, "=") {
			t.Errorf("Part %q missing '=' separator", part)
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			t.Errorf("Part %q should have exactly one '=' separator", part)
		}
		if kv[0] == "" {
			t.Errorf("Part %q has empty key", part)
		}
		if kv[1] == "" {
			t.Errorf("Part %q has empty value", part)
		}
	}
}

func TestBuildQueryParts_AllDefaultParams(t *testing.T) {
	// Test with all default params to ensure no duplicates or empty values
	params := defaultDiscoveryParams

	queryParts := make([]string, 0, len(params))
	canaries := make(map[string]string)

	for i, param := range params {
		canary := generateCanaryForParam(i, param)
		canaries[param] = canary
		queryParts = append(queryParts, httpmsg.EncodeQueryValue(param)+"="+httpmsg.EncodeQueryValue(canary))
	}

	result := strings.Join(queryParts, "&")

	// Verify each param appears with its canary
	for param, canary := range canaries {
		expectedPart := param + "=" + canary
		if !strings.Contains(result, expectedPart) {
			t.Errorf("Query string missing %q", expectedPart)
		}
	}

	// Verify no param appears without value (just name&name2 format)
	parts := strings.Split(result, "&")
	for _, part := range parts {
		if !strings.Contains(part, "=") {
			t.Errorf("Found param without value: %q", part)
		}
	}
}

// ============================================================================
// ParameterDiscovery Tests
// ============================================================================

func TestNewParameterDiscovery(t *testing.T) {
	pd := NewParameterDiscovery()
	if pd == nil {
		t.Fatal("NewParameterDiscovery returned nil")
	}
	if len(pd.params) == 0 {
		t.Error("NewParameterDiscovery has no default params")
	}
	if len(pd.params) != len(defaultDiscoveryParams) {
		t.Errorf("NewParameterDiscovery params count = %d, want %d",
			len(pd.params), len(defaultDiscoveryParams))
	}
}

func TestNewParameterDiscoveryWithParams(t *testing.T) {
	customParams := []string{"foo", "bar", "baz"}
	pd := NewParameterDiscoveryWithParams(customParams)

	if pd == nil {
		t.Fatal("NewParameterDiscoveryWithParams returned nil")
	}
	if len(pd.params) != len(customParams) {
		t.Errorf("params count = %d, want %d", len(pd.params), len(customParams))
	}
	for i, p := range pd.params {
		if p != customParams[i] {
			t.Errorf("param[%d] = %q, want %q", i, p, customParams[i])
		}
	}
}

// ============================================================================
// Canary Mapping Tests
// ============================================================================

func TestCanaryMapping(t *testing.T) {
	// Test that canaries can be mapped back to params
	params := defaultDiscoveryParams
	canaryToParam := make(map[string]string)

	for i, param := range params {
		canary := generateCanaryForParam(i, param)
		canaryToParam[canary] = param
	}

	// Simulate finding a canary in response
	testCanary := generateCanaryForParam(0, params[0])
	foundParam, exists := canaryToParam[testCanary]
	if !exists {
		t.Errorf("Could not map canary %q back to param", testCanary)
	}
	if foundParam != params[0] {
		t.Errorf("Canary mapped to wrong param: got %q, want %q", foundParam, params[0])
	}
}

func TestCanaryFormat(t *testing.T) {
	// Verify canary format is consistent: pd{index}{firstChar}
	testCases := []struct {
		index     int
		paramName string
	}{
		{0, "debug"},
		{1, "test"},
		{25, "search"},
		{100, "query"},
	}

	for _, tc := range testCases {
		canary := generateCanaryForParam(tc.index, tc.paramName)

		// Must start with "pd"
		if !strings.HasPrefix(canary, "pd") {
			t.Errorf("Canary %q does not start with 'pd'", canary)
		}

		// Must end with first char of param (or 'x' if empty)
		expectedSuffix := string(tc.paramName[0])
		if !strings.HasSuffix(canary, expectedSuffix) {
			t.Errorf("Canary %q does not end with %q", canary, expectedSuffix)
		}
	}
}
