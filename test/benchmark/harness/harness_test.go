package harness

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testDefinitionsDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "definitions")
}

func TestLoadDefinition_DVWA(t *testing.T) {
	defPath := filepath.Join(testDefinitionsDir(), "dvwa.yaml")
	def, err := LoadDefinition(defPath)
	require.NoError(t, err)

	assert.Equal(t, "dvwa", def.App.Name)
	assert.Equal(t, "docker", def.App.Type)
	assert.Equal(t, "vulnerables/web-dvwa:latest", def.App.Image)
	assert.NotEmpty(t, def.TestCases)

	// Verify defaults are applied
	for _, tc := range def.TestCases {
		assert.NotEmpty(t, tc.ID, "Test case should have an ID")
		assert.NotEmpty(t, tc.Modules, "Test case should have modules")
		assert.Contains(t, []string{"active", "passive"}, tc.ScanMode)
		assert.Contains(t, []string{"strict", "soft", "negative"}, tc.Assertion)
	}
}

func TestLoadDefinition_VAmPI(t *testing.T) {
	defPath := filepath.Join(testDefinitionsDir(), "vampi.yaml")
	def, err := LoadDefinition(defPath)
	require.NoError(t, err)

	assert.Equal(t, "vampi", def.App.Name)
	assert.Equal(t, "1", def.App.Env["vulnerable"])
	assert.NotEmpty(t, def.TestCases)
}

func TestLoadDefinition_JuiceShop(t *testing.T) {
	defPath := filepath.Join(testDefinitionsDir(), "juiceshop.yaml")
	def, err := LoadDefinition(defPath)
	require.NoError(t, err)

	assert.Equal(t, "juiceshop", def.App.Name)
	assert.NotEmpty(t, def.TestCases)
}

func TestLoadDefinition_CrAPI(t *testing.T) {
	defPath := filepath.Join(testDefinitionsDir(), "crapi.yaml")
	def, err := LoadDefinition(defPath)
	require.NoError(t, err)

	assert.Equal(t, "crapi", def.App.Name)
	assert.Equal(t, "compose", def.App.Type)
	assert.NotNil(t, def.Setup)
	assert.NotEmpty(t, def.Setup.AuthFlow)
}

func TestLoadDefinition_VulnerableJava(t *testing.T) {
	defPath := filepath.Join(testDefinitionsDir(), "vulnerable-java.yaml")
	def, err := LoadDefinition(defPath)
	require.NoError(t, err)

	assert.Equal(t, "vulnerable-java", def.App.Name)
	assert.Equal(t, "docker", def.App.Type)
	assert.Equal(t, "ghcr.io/datadog/vulnerable-java-application:latest", def.App.Image)
	assert.NotEmpty(t, def.TestCases)

	// Verify OAST test cases exist
	hasOAST := false
	for _, tc := range def.TestCases {
		if tc.RequiresOAST {
			hasOAST = true
			break
		}
	}
	assert.True(t, hasOAST, "Should have at least one OAST test case")
}

func TestLoadDefinition_VulnerableNginx(t *testing.T) {
	defPath := filepath.Join(testDefinitionsDir(), "vulnerable-nginx.yaml")
	def, err := LoadDefinition(defPath)
	require.NoError(t, err)

	assert.Equal(t, "vulnerable-nginx", def.App.Name)
	assert.Equal(t, "docker", def.App.Type)
	assert.Equal(t, "detectify/vulnerable-nginx:latest", def.App.Image)
	assert.NotEmpty(t, def.TestCases)
}

func TestLoadDefinitionsFromDir(t *testing.T) {
	defs, err := LoadDefinitionsFromDir(testDefinitionsDir())
	require.NoError(t, err)

	// Should find at least dvwa, vampi, juiceshop, crapi, vulnerable-java, vulnerable-nginx
	assert.GreaterOrEqual(t, len(defs), 6, "Should have at least 6 definitions")

	names := make(map[string]bool)
	for _, def := range defs {
		names[def.App.Name] = true
	}
	assert.True(t, names["dvwa"])
	assert.True(t, names["vampi"])
	assert.True(t, names["juiceshop"])
	assert.True(t, names["crapi"])
	assert.True(t, names["vulnerable-java"])
	assert.True(t, names["vulnerable-nginx"])
}

func TestResolveActiveModules(t *testing.T) {
	mods, err := ResolveActiveModules([]string{"sqli-error-based", "xss-light-url-params"})
	require.NoError(t, err)
	assert.Len(t, mods, 2)
}

func TestResolveActiveModules_NotFound(t *testing.T) {
	_, err := ResolveActiveModules([]string{"nonexistent-module"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent-module")
}

func TestResolvePassiveModules(t *testing.T) {
	mods, err := ResolvePassiveModules([]string{"security-headers-missing"})
	require.NoError(t, err)
	assert.Len(t, mods, 1)
}

func TestGenerateCoverageReport(t *testing.T) {
	report, err := GenerateCoverageReport(testDefinitionsDir())
	require.NoError(t, err)

	assert.Greater(t, report.TotalActive, 0)
	assert.Greater(t, report.TotalPassive, 0)
	assert.Greater(t, report.CoveredActive, 0, "Should have active module coverage from YAML definitions")
	assert.Greater(t, report.CoveredPassive, 0, "Should have passive module coverage from YAML definitions")
	assert.Greater(t, report.TotalTestCases, 0)

	// Verify the markdown output
	markdown := FormatCoverageMarkdown(report)
	assert.Contains(t, markdown, "Module Benchmark Coverage")
	assert.Contains(t, markdown, "sqli-error-based")
	assert.Contains(t, markdown, "security-headers-missing")
}

func TestBuildRequestWithMethodAndBody(t *testing.T) {
	tests := []struct {
		name   string
		method string
	}{
		{"POST", "POST"},
		{"PUT", "PUT"},
		{"PATCH", "PATCH"},
		{"DELETE", "DELETE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr, err := buildRequestWithMethodAndBody(
				"http://example.com/api/test?id=1",
				tt.method,
				`{"key":"value"}`,
				map[string]string{"Content-Type": "application/json"},
			)
			require.NoError(t, err)
			require.NotNil(t, rr)

			raw := string(rr.Request().Raw())
			assert.True(t, strings.HasPrefix(raw, tt.method+" "),
				"Request should start with %s, got: %s", tt.method, raw[:min(len(raw), 30)])
			assert.Contains(t, raw, "Content-Type: application/json")
			assert.Contains(t, raw, `{"key":"value"}`)
		})
	}
}

func TestBuildRequestWithMethod(t *testing.T) {
	tests := []struct {
		name   string
		method string
	}{
		{"DELETE", "DELETE"},
		{"HEAD", "HEAD"},
		{"OPTIONS", "OPTIONS"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr, err := buildRequestWithMethod(
				"http://example.com/api/resource",
				tt.method,
				nil,
			)
			require.NoError(t, err)
			require.NotNil(t, rr)

			raw := string(rr.Request().Raw())
			assert.True(t, strings.HasPrefix(raw, tt.method+" "),
				"Request should start with %s, got: %s", tt.method, raw[:min(len(raw), 30)])
			// Should not contain a body
			parts := strings.SplitN(raw, "\r\n\r\n", 2)
			if len(parts) == 2 {
				assert.Empty(t, parts[1], "Bodyless request should have no body")
			}
		})
	}
}

func TestMergeHeaders_CookieAdditive(t *testing.T) {
	authHeaders := map[string]string{
		"Cookie":        "PHPSESSID=abc123; security=low",
		"Authorization": "Bearer token",
	}
	tcHeaders := map[string]string{
		"Cookie":       "trackingId=xyz",
		"Content-Type": "application/json",
	}

	merged := MergeHeaders(authHeaders, tcHeaders)

	// Cookie should be merged additively
	assert.Contains(t, merged["Cookie"], "PHPSESSID=abc123")
	assert.Contains(t, merged["Cookie"], "trackingId=xyz")

	// Other headers: tc takes precedence
	assert.Equal(t, "Bearer token", merged["Authorization"])
	assert.Equal(t, "application/json", merged["Content-Type"])
}

func TestContainerConfigFromApp(t *testing.T) {
	app := AppConfig{
		Name:           "test",
		Type:           "docker",
		Image:          "test:latest",
		Port:           8080,
		WaitEndpoint:   "/health",
		StartupTimeout: 60_000_000_000, // 60s in nanoseconds
	}

	config := ContainerConfigFromApp(app)
	assert.Equal(t, "test:latest", config.Image)
	assert.Equal(t, "8080/tcp", config.ExposedPort)
	assert.Equal(t, "/health", config.ReadyEndpoint)
}
