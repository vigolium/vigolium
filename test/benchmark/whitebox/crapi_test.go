//go:build canary

package whitebox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/test/benchmark/harness"
)

// TestWhitebox_CrAPI_Active runs crAPI active module benchmarks.
// crAPI requires Docker Compose (managed externally via `make crapi-up`)
// and an authentication flow to access protected endpoints.
func TestWhitebox_CrAPI_Active(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	defPath := filepath.Join(harness.DefinitionsDir(), "crapi.yaml")
	def, err := harness.LoadDefinition(defPath)
	require.NoError(t, err, "Failed to load crAPI definition")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// crAPI uses compose — verify it's running
	app, err := harness.StartAppFromDefinition(ctx, def.App)
	if err != nil {
		t.Skipf("crAPI not available (run 'make crapi-up' first): %v", err)
		return
	}
	defer func() { _ = app.Stop() }()

	t.Logf("crAPI running at %s", app.BaseURL)

	// Run auth flow if defined
	authToken := ""
	if def.Setup != nil && len(def.Setup.AuthFlow) > 0 {
		token, err := runAuthFlow(t, app.BaseURL, def.Setup.AuthFlow)
		if err != nil {
			t.Logf("Auth flow failed (some tests may fail): %v", err)
		} else {
			authToken = token
			t.Logf("Auth token obtained: %s...", authToken[:min(20, len(authToken))])
		}
	}

	// Setup test infrastructure
	infra, err := harness.SetupTestInfra()
	require.NoError(t, err, "Failed to setup test infrastructure")
	defer infra.Cleanup()

	// Run active test cases
	for _, tc := range def.TestCases {
		if tc.ScanMode != "active" {
			continue
		}

		// Inject auth token into test case headers if available
		if authToken != "" && tc.Headers == nil {
			tc.Headers = make(map[string]string)
		}
		if authToken != "" {
			tc.Headers["Authorization"] = "Bearer " + authToken
		}

		t.Run(tc.ID, func(t *testing.T) {
			results := harness.RunActiveTestCase(t, tc, app.BaseURL, infra)
			for _, r := range results {
				if r.Error != nil {
					t.Logf("[%s] Error: %v", tc.ID, r.Error)
				}
				t.Logf("[%s] %s: %d findings (passed=%v, duration=%v)",
					tc.ID, r.ModuleID, r.FindingCount, r.Passed, r.Duration)
			}
		})
	}
}

// TestWhitebox_CrAPI_Passive runs crAPI passive module benchmarks.
func TestWhitebox_CrAPI_Passive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping benchmark test in short mode")
	}

	defPath := filepath.Join(harness.DefinitionsDir(), "crapi.yaml")
	def, err := harness.LoadDefinition(defPath)
	require.NoError(t, err, "Failed to load crAPI definition")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	app, err := harness.StartAppFromDefinition(ctx, def.App)
	if err != nil {
		t.Skipf("crAPI not available (run 'make crapi-up' first): %v", err)
		return
	}
	defer func() { _ = app.Stop() }()

	t.Logf("crAPI running at %s", app.BaseURL)

	infra, err := harness.SetupTestInfra()
	require.NoError(t, err, "Failed to setup test infrastructure")
	defer infra.Cleanup()

	for _, tc := range def.TestCases {
		if tc.ScanMode != "passive" {
			continue
		}

		t.Run(tc.ID, func(t *testing.T) {
			results := harness.RunPassiveTestCase(t, tc, app.BaseURL, infra)
			for _, r := range results {
				t.Logf("[%s] %s: %d findings (passed=%v)",
					tc.ID, r.ModuleID, r.FindingCount, r.Passed)
			}
		})
	}
}

// runAuthFlow executes the authentication steps and returns the extracted token.
func runAuthFlow(t *testing.T, baseURL string, steps []harness.AuthStep) (string, error) {
	t.Helper()

	client := &http.Client{Timeout: 15 * time.Second}
	extractedVars := make(map[string]string)

	for _, step := range steps {
		url := baseURL + step.Path
		var bodyReader io.Reader
		if step.Body != "" {
			bodyReader = bytes.NewBufferString(step.Body)
		}

		req, err := http.NewRequest(step.Method, url, bodyReader)
		if err != nil {
			return "", fmt.Errorf("auth step %q: failed to create request: %w", step.Name, err)
		}

		for k, v := range step.Headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			return "", fmt.Errorf("auth step %q: request failed: %w", step.Name, err)
		}

		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		t.Logf("Auth step %q: %s %s -> %d", step.Name, step.Method, step.Path, resp.StatusCode)

		// Extract variables from response
		if step.Extract != nil && len(body) > 0 {
			var jsonData map[string]interface{}
			if err := json.Unmarshal(body, &jsonData); err == nil {
				for varName, jsonPath := range step.Extract {
					// Simple JSONPath extraction (supports $.key format)
					value := extractJSONValue(jsonData, jsonPath)
					if value != "" {
						extractedVars[varName] = value
						t.Logf("Auth step %q: extracted %s", step.Name, varName)
					}
				}
			}
		}
	}

	if token, ok := extractedVars["token"]; ok {
		return token, nil
	}

	return "", fmt.Errorf("no token extracted from auth flow")
}

// extractJSONValue performs simple JSONPath extraction (supports $.key and $.key.subkey).
func extractJSONValue(data map[string]interface{}, path string) string {
	// Strip "$." prefix
	if len(path) > 2 && path[:2] == "$." {
		path = path[2:]
	}

	// Simple single-level extraction
	if val, ok := data[path]; ok {
		switch v := val.(type) {
		case string:
			return v
		case float64:
			return fmt.Sprintf("%v", v)
		default:
			return fmt.Sprintf("%v", v)
		}
	}

	return ""
}
