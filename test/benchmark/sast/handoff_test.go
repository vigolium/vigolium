//go:build sast

package sast

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/test/benchmark/harness"
)

// TestHandoff_All loads all handoff definitions and runs each.
func TestHandoff_All(t *testing.T) {
	dir := filepath.Join(definitionsDir(), "handoff")
	defs, err := harness.LoadSASTHandoffDefinitionsFromDir(dir)
	require.NoError(t, err, "failed to load handoff definitions")
	require.NotEmpty(t, defs, "no handoff definitions found in %s", dir)

	for _, def := range defs {
		t.Run(def.Framework, func(t *testing.T) {
			runHandoffDefinition(t, def)
		})
	}
}

// TestHandoff_MethodNormalization validates ANY/HANDLE/"" methods normalize to GET.
func TestHandoff_MethodNormalization(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"ANY", "GET"},
		{"HANDLE", "GET"},
		{"ALL", "GET"},
		{"", "GET"},
		{"GET", "GET"},
		{"POST", "POST"},
		{"PUT", "PUT"},
		{"DELETE", "DELETE"},
		{"PATCH", "PATCH"},
	}

	for _, tc := range cases {
		t.Run(fmt.Sprintf("method_%s", tc.input), func(t *testing.T) {
			method := normalizeMethod(tc.input)
			assert.Equal(t, tc.expected, method,
				"normalizeMethod(%q) should return %q", tc.input, tc.expected)
		})
	}
}

// TestHandoff_EmptyPathSkipped validates that empty-path routes are skipped.
func TestHandoff_EmptyPathSkipped(t *testing.T) {
	route := harness.HandoffRoute{
		Method: "",
		Path:   "",
	}
	assert.True(t, shouldSkipRoute(route), "route with empty method and path should be skipped")

	route2 := harness.HandoffRoute{
		Method: "GET",
		Path:   "",
	}
	assert.True(t, shouldSkipRoute(route2), "route with empty path should be skipped")
}

// TestHandoff_InsertionPointCreation validates URL params produce insertion points.
func TestHandoff_InsertionPointCreation(t *testing.T) {
	rawReq := "GET /users?q=test&page=1 HTTP/1.1\r\nHost: localhost\r\n\r\n"
	rr, err := httpmsg.ParseRawRequest(rawReq)
	require.NoError(t, err)

	points, err := httpmsg.CreateAllInsertionPoints(rr.Request().Raw(), false)
	require.NoError(t, err)
	assert.NotEmpty(t, points, "should create insertion points from URL params")

	// Should find at least URL parameter insertion points for q and page
	var paramNames []string
	for _, p := range points {
		if p.Type() == httpmsg.INS_PARAM_URL {
			paramNames = append(paramNames, p.Name())
		}
	}
	assert.Contains(t, paramNames, "q", "should have insertion point for 'q'")
	assert.Contains(t, paramNames, "page", "should have insertion point for 'page'")
}

func TestHandoff_NextJS_Oopssec(t *testing.T) {
	defPath := filepath.Join(definitionsDir(), "handoff", "nextjs-oopssec-handoff.yaml")
	def, err := harness.LoadSASTHandoffDefinition(defPath)
	require.NoError(t, err, "failed to load definition nextjs-oopssec-handoff.yaml")
	runHandoffDefinition(t, def)
}

func TestHandoff_NextJS_VulnExamples(t *testing.T) {
	defPath := filepath.Join(definitionsDir(), "handoff", "nextjs-vulnexamples-handoff.yaml")
	def, err := harness.LoadSASTHandoffDefinition(defPath)
	require.NoError(t, err, "failed to load definition nextjs-vulnexamples-handoff.yaml")
	runHandoffDefinition(t, def)
}

func runHandoffDefinition(t *testing.T, def *harness.SASTHandoffDefinition) {
	t.Helper()

	baseURL, err := url.Parse(def.BaseURL)
	require.NoError(t, err, "invalid base URL: %s", def.BaseURL)

	for i, route := range def.Routes {
		t.Run(fmt.Sprintf("route_%d_%s_%s", i, route.Method, route.Path), func(t *testing.T) {
			// Check if route should be skipped
			if route.ExpectedSkip {
				assert.True(t, shouldSkipRoute(route),
					"route %s %s should be skipped", route.Method, route.Path)
				return
			}

			if shouldSkipRoute(route) {
				t.Skipf("route with empty path is skipped")
				return
			}

			// Build raw HTTP request from route
			method := normalizeMethod(route.Method)
			uri := route.Path

			// Add params as query string
			if len(route.Params) > 0 {
				q := url.Values{}
				for _, p := range route.Params {
					q.Set(p, "FUZZ")
				}
				uri += "?" + q.Encode()
			}

			rawReq := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\n\r\n", method, uri, baseURL.Host)

			rr, err := httpmsg.ParseRawRequest(rawReq)
			require.NoError(t, err, "failed to parse raw request")

			// Validate method
			assert.Equal(t, route.ExpectedRequest.Method, rr.Request().Method(),
				"method mismatch for route %s %s", route.Method, route.Path)

			// Validate host via raw request
			assert.Equal(t, route.ExpectedRequest.Host, rr.Request().Header("Host"),
				"host mismatch for route %s %s", route.Method, route.Path)

			// Validate URI path is present in raw request
			rawStr := string(rr.Request().Raw())
			assert.True(t, strings.Contains(rawStr, route.Path) || route.Path == "",
				"raw request should contain path %q", route.Path)
		})
	}
}

