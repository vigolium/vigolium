package sast

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/pkg/toolexec/astgrep"
	"github.com/vigolium/vigolium/pkg/toolexec/sourcetools"
	"github.com/vigolium/vigolium/test/benchmark/harness"
)

// stubPath returns the absolute path to a framework's source stub directory.
func stubPath(framework string) string { //nolint:unused
	candidates := []string{
		filepath.Join("../../testdata/sast-stubs", framework),
		filepath.Join("../testdata/sast-stubs", framework),
		filepath.Join("test/testdata/sast-stubs", framework),
	}
	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	return filepath.Join("test/testdata/sast-stubs", framework)
}

// sarifFixturePath returns the absolute path to a SARIF fixture file.
func sarifFixturePath(name string) string { //nolint:unused
	candidates := []string{
		filepath.Join("../../testdata/sast-sarif", name),
		filepath.Join("../testdata/sast-sarif", name),
		filepath.Join("test/testdata/sast-sarif", name),
	}
	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	return filepath.Join("test/testdata/sast-sarif", name)
}

// definitionsDir returns the absolute path to the whitebox definitions directory.
func definitionsDir() string { //nolint:unused
	candidates := []string{
		"../definitions/whitebox",
		"../../definitions/whitebox",
		"test/benchmark/definitions/whitebox",
	}
	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	return "test/benchmark/definitions/whitebox"
}

// findRoute searches for a route with the given method and path in the results.
// Path matching uses suffix matching on the path component to handle absolute paths.
func findRoute(routes []astgrep.Route, method, path string) *astgrep.Route { //nolint:unused
	for i := range routes {
		methodMatch := strings.EqualFold(routes[i].Method, method) || method == ""
		pathMatch := routes[i].Path == path || path == ""
		if methodMatch && pathMatch {
			return &routes[i]
		}
	}
	return nil
}

// findFinding searches for a finding with the given rule ID.
func findFinding(findings []sourcetools.RawFinding, ruleID string) *sourcetools.RawFinding { //nolint:unused
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

// buildSeverityDistribution counts findings by severity level.
func buildSeverityDistribution(findings []sourcetools.RawFinding) map[string]int { //nolint:unused
	dist := make(map[string]int)
	for _, f := range findings {
		dist[f.Severity]++
	}
	return dist
}

// normalizeMethod normalizes HTTP method names.
// ANY, HANDLE, ALL, and empty strings map to GET.
func normalizeMethod(method string) string { //nolint:unused
	upper := strings.ToUpper(strings.TrimSpace(method))
	switch upper {
	case "ANY", "HANDLE", "ALL", "":
		return "GET"
	default:
		return upper
	}
}

// shouldSkipRoute returns true if the route should be skipped (empty path).
func shouldSkipRoute(route harness.HandoffRoute) bool { //nolint:unused
	return strings.TrimSpace(route.Path) == ""
}
