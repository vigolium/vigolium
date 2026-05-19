package agent

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/vigolium/vigolium/pkg/agent"
)

// fixturePath returns the absolute path to an agent fixture JSON file.
func fixturePath(name string) string { //nolint:unused
	candidates := []string{
		filepath.Join("../../testdata/agent-fixtures", name),
		filepath.Join("../testdata/agent-fixtures", name),
		filepath.Join("test/testdata/agent-fixtures", name),
	}
	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	return filepath.Join("test/testdata/agent-fixtures", name)
}

// definitionsDir returns the absolute path to the whitebox agent definitions directory.
func definitionsDir() string { //nolint:unused
	candidates := []string{
		"../definitions/whitebox/agent",
		"../../definitions/whitebox/agent",
		"test/benchmark/definitions/whitebox/agent",
	}
	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	return "test/benchmark/definitions/whitebox/agent"
}

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

// findFindingByCWE searches for a finding with the given CWE identifier.
func findFindingByCWE(findings []agent.AgentFinding, cwe string) *agent.AgentFinding { //nolint:unused
	for i := range findings {
		if findings[i].CWE == cwe {
			return &findings[i]
		}
	}
	return nil
}

// findFindingByVulnType searches for a finding whose title or tags contain the given type.
func findFindingByVulnType(findings []agent.AgentFinding, vulnType string) *agent.AgentFinding { //nolint:unused
	lower := strings.ToLower(vulnType)
	for i := range findings {
		if strings.Contains(strings.ToLower(findings[i].Title), lower) {
			return &findings[i]
		}
		for _, tag := range findings[i].Tags {
			if strings.Contains(strings.ToLower(tag), lower) {
				return &findings[i]
			}
		}
	}
	return nil
}

// findRecordByMethod searches for an HTTP record with the given method and URL prefix.
func findRecordByMethod(records []agent.AgentHTTPRecord, method, urlPrefix string) *agent.AgentHTTPRecord { //nolint:unused
	for i := range records {
		if strings.EqualFold(records[i].Method, method) &&
			strings.HasPrefix(records[i].URL, urlPrefix) {
			return &records[i]
		}
	}
	return nil
}

// buildSeverityDistribution counts findings by severity level.
func buildSeverityDistribution(findings []agent.AgentFinding) map[string]int { //nolint:unused
	dist := make(map[string]int)
	for _, f := range findings {
		if f.Severity != "" {
			dist[strings.ToLower(f.Severity)]++
		}
	}
	return dist
}
