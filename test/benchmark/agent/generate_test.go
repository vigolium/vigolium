//go:build agent_generate

package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	agentpkg "github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/test/benchmark/harness"
)

// TestGenerate_AllFixtures runs the real agent against source stubs and writes fixture JSON files.
// This is expensive (real LLM calls) and should only be run via:
//
//	make benchmark-agent-generate
//
// Environment:
//   - VIGOLIUM_AGENT: agent name to use (default: "claude")
//   - VIGOLIUM_CONFIG: path to vigolium-configs.yaml (default: auto-detect)
func TestGenerate_AllFixtures(t *testing.T) {
	agentName := os.Getenv("VIGOLIUM_AGENT")
	if agentName == "" {
		agentName = "claude"
	}

	// Load settings
	settings, err := config.LoadSettings("")
	require.NoError(t, err, "failed to load settings (set VIGOLIUM_CONFIG if needed)")

	// Verify agent is configured
	_, ok := settings.Agent.Agents[agentName]
	require.True(t, ok, "agent %q not found in configuration", agentName)

	// Create output directory
	outDir := fixtureOutputDir()
	require.NoError(t, os.MkdirAll(outDir, 0755), "failed to create output dir %s", outDir)

	// Define the matrix of (stub × template) pairs
	matrix := []struct {
		stub     string
		template string
		schema   string // "findings" or "http_records"
	}{
		{"gin", "security-code-review", "findings"},
		{"gin", "endpoint-discovery", "http_records"},
		{"gin", "api-input-gen", "http_records"},
		{"flask", "security-code-review", "findings"},
		{"flask", "endpoint-discovery", "http_records"},
		{"flask", "api-input-gen", "http_records"},
		{"express", "security-code-review", "findings"},
		{"express", "endpoint-discovery", "http_records"},
		{"django", "security-code-review", "findings"},
		{"django", "endpoint-discovery", "http_records"},
		{"fastapi", "security-code-review", "findings"},
		{"fastapi", "endpoint-discovery", "http_records"},
	}

	engine := agentpkg.NewEngine(settings, nil)
	ctx := context.Background()

	for _, m := range matrix {
		fixtureName := m.stub + "-" + m.template + ".json"
		t.Run(fixtureName, func(t *testing.T) {
			outPath := filepath.Join(outDir, fixtureName)

			// Skip if fixture already exists and is not stale
			if !shouldRegenerate(outPath) {
				t.Skipf("fixture %s exists and is not stale, skipping (delete to regenerate)", fixtureName)
				return
			}

			stubDir := stubPath(m.stub)
			require.DirExists(t, stubDir, "source stub directory not found: %s", stubDir)

			t.Logf("Running agent %q with template %q against stub %s...", agentName, m.template, m.stub)

			result, err := engine.Run(ctx, agentpkg.Options{
				AgentName:      agentName,
				PromptTemplate: m.template,
				RepoPath:       stubDir,
			})
			require.NoError(t, err, "agent run failed for %s × %s", m.stub, m.template)
			require.NotEmpty(t, result.RawOutput, "agent returned empty output for %s × %s", m.stub, m.template)

			// Build fixture
			fixture := harness.AgentFixture{
				Metadata: harness.AgentFixtureMetadata{
					Stub:         m.stub,
					Template:     m.template,
					AgentName:    agentName,
					OutputSchema: m.schema,
					GeneratedAt:  time.Now().UTC(),
				},
				RawOutput: result.RawOutput,
			}

			// Pre-parse to populate counts
			switch m.schema {
			case "findings":
				if findings, err := agentpkg.ParseFindings(result.RawOutput); err == nil {
					fixture.Parsed.FindingCount = len(findings)
				}
			case "http_records":
				if records, err := agentpkg.ParseHTTPRecords(result.RawOutput); err == nil {
					fixture.Parsed.RecordCount = len(records)
				}
			}

			// Write fixture
			data, err := json.MarshalIndent(fixture, "", "  ")
			require.NoError(t, err, "failed to marshal fixture for %s", fixtureName)

			require.NoError(t, os.WriteFile(outPath, data, 0644),
				"failed to write fixture %s", outPath)

			t.Logf("Written fixture: %s (findings=%d, records=%d)",
				fixtureName, fixture.Parsed.FindingCount, fixture.Parsed.RecordCount)
		})
	}
}

// fixtureOutputDir returns the target directory for generated fixtures.
func fixtureOutputDir() string {
	candidates := []string{
		"../../testdata/agent-fixtures",
		"../testdata/agent-fixtures",
		"test/testdata/agent-fixtures",
	}
	for _, c := range candidates {
		if abs, err := filepath.Abs(c); err == nil {
			if _, err := os.Stat(abs); err == nil {
				return abs
			}
		}
	}
	// Default: create relative to test directory
	abs, _ := filepath.Abs("../../testdata/agent-fixtures")
	return abs
}

// shouldRegenerate returns true if the fixture file should be regenerated.
// Returns true if file doesn't exist or is older than 30 days.
func shouldRegenerate(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return true // file doesn't exist
	}
	return time.Since(info.ModTime()) > 30*24*time.Hour
}
