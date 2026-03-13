//go:build e2e

package e2e

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
)

// Test flags for running swarm tests with real agents.
// Usage: go test -v -tags=e2e -run TestSwarmRealAgent ./test/e2e/ -agent=opencode -target=http://localhost:3000
var (
	testAgentName = flag.String("agent", "", "Real agent name from vigolium-configs.yaml (e.g. opencode, codex, claude)")
	testTargetURL = flag.String("target", "http://localhost:3000/", "Target URL for real agent tests")
	testConfigPath = flag.String("config", "", "Path to vigolium-configs.yaml (default: auto-discover)")
)

// fakeSwarmAgentScript returns a shell script path that outputs a valid swarm plan
// in markdown section format. The script is written to a temp dir and made executable.
func fakeSwarmAgentScript(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-swarm-agent.sh")
	content := `#!/bin/sh
# Consume stdin (required for pipe-protocol agents)
cat > /dev/null
# Output a valid markdown-format swarm plan
cat <<'PLAN'
## MODULE_TAGS
discovery, fingerprint, light

## FOCUS_AREAS
- Technology fingerprinting on root endpoint
- Sensitive file exposure

## NOTES
Target is a local HTTP service. Broad recon scan recommended.
PLAN
`
	require.NoError(t, os.WriteFile(script, []byte(content), 0755))
	return script
}

// fakeTriageAgentScript returns a script that outputs a valid triage result (verdict: done).
func fakeTriageAgentScript(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-triage-agent.sh")
	content := `#!/bin/sh
cat > /dev/null
cat <<'TRIAGE'
{"confirmed":[],"false_positives":[],"verdict":"done","notes":"no findings to triage"}
TRIAGE
`
	require.NoError(t, os.WriteFile(script, []byte(content), 0755))
	return script
}

// fakeSwarmAgentWithExtensions returns a script that outputs a plan with quick checks and extensions.
func fakeSwarmAgentWithExtensions(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-swarm-ext-agent.sh")
	// Use a heredoc-safe approach: the JS code block uses its own delimiters
	content := "#!/bin/sh\ncat > /dev/null\ncat <<'PLAN'\n" +
		"## MODULE_TAGS\nsqli, xss, injection\n\n" +
		"## MODULE_IDS\nsqli-error-based\n\n" +
		"## FOCUS_AREAS\n- SQL injection in query parameters\n- Reflected XSS\n\n" +
		"## NOTES\nLocal development server, likely Express.js or similar.\n\n" +
		"```json\n" +
		`[{"id":"ssti-check","scan":"per_insertion_point","severity":"high","payloads":["{{7*7}}"],"match":{"body_contains":"49"}}]` +
		"\n```\n\n" +
		"#### custom-path-traversal.js\nReason: Check for path traversal to admin endpoints\n\n" +
		"```javascript\n" +
		"module.exports = {\n" +
		`    id: "custom-path-traversal",` + "\n" +
		`    name: "Path Traversal Admin",` + "\n" +
		`    type: "active",` + "\n" +
		`    severity: "high",` + "\n" +
		`    confidence: "tentative",` + "\n" +
		`    tags: ["custom"],` + "\n" +
		`    scanTypes: ["per_request"],` + "\n" +
		"    scanPerRequest: function(ctx) { return null; }\n" +
		"};\n" +
		"```\n" +
		"PLAN\n"
	require.NoError(t, os.WriteFile(script, []byte(content), 0755))
	return script
}

func newSwarmTestSettings(t *testing.T, agentName, scriptPath string) *config.Settings {
	t.Helper()
	backends := map[string]config.AgentDef{
		agentName: {
			Command:     scriptPath,
			Description: "Fake swarm agent for e2e testing",
		},
	}
	return &config.Settings{
		Agent: config.AgentConfig{
			DefaultAgent: agentName,
			Backends:     backends,
		},
	}
}

// TestSwarmBasicPlan tests the happy path: normalize → plan phase with a fake agent
// that returns a valid markdown-format swarm plan.
func TestSwarmBasicPlan(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	agentName := "fake-swarm"
	script := fakeSwarmAgentScript(t)
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs:        []string{"http://localhost:12345/"},
		AgentName:     agentName,
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		// Skip scan/triage by providing no ScanFunc — the swarm should still
		// complete the plan phase and produce a SwarmPlan.
		SkipPhases: []string{"scan", "triage", "rescan"},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)

	// Verify result structure
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.AgentRunUUID)
	assert.Equal(t, 1, result.TotalRecords)

	// Verify the plan was parsed correctly
	require.NotNil(t, result.SwarmPlan, "expected a parsed swarm plan")
	plan := result.SwarmPlan
	assert.Contains(t, plan.ModuleTags, "discovery")
	assert.Contains(t, plan.ModuleTags, "fingerprint")
	assert.Contains(t, plan.ModuleTags, "light")
	assert.NotEmpty(t, plan.FocusAreas)
	assert.NotEmpty(t, plan.Notes)
}

// TestSwarmPlanWithExtensions tests that quick checks and JS extensions from the
// master agent are correctly parsed and written to the session directory.
func TestSwarmPlanWithExtensions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	agentName := "fake-swarm-ext"
	script := fakeSwarmAgentWithExtensions(t)
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs:        []string{"http://localhost:12345/api/search?q=test"},
		AgentName:     agentName,
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		SkipPhases:    []string{"scan", "triage", "rescan"},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result.SwarmPlan)

	plan := result.SwarmPlan

	// Verify module tags
	assert.Contains(t, plan.ModuleTags, "sqli")
	assert.Contains(t, plan.ModuleTags, "xss")

	// Verify module IDs
	assert.Contains(t, plan.ModuleIDs, "sqli-error-based")

	// Verify focus areas
	assert.GreaterOrEqual(t, len(plan.FocusAreas), 1)

	// Verify quick checks were parsed
	assert.GreaterOrEqual(t, len(plan.QuickChecks), 1, "expected at least 1 quick check")
	if len(plan.QuickChecks) > 0 {
		assert.Equal(t, "ssti-check", plan.QuickChecks[0].ID)
		assert.Equal(t, "per_insertion_point", plan.QuickChecks[0].Scan)
	}

	// Verify extensions were parsed
	assert.GreaterOrEqual(t, len(plan.Extensions), 1, "expected at least 1 extension")
	if len(plan.Extensions) > 0 {
		assert.Equal(t, "custom-path-traversal.js", plan.Extensions[0].Filename)
		assert.NotEmpty(t, plan.Extensions[0].Code)
		assert.NotEmpty(t, plan.Extensions[0].Reason)
	}

	// Verify extensions were written to session dir
	extDir := filepath.Join(sessionDir, "extensions")
	if _, err := os.Stat(extDir); err == nil {
		entries, _ := os.ReadDir(extDir)
		assert.GreaterOrEqual(t, len(entries), 1, "expected extension files in session dir")
	}
}

// TestSwarmEmptyAgentOutput tests that the swarm correctly handles an agent that
// returns empty output (the exact failure mode from the user's error log).
func TestSwarmEmptyAgentOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	// Agent that produces empty output (simulates the opencode ACP bug)
	dir := t.TempDir()
	emptyScript := filepath.Join(dir, "empty-agent.sh")
	require.NoError(t, os.WriteFile(emptyScript, []byte("#!/bin/sh\ncat > /dev/null\n"), 0755))

	agentName := "empty-agent"
	settings := newSwarmTestSettings(t, agentName, emptyScript)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs:        []string{"http://localhost:12345/"},
		AgentName:     agentName,
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
	}

	result, err := swarmRunner.Run(ctx, cfg)

	// Should fail with a parse error, not panic
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse swarm plan")
	// Result should still be returned (with the agent run UUID for debugging)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.AgentRunUUID)
}

// TestSwarmDryRun tests that --dry-run renders prompts without executing agents.
func TestSwarmDryRun(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	agentName := "fake-swarm"
	script := fakeSwarmAgentScript(t)
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs:      []string{"http://localhost:12345/"},
		AgentName:   agentName,
		DryRun:      true,
		ProjectUUID: database.DefaultProjectUUID,
		SessionDir:  sessionDir,
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	assert.NotNil(t, result)
	// In dry-run mode, no plan is parsed (prompt is just rendered)
	assert.Nil(t, result.SwarmPlan)
}

// TestSwarmWithCustomAgentName tests that the --agent flag correctly routes to
// the specified agent backend, catching configuration mismatches early.
func TestSwarmWithCustomAgentName(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	// Register multiple agents and verify the correct one is used
	script := fakeSwarmAgentScript(t)
	settings := &config.Settings{
		Agent: config.AgentConfig{
			DefaultAgent: "default-agent",
			Backends: map[string]config.AgentDef{
				"default-agent": {
					Command:     "/bin/false", // would fail if used
					Description: "Should not be used",
				},
				"custom-agent": {
					Command:     script,
					Description: "Custom test agent",
				},
			},
		},
	}

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs:        []string{"http://localhost:12345/"},
		AgentName:     "custom-agent", // explicit agent name
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		SkipPhases:    []string{"scan", "triage", "rescan"},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result.SwarmPlan, "expected plan from custom-agent")
	assert.Contains(t, result.SwarmPlan.ModuleTags, "discovery")
}

// TestSwarmAgentNotFound tests that specifying a non-existent agent name
// produces a clear error early in the pipeline.
func TestSwarmAgentNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	settings := &config.Settings{
		Agent: config.AgentConfig{
			DefaultAgent: "fake-agent",
			Backends: map[string]config.AgentDef{
				"fake-agent": {
					Command:     "cat",
					Description: "Only agent available",
				},
			},
		},
	}

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs:      []string{"http://localhost:12345/"},
		AgentName:   "nonexistent-agent",
		ProjectUUID: database.DefaultProjectUUID,
		SessionDir:  sessionDir,
	}

	result, err := swarmRunner.Run(ctx, cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent-agent")
	assert.NotNil(t, result)
}

// TestSwarmCheckpointWrite tests that checkpoints are written to the session dir.
func TestSwarmCheckpointWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	agentName := "fake-swarm"
	script := fakeSwarmAgentScript(t)
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs:        []string{"http://localhost:12345/"},
		AgentName:     agentName,
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		SkipPhases:    []string{"scan", "triage", "rescan"},
	}

	_, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)

	// Verify checkpoint file exists
	checkpointPath := filepath.Join(sessionDir, "checkpoint.json")
	_, statErr := os.Stat(checkpointPath)
	assert.NoError(t, statErr, "expected checkpoint.json in session dir")

	// Verify prompt file exists
	promptPath := filepath.Join(sessionDir, "prompt-master.md")
	_, statErr = os.Stat(promptPath)
	assert.NoError(t, statErr, "expected prompt-master.md in session dir")
}

// TestSwarmMultipleInputs tests the swarm with multiple URL inputs.
func TestSwarmMultipleInputs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	agentName := "fake-swarm"
	script := fakeSwarmAgentScript(t)
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs: []string{
			"http://localhost:12345/",
			"http://localhost:12345/api/users",
			"http://localhost:12345/api/products?q=test",
		},
		AgentName:     agentName,
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		SkipPhases:    []string{"scan", "triage", "rescan"},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	assert.Equal(t, 3, result.TotalRecords, "expected 3 records from 3 URL inputs")
	require.NotNil(t, result.SwarmPlan)
}

// TestSwarmVulnTypeFocus tests that --vuln-type is forwarded to the agent prompt.
func TestSwarmVulnTypeFocus(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	agentName := "fake-swarm"
	script := fakeSwarmAgentScript(t)
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs:      []string{"http://localhost:12345/"},
		AgentName:   agentName,
		VulnType:    "sqli",
		DryRun:      true, // just verify prompt rendering includes vuln type
		ProjectUUID: database.DefaultProjectUUID,
		SessionDir:  sessionDir,
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Check that the prompt file contains the vuln type focus
	promptPath := filepath.Join(sessionDir, "prompt-master.md")
	if data, readErr := os.ReadFile(promptPath); readErr == nil {
		assert.Contains(t, string(data), "sqli", "expected vuln type in rendered prompt")
	}
}

// loadRealAgentSettings loads settings from vigolium-configs.yaml and validates
// that the requested agent exists and is enabled.
func loadRealAgentSettings(t *testing.T, agentName string) *config.Settings {
	t.Helper()
	settings, err := config.LoadSettings(*testConfigPath)
	require.NoError(t, err, "failed to load vigolium-configs.yaml (use -config to specify path)")

	def, ok := settings.Agent.Backends[agentName]
	if !ok {
		available := make([]string, 0, len(settings.Agent.Backends))
		for k := range settings.Agent.Backends {
			available = append(available, k)
		}
		t.Fatalf("agent %q not found in config. Available agents: %v", agentName, available)
	}
	require.True(t, def.IsEnabled(), "agent %q is disabled in config", agentName)
	t.Logf("Using agent: %s (command: %s, args: %v, protocol: %s)",
		agentName, def.Command, def.Args, def.EffectiveProtocol())
	return settings
}

// TestSwarmRealAgent runs the swarm plan phase with a real agent backend.
// Skipped unless -agent flag is provided.
//
// Usage:
//
//	go test -v -tags=e2e -run TestSwarmRealAgent ./test/e2e/ -agent=opencode
//	go test -v -tags=e2e -run TestSwarmRealAgent ./test/e2e/ -agent=codex -target=http://localhost:3000/
//	go test -v -tags=e2e -run TestSwarmRealAgent ./test/e2e/ -agent=claude -target=http://example.com/api/search?q=test
func TestSwarmRealAgent(t *testing.T) {
	if *testAgentName == "" {
		t.Skip("Skipping: use -agent=<name> to run with a real agent (e.g. -agent=opencode)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	settings := loadRealAgentSettings(t, *testAgentName)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs:        []string{*testTargetURL},
		AgentName:     *testAgentName,
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		SkipPhases:    []string{"scan", "triage", "rescan"},
	}

	t.Logf("Running swarm plan phase with agent=%s target=%s", *testAgentName, *testTargetURL)

	result, err := swarmRunner.Run(ctx, cfg)
	if err != nil {
		// Log the session dir for debugging
		t.Logf("Session dir: %s", sessionDir)
		// Log raw prompt if available
		if data, readErr := os.ReadFile(filepath.Join(sessionDir, "prompt-master.md")); readErr == nil {
			t.Logf("Rendered prompt (%d bytes):\n%s", len(data), string(data))
		}
		t.Fatalf("swarm failed: %v", err)
	}

	require.NotNil(t, result)
	t.Logf("Agent run UUID: %s", result.AgentRunUUID)
	t.Logf("Total records: %d", result.TotalRecords)
	t.Logf("Duration: %s", result.Duration)

	require.NotNil(t, result.SwarmPlan, "expected a parsed swarm plan from %s", *testAgentName)
	plan := result.SwarmPlan

	t.Logf("Module tags: %v", plan.ModuleTags)
	t.Logf("Module IDs: %v", plan.ModuleIDs)
	t.Logf("Focus areas: %v", plan.FocusAreas)
	t.Logf("Notes: %s", plan.Notes)
	t.Logf("Extensions: %d", len(plan.Extensions))
	t.Logf("Quick checks: %d", len(plan.QuickChecks))
	t.Logf("Snippets: %d", len(plan.Snippets))

	// The plan must have at least some content
	assert.True(t,
		len(plan.ModuleTags) > 0 || len(plan.ModuleIDs) > 0 || len(plan.FocusAreas) > 0 || plan.Notes != "",
		"expected plan to have at least one of: module_tags, module_ids, focus_areas, or notes")

	// Log extensions for debugging
	for i, ext := range plan.Extensions {
		t.Logf("Extension[%d]: %s (reason: %s, code: %d bytes)", i, ext.Filename, ext.Reason, len(ext.Code))
	}
	for i, qc := range plan.QuickChecks {
		t.Logf("QuickCheck[%d]: %s (scan: %s, payloads: %d)", i, qc.ID, qc.Scan, len(qc.Payloads))
	}
}

// TestSwarmRealAgentDryRun renders the full swarm prompt with a real agent config
// without actually executing the agent. Useful for verifying prompt rendering.
//
// Usage:
//
//	go test -v -tags=e2e -run TestSwarmRealAgentDryRun ./test/e2e/ -agent=opencode
func TestSwarmRealAgentDryRun(t *testing.T) {
	if *testAgentName == "" {
		t.Skip("Skipping: use -agent=<name> to run with a real agent config")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	settings := loadRealAgentSettings(t, *testAgentName)

	engine := agent.NewEngine(settings, repo)
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs:      []string{*testTargetURL},
		AgentName:   *testAgentName,
		DryRun:      true,
		ProjectUUID: database.DefaultProjectUUID,
		SessionDir:  sessionDir,
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// Print the rendered prompt for inspection
	promptPath := filepath.Join(sessionDir, "prompt-master.md")
	data, readErr := os.ReadFile(promptPath)
	require.NoError(t, readErr, "expected prompt file in session dir")
	t.Logf("Rendered prompt (%d bytes):\n%s", len(data), string(data))

	// Verify prompt doesn't contain unresolved template variables
	prompt := string(data)
	assert.NotContains(t, prompt, "{{.", "prompt contains unresolved template variable")
	assert.NotContains(t, prompt, "<no value>", "prompt contains unresolved template variable")
}

// TestSwarmRealAgentShowPrompt runs the swarm with --show-prompt to stderr for debugging.
//
// Usage:
//
//	go test -v -tags=e2e -run TestSwarmRealAgentShowPrompt ./test/e2e/ -agent=opencode -target=http://localhost:3000/
func TestSwarmRealAgentShowPrompt(t *testing.T) {
	if *testAgentName == "" {
		t.Skip("Skipping: use -agent=<name> to run with a real agent")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	settings := loadRealAgentSettings(t, *testAgentName)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs:        []string{*testTargetURL},
		AgentName:     *testAgentName,
		ShowPrompt:    true,
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		SkipPhases:    []string{"scan", "triage", "rescan"},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	if err != nil {
		t.Logf("Session dir: %s", sessionDir)

		// Dump raw output if available
		outputPath := filepath.Join(sessionDir, "output.txt")
		if data, readErr := os.ReadFile(outputPath); readErr == nil {
			t.Logf("Raw agent output:\n%s", string(data))
		}

		t.Fatalf("swarm failed with agent %s: %v", *testAgentName, err)
	}

	require.NotNil(t, result.SwarmPlan, "expected a parsed swarm plan")
	plan := result.SwarmPlan
	t.Logf("Plan: tags=%v ids=%v focus=%v exts=%d qc=%d notes=%q",
		plan.ModuleTags, plan.ModuleIDs, plan.FocusAreas,
		len(plan.Extensions), len(plan.QuickChecks), plan.Notes)

	// Dump token usage if available
	if result.TokenUsage.InputTokens > 0 || result.TokenUsage.OutputTokens > 0 {
		t.Logf("Token usage: input=%d output=%d", result.TokenUsage.InputTokens, result.TokenUsage.OutputTokens)
	}
}

// TestSwarmRealAgentMultipleInputs runs with multiple URLs to test batching behavior.
//
// Usage:
//
//	go test -v -tags=e2e -run TestSwarmRealAgentMultipleInputs ./test/e2e/ -agent=opencode -target=http://localhost:3000
func TestSwarmRealAgentMultipleInputs(t *testing.T) {
	if *testAgentName == "" {
		t.Skip("Skipping: use -agent=<name> to run with a real agent")
	}

	target := *testTargetURL

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	settings := loadRealAgentSettings(t, *testAgentName)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs: []string{
			target,
			fmt.Sprintf("%s/api/users", target),
			fmt.Sprintf("%s/api/products?q=test", target),
		},
		AgentName:     *testAgentName,
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		SkipPhases:    []string{"scan", "triage", "rescan"},
	}

	t.Logf("Running with %d inputs against agent=%s", len(cfg.Inputs), *testAgentName)

	result, err := swarmRunner.Run(ctx, cfg)
	if err != nil {
		t.Logf("Session dir: %s", sessionDir)
		t.Fatalf("swarm failed: %v", err)
	}

	require.NotNil(t, result.SwarmPlan)
	t.Logf("Records: %d, Plan: tags=%v focus=%v exts=%d",
		result.TotalRecords, result.SwarmPlan.ModuleTags,
		result.SwarmPlan.FocusAreas, len(result.SwarmPlan.Extensions))
}
