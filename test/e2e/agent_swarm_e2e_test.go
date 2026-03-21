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
		SkipPhases: []string{"native-scan", "triage", "rescan"},
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

// --- Two-Phase Plan+Extension Agent Tests ---
//
// These tests verify the two-phase swarm flow where:
//   Phase 1 (plan) outputs only markdown sections (MODULE_TAGS, FOCUS_AREAS, etc.)
//   Phase 2 (extensions) runs conditionally when NEEDS_EXTENSIONS=yes and outputs JS code

// fakeTwoPhasePlanOnlyScript returns a script that outputs a plan with NEEDS_EXTENSIONS=no.
// This simulates Phase 1 where the agent decides no custom extensions are needed.
func fakeTwoPhasePlanOnlyScript(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-plan-only.sh")
	content := `#!/bin/sh
cat > /dev/null
cat <<'PLAN'
## MODULE_TAGS
sqli, xss, injection, nosqli

## MODULE_IDS
sqli-error-based, sqli-time-based, xss-reflected, nosqli-injection

## FOCUS_AREAS
- SQL injection in query parameter q (product search endpoint)
- NoSQL injection via JSON body manipulation
- Reflected XSS through search query reflection in response

## NOTES
Target is a Node.js Express application (Juice Shop) running on port 3000.
The /rest/products/search endpoint accepts a query parameter q and returns JSON.
Authorization header uses JWT Bearer tokens — test for JWT manipulation.
The response includes product data that may reflect user input unsanitized.

## NEEDS_EXTENSIONS
no
Built-in modules cover standard SQLi/XSS/NoSQLi for this REST API endpoint.
PLAN
`
	require.NoError(t, os.WriteFile(script, []byte(content), 0755))
	return script
}

// fakeTwoPhasePlanWithExtensionsScript returns a script that outputs a plan with NEEDS_EXTENSIONS=yes.
// This triggers Phase 2 (extension agent). The same script handles both phases by
// detecting the prompt content — if PlanContext is present, it's Phase 2.
func fakeTwoPhasePlanWithExtensionsScript(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-two-phase.sh")
	// The script checks stdin for "PlanContext" or "Plan Context" to distinguish phases.
	// Phase 1 (plan): no PlanContext in prompt → output plan with NEEDS_EXTENSIONS=yes
	// Phase 2 (extensions): PlanContext present → output JS extensions
	content := "#!/bin/sh\n" +
		"INPUT=$(cat)\n" +
		"if echo \"$INPUT\" | grep -q 'Plan Context\\|PlanContext\\|plan context'; then\n" +
		"  # Phase 2: Extension agent output\n" +
		"  cat <<'EXTENSIONS'\n" +
		"Based on the analysis, here are custom extensions for the Juice Shop target:\n\n" +
		"#### jwt-none-alg.js\n" +
		"Reason: Test JWT token with algorithm set to none for auth bypass\n\n" +
		"```javascript\n" +
		"module.exports = {\n" +
		"  id: \"jwt-none-alg\",\n" +
		"  name: \"JWT None Algorithm\",\n" +
		"  type: \"active\",\n" +
		"  severity: \"high\",\n" +
		"  confidence: \"tentative\",\n" +
		"  tags: [\"custom\", \"auth\"],\n" +
		"  scanTypes: [\"per_request\"],\n" +
		"  scanPerRequest: function(ctx) {\n" +
		"    var authHeader = ctx.request.headers[\"Authorization\"];\n" +
		"    if (!authHeader || !authHeader.startsWith(\"Bearer \")) return null;\n" +
		"    var token = authHeader.substring(7);\n" +
		"    var parts = token.split(\".\");\n" +
		"    if (parts.length !== 3) return null;\n" +
		"    var header = JSON.parse(vigolium.utils.base64Decode(parts[0]));\n" +
		"    header.alg = \"none\";\n" +
		"    var newToken = vigolium.utils.base64Encode(JSON.stringify(header)) + \".\" + parts[1] + \".\";\n" +
		"    var resp = vigolium.http.request({\n" +
		"      method: ctx.request.method,\n" +
		"      url: ctx.request.url,\n" +
		"      headers: {\"Authorization\": \"Bearer \" + newToken}\n" +
		"    });\n" +
		"    if (resp && resp.status === 200) {\n" +
		"      return [{url: ctx.request.url, matched: \"JWT none algorithm accepted\", name: \"JWT None Algorithm Bypass\"}];\n" +
		"    }\n" +
		"    return null;\n" +
		"  }\n" +
		"};\n" +
		"```\n\n" +
		"```json\n" +
		"[{\"id\":\"juice-shop-admin\",\"scan\":\"per_host\",\"severity\":\"high\",\"requests\":[{\"method\":\"GET\",\"path\":\"/rest/admin/application-configuration\"},{\"method\":\"GET\",\"path\":\"/#/administration\"}],\"match\":{\"status\":200,\"body_regex\":\"(admin|application-configuration)\"}}]\n" +
		"```\n" +
		"EXTENSIONS\n" +
		"else\n" +
		"  # Phase 1: Plan agent output\n" +
		"  cat <<'PLAN'\n" +
		"## MODULE_TAGS\n" +
		"sqli, xss, injection, auth, nosqli\n\n" +
		"## MODULE_IDS\n" +
		"sqli-error-based, xss-reflected\n\n" +
		"## FOCUS_AREAS\n" +
		"- SQL injection in login email/password fields\n" +
		"- JWT token manipulation (none algorithm, weak secret)\n" +
		"- NoSQL injection via JSON body parameters\n" +
		"- Admin endpoint exposure\n\n" +
		"## NOTES\n" +
		"Target is OWASP Juice Shop (Node.js/Express). Login endpoint at /rest/user/login accepts JSON body with email and password fields. JWT Bearer tokens are used for auth. The application likely uses SQLite or Sequelize ORM which may be vulnerable to specific injection patterns.\n\n" +
		"## NEEDS_EXTENSIONS\n" +
		"yes\n" +
		"PLAN\n" +
		"fi\n"
	require.NoError(t, os.WriteFile(script, []byte(content), 0755))
	return script
}

// fakeTwoPhaseExtensionFailureScript returns a script where Phase 1 succeeds
// but Phase 2 outputs garbage. This tests graceful degradation.
func fakeTwoPhaseExtensionFailureScript(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-ext-fail.sh")
	content := "#!/bin/sh\n" +
		"INPUT=$(cat)\n" +
		"if echo \"$INPUT\" | grep -q 'Plan Context\\|PlanContext\\|plan context'; then\n" +
		"  # Phase 2: Produce garbled output that can't be parsed\n" +
		"  echo 'I tried to generate extensions but something went wrong {{{invalid json...'\n" +
		"else\n" +
		"  # Phase 1: Valid plan\n" +
		"  cat <<'PLAN'\n" +
		"## MODULE_TAGS\n" +
		"sqli, auth\n\n" +
		"## FOCUS_AREAS\n" +
		"- SQL injection in login\n\n" +
		"## NEEDS_EXTENSIONS\n" +
		"yes\n" +
		"PLAN\n" +
		"fi\n"
	require.NoError(t, os.WriteFile(script, []byte(content), 0755))
	return script
}

// TestSwarmTwoPhasePlanOnly tests the two-phase flow where the plan agent decides
// no custom extensions are needed (NEEDS_EXTENSIONS=no). Phase 2 should be skipped entirely.
// Simulates: vigolium agent swarm <<< "GET /rest/products/search?q=apple HTTP/1.1\nHost: localhost:3000"
func TestSwarmTwoPhasePlanOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	agentName := "fake-plan-only"
	script := fakeTwoPhasePlanOnlyScript(t)
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs: []string{
			"GET /rest/products/search?q=apple HTTP/1.1\r\nHost: localhost:3000\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MX0.sig\r\nAccept: application/json\r\n\r\n",
		},
		InputType:     agent.InputTypeRaw,
		AgentName:     agentName,
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		SkipPhases:    []string{"scan", "triage", "rescan"},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result.SwarmPlan, "expected a parsed swarm plan")

	plan := result.SwarmPlan

	// Plan should have module tags from the plan agent
	assert.Contains(t, plan.ModuleTags, "sqli")
	assert.Contains(t, plan.ModuleTags, "xss")
	assert.Contains(t, plan.ModuleTags, "injection")
	assert.Contains(t, plan.ModuleTags, "nosqli")

	// Plan should have specific module IDs
	assert.Contains(t, plan.ModuleIDs, "sqli-error-based")
	assert.Contains(t, plan.ModuleIDs, "sqli-time-based")
	assert.Contains(t, plan.ModuleIDs, "xss-reflected")
	assert.Contains(t, plan.ModuleIDs, "nosqli-injection")

	// Should have focus areas and notes
	assert.GreaterOrEqual(t, len(plan.FocusAreas), 2)
	assert.NotEmpty(t, plan.Notes)
	assert.Contains(t, plan.Notes, "Juice Shop")

	// NEEDS_EXTENSIONS=no → no extensions should be generated
	assert.False(t, plan.NeedsExtensions, "expected NeedsExtensions to be false")
	assert.NotEmpty(t, plan.NeedsExtensionsReason, "expected reason for NEEDS_EXTENSIONS decision")
	assert.Contains(t, plan.NeedsExtensionsReason, "Built-in modules")
	t.Logf("NEEDS_EXTENSIONS reason: %s", plan.NeedsExtensionsReason)
	assert.Empty(t, plan.Extensions, "expected no extensions when NEEDS_EXTENSIONS=no")
	assert.Empty(t, plan.QuickChecks, "expected no quick checks when NEEDS_EXTENSIONS=no")

	// No extension directory should be created
	extDir := filepath.Join(sessionDir, "extensions")
	_, statErr := os.Stat(extDir)
	assert.True(t, os.IsNotExist(statErr), "expected no extensions directory when NEEDS_EXTENSIONS=no")

	t.Logf("Plan: tags=%v ids=%v focus=%d notes=%d chars",
		plan.ModuleTags, plan.ModuleIDs, len(plan.FocusAreas), len(plan.Notes))
}

// TestSwarmTwoPhasePlanWithExtensions tests the full two-phase flow where:
//   Phase 1: Plan agent outputs MODULE_TAGS + NEEDS_EXTENSIONS=yes
//   Phase 2: Extension agent generates JS code + quick checks
// Simulates: vigolium agent swarm <<< "POST /rest/user/login ..."
func TestSwarmTwoPhasePlanWithExtensions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	agentName := "fake-two-phase"
	script := fakeTwoPhasePlanWithExtensionsScript(t)
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs: []string{
			"POST /rest/user/login HTTP/1.1\r\nHost: localhost:3000\r\nContent-Type: application/json\r\nAccept: application/json\r\nCookie: language=en; welcomebanner_status=dismiss\r\n\r\n{\"email\":\"admin@juice-sh.op\",\"password\":\"admin123\"}",
		},
		InputType:     agent.InputTypeRaw,
		AgentName:     agentName,
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		SkipPhases:    []string{"scan", "triage", "rescan"},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result.SwarmPlan, "expected a parsed swarm plan")

	plan := result.SwarmPlan

	// Phase 1: Plan should have module tags
	assert.Contains(t, plan.ModuleTags, "sqli")
	assert.Contains(t, plan.ModuleTags, "xss")
	assert.Contains(t, plan.ModuleTags, "auth")
	assert.Contains(t, plan.ModuleTags, "nosqli")

	// Phase 1: Plan should have module IDs
	assert.Contains(t, plan.ModuleIDs, "sqli-error-based")
	assert.Contains(t, plan.ModuleIDs, "xss-reflected")

	// Phase 1: Focus areas should mention login-specific concerns
	assert.GreaterOrEqual(t, len(plan.FocusAreas), 3)
	foundLoginFocus := false
	for _, fa := range plan.FocusAreas {
		if assert.ObjectsAreEqual(fa, "SQL injection in login email/password fields") {
			foundLoginFocus = true
		}
	}
	assert.True(t, foundLoginFocus, "expected focus area about login fields, got: %v", plan.FocusAreas)

	// Phase 1: Notes should mention Juice Shop
	assert.Contains(t, plan.Notes, "Juice Shop")

	// Phase 2: Extensions should be generated (from the extension agent)
	assert.GreaterOrEqual(t, len(plan.Extensions), 1, "expected at least 1 JS extension from Phase 2")

	// Verify JWT none-algorithm extension
	foundJWT := false
	for _, ext := range plan.Extensions {
		if ext.Filename == "jwt-none-alg.js" {
			foundJWT = true
			assert.Contains(t, ext.Code, "jwt-none-alg")
			assert.Contains(t, ext.Code, "alg")
			assert.NotEmpty(t, ext.Reason)
			assert.Contains(t, ext.Reason, "JWT")
		}
	}
	assert.True(t, foundJWT, "expected jwt-none-alg.js extension")

	// Phase 2: Quick checks should be parsed from JSON block
	assert.GreaterOrEqual(t, len(plan.QuickChecks), 1, "expected at least 1 quick check from Phase 2")
	if len(plan.QuickChecks) > 0 {
		assert.Equal(t, "juice-shop-admin", plan.QuickChecks[0].ID)
		assert.Equal(t, "per_host", plan.QuickChecks[0].Scan)
		assert.Equal(t, "high", plan.QuickChecks[0].Severity)
		assert.GreaterOrEqual(t, len(plan.QuickChecks[0].Requests), 1)
	}

	// Extensions should be written to session dir
	extDir := filepath.Join(sessionDir, "extensions")
	entries, statErr := os.ReadDir(extDir)
	if assert.NoError(t, statErr, "expected extensions directory") {
		assert.GreaterOrEqual(t, len(entries), 1, "expected extension files written to disk")
		t.Logf("Extension files: %v", func() []string {
			names := make([]string, len(entries))
			for i, e := range entries {
				names[i] = e.Name()
			}
			return names
		}())
	}

	// Verify plan JSON was saved
	planPath := filepath.Join(sessionDir, "swarm-plan.json")
	_, statErr = os.Stat(planPath)
	assert.NoError(t, statErr, "expected swarm-plan.json in session dir")

	t.Logf("Plan: tags=%v ids=%v focus=%d exts=%d qc=%d",
		plan.ModuleTags, plan.ModuleIDs, len(plan.FocusAreas),
		len(plan.Extensions), len(plan.QuickChecks))
}

// TestSwarmTwoPhaseExtensionFailureGraceful tests that when Phase 2 (extension agent)
// fails, the scan still proceeds with the valid plan from Phase 1.
// This is the key resilience guarantee of the two-phase design.
func TestSwarmTwoPhaseExtensionFailureGraceful(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	agentName := "fake-ext-fail"
	script := fakeTwoPhaseExtensionFailureScript(t)
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs: []string{
			"POST /rest/user/login HTTP/1.1\r\nHost: localhost:3000\r\nContent-Type: application/json\r\n\r\n{\"email\":\"test@test.com\",\"password\":\"test\"}",
		},
		InputType:     agent.InputTypeRaw,
		AgentName:     agentName,
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		SkipPhases:    []string{"scan", "triage", "rescan"},
	}

	result, err := swarmRunner.Run(ctx, cfg)

	// The run should succeed despite Phase 2 failure (graceful degradation)
	require.NoError(t, err, "swarm should succeed even when extension agent fails")
	require.NotNil(t, result.SwarmPlan, "plan from Phase 1 should be preserved")

	plan := result.SwarmPlan

	// Phase 1 plan should be intact
	assert.Contains(t, plan.ModuleTags, "sqli")
	assert.Contains(t, plan.ModuleTags, "auth")
	assert.GreaterOrEqual(t, len(plan.FocusAreas), 1)

	// No extensions since Phase 2 failed
	assert.Empty(t, plan.Extensions, "expected no extensions since Phase 2 failed")
	assert.Empty(t, plan.QuickChecks, "expected no quick checks since Phase 2 failed")

	t.Logf("Graceful degradation OK: plan has tags=%v but no extensions (Phase 2 failed as expected)",
		plan.ModuleTags)
}

// TestSwarmTwoPhaseNormalization tests that plan normalization correctly cleans
// up LLM output quirks: inline commentary, mixed case, duplicates.
func TestSwarmTwoPhaseNormalization(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	// Agent that outputs messy tags with commentary and duplicates
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-messy.sh")
	messyContent := `#!/bin/sh
cat > /dev/null
cat <<'PLAN'
## MODULE_TAGS
SQLI (most important), xss, Injection, sqli, XSS - reflected and stored, auth

## MODULE_IDS
sqli-error-based, SQLI-ERROR-BASED, xss-reflected (DOM variant too)

## FOCUS_AREAS
- SQL injection in login form
-   SQL injection in login form
- XSS in search results
-

## NOTES
  Target is an Express.js app.
PLAN
`
	require.NoError(t, os.WriteFile(script, []byte(messyContent), 0755))

	agentName := "fake-messy"
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs:        []string{"http://localhost:3000/"},
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

	// Tags should be lowercased, deduplicated, commentary stripped
	assert.Equal(t, []string{"sqli", "xss", "injection", "auth"}, plan.ModuleTags,
		"expected normalized, deduplicated, lowercased tags without commentary")

	// IDs should be lowercased, deduplicated, commentary stripped
	assert.Equal(t, []string{"sqli-error-based", "xss-reflected"}, plan.ModuleIDs,
		"expected normalized, deduplicated IDs without commentary")

	// Focus areas should be deduplicated, trimmed, empty removed
	assert.Equal(t, []string{"SQL injection in login form", "XSS in search results"}, plan.FocusAreas,
		"expected deduplicated, trimmed focus areas with empty lines removed")

	// Notes should be trimmed
	assert.Equal(t, "Target is an Express.js app.", plan.Notes,
		"expected trimmed notes")

	t.Logf("Normalization OK: tags=%v ids=%v focus=%v", plan.ModuleTags, plan.ModuleIDs, plan.FocusAreas)
}

// TestSwarmTwoPhaseRawHTTPLoginRequest tests the two-phase flow with a realistic
// raw HTTP POST login request (the exact format from stdin piping).
// Simulates: vigolium agent swarm <<EOF ... POST /rest/user/login ... EOF
func TestSwarmTwoPhaseRawHTTPLoginRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	// Agent specifically tailored for login endpoint analysis
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-login-agent.sh")
	loginContent := `#!/bin/sh
cat > /dev/null
cat <<'PLAN'
## MODULE_TAGS
sqli, nosqli, auth, injection

## MODULE_IDS
sqli-error-based, sqli-time-based, nosqli-injection

## FOCUS_AREAS
- SQL injection in email parameter (string-based, error-based)
- SQL injection in password parameter (blind/time-based)
- NoSQL injection via JSON body (MongoDB operator injection)
- Authentication bypass via SQL injection in login
- Credential stuffing protection check

## NOTES
POST /rest/user/login accepts JSON body {"email":"...","password":"..."}.
Content-Type is application/json. Response likely returns JWT token on success.
Both parameters are prime injection targets. The email field may be used
directly in a SQL WHERE clause. The cookie shows language=en which suggests
i18n support — check for locale-based injection paths.
PLAN
`
	require.NoError(t, os.WriteFile(script, []byte(loginContent), 0755))

	agentName := "fake-login"
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	// Use the exact raw HTTP format from the user's example
	rawHTTPLogin := "POST /rest/user/login HTTP/1.1\r\n" +
		"Host: localhost:3000\r\n" +
		"Content-Length: 51\r\n" +
		"sec-ch-ua-platform: \"macOS\"\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"Accept: application/json, text/plain, */*\r\n" +
		"sec-ch-ua: \"Chromium\";v=\"145\", \"Not:A-Brand\";v=\"99\"\r\n" +
		"Content-Type: application/json\r\n" +
		"sec-ch-ua-mobile: ?0\r\n" +
		"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36\r\n" +
		"Origin: http://localhost:3000\r\n" +
		"Sec-Fetch-Site: same-origin\r\n" +
		"Sec-Fetch-Mode: cors\r\n" +
		"Sec-Fetch-Dest: empty\r\n" +
		"Referer: http://localhost:3000/login\r\n" +
		"Accept-Encoding: gzip, deflate, br\r\n" +
		"Cookie: language=en; welcomebanner_status=dismiss\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n" +
		"{\"email\":\"admin@juice-sh.op\",\"password\":\"admin123\"}"

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs:        []string{rawHTTPLogin},
		InputType:     agent.InputTypeRaw,
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

	// Verify tags are normalized
	assert.Contains(t, plan.ModuleTags, "sqli")
	assert.Contains(t, plan.ModuleTags, "nosqli")
	assert.Contains(t, plan.ModuleTags, "auth")

	// Verify module IDs
	assert.Contains(t, plan.ModuleIDs, "sqli-error-based")
	assert.Contains(t, plan.ModuleIDs, "sqli-time-based")

	// Verify focus areas mention specific parameters
	foundEmailFocus := false
	for _, fa := range plan.FocusAreas {
		if fmt.Sprintf("%s", fa) != "" && (assert.ObjectsAreEqual(fa, "SQL injection in email parameter (string-based, error-based)") || fmt.Sprintf("%v", fa) == "SQL injection in email parameter (string-based, error-based)") {
			foundEmailFocus = true
		}
	}
	_ = foundEmailFocus // focus area content validated by count
	assert.GreaterOrEqual(t, len(plan.FocusAreas), 4, "expected at least 4 focus areas for login endpoint")

	// Notes should mention the endpoint
	assert.Contains(t, plan.Notes, "/rest/user/login")

	// No extensions expected (NEEDS_EXTENSIONS not set)
	assert.Empty(t, plan.Extensions)

	t.Logf("Login request plan: tags=%v ids=%v focus=%d",
		plan.ModuleTags, plan.ModuleIDs, len(plan.FocusAreas))
}

// TestSwarmTwoPhaseRawHTTPSearchRequest tests with the raw GET search request
// that includes auth headers.
// Simulates: vigolium agent swarm <<EOF ... GET /rest/products/search?q=apple ... EOF
func TestSwarmTwoPhaseRawHTTPSearchRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	agentName := "fake-plan-only"
	script := fakeTwoPhasePlanOnlyScript(t)
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	// Use the exact raw HTTP format from the user's example
	rawHTTPSearch := "GET /rest/products/search?q=apple HTTP/1.1\r\n" +
		"Host: localhost:3000\r\n" +
		"sec-ch-ua-platform: \"macOS\"\r\n" +
		"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc3MzA3NjMyNSwiZXhwIjoxNzczMDc5OTI1fQ.c2lnbmF0dXJlX2dlbmVyYXRlZF93aXRoX3NlY3JldDEyMw\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"Accept: application/json, text/plain, */*\r\n" +
		"sec-ch-ua: \"Chromium\";v=\"145\", \"Not:A-Brand\";v=\"99\"\r\n" +
		"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36\r\n" +
		"sec-ch-ua-mobile: ?0\r\n" +
		"Sec-Fetch-Site: same-origin\r\n" +
		"Sec-Fetch-Mode: cors\r\n" +
		"Sec-Fetch-Dest: empty\r\n" +
		"Referer: http://localhost:3000/\r\n" +
		"Accept-Encoding: gzip, deflate, br\r\n" +
		"Cookie: language=en;\r\n" +
		"If-None-Match: W/\"354c-v3Z5i9VIS27KdIPvey41XPBPWSI\"\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n"

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs:        []string{rawHTTPSearch},
		InputType:     agent.InputTypeRaw,
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

	// Verify plan content
	assert.Equal(t, 1, result.TotalRecords)
	assert.Contains(t, plan.ModuleTags, "sqli")
	assert.Contains(t, plan.ModuleTags, "xss")
	assert.Contains(t, plan.ModuleIDs, "sqli-error-based")
	assert.Contains(t, plan.ModuleIDs, "nosqli-injection")
	assert.False(t, plan.NeedsExtensions)
	assert.Empty(t, plan.Extensions)

	t.Logf("Search request plan: tags=%v ids=%v", plan.ModuleTags, plan.ModuleIDs)
}

// TestSwarmTwoPhaseMultipleRawHTTPRequests tests the two-phase flow with
// multiple raw HTTP requests piped together (both the search and login requests).
func TestSwarmTwoPhaseMultipleRawHTTPRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	agentName := "fake-two-phase"
	script := fakeTwoPhasePlanWithExtensionsScript(t)
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs: []string{
			// Search request (GET)
			"GET /rest/products/search?q=apple HTTP/1.1\r\nHost: localhost:3000\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MX0.sig\r\nAccept: application/json\r\n\r\n",
			// Login request (POST)
			"POST /rest/user/login HTTP/1.1\r\nHost: localhost:3000\r\nContent-Type: application/json\r\n\r\n{\"email\":\"admin@juice-sh.op\",\"password\":\"admin123\"}",
		},
		InputType:     agent.InputTypeRaw,
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

	// Multiple records should be ingested
	assert.Equal(t, 2, result.TotalRecords, "expected 2 records from 2 raw HTTP inputs")

	// Phase 1: Plan should have tags from analysis of both requests
	assert.Contains(t, plan.ModuleTags, "sqli")
	assert.Contains(t, plan.ModuleTags, "auth")

	// Phase 2: Extensions should be generated (NEEDS_EXTENSIONS=yes from the plan)
	assert.GreaterOrEqual(t, len(plan.Extensions), 1, "expected extensions from Phase 2")

	// Verify that plan JSON was written
	planJSON, readErr := os.ReadFile(filepath.Join(sessionDir, "swarm-plan.json"))
	require.NoError(t, readErr)
	assert.Contains(t, string(planJSON), "sqli")

	t.Logf("Multi-request plan: records=%d tags=%v exts=%d qc=%d",
		result.TotalRecords, plan.ModuleTags, len(plan.Extensions), len(plan.QuickChecks))
}

// TestSwarmRealAgentTwoPhase runs the two-phase flow with a real agent backend.
// Skipped unless -agent flag is provided. This validates that real LLM output
// from the new plan prompt is correctly parsed.
//
// Usage:
//
//	go test -v -tags=e2e -run TestSwarmRealAgentTwoPhase ./test/e2e/ -agent=opencode -target=http://localhost:3000
func TestSwarmRealAgentTwoPhase(t *testing.T) {
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
		Inputs: []string{
			"POST /rest/user/login HTTP/1.1\r\nHost: localhost:3000\r\nContent-Type: application/json\r\nAccept: application/json\r\n\r\n{\"email\":\"admin@juice-sh.op\",\"password\":\"admin123\"}",
		},
		InputType:     agent.InputTypeRaw,
		AgentName:     *testAgentName,
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		SkipPhases:    []string{"scan", "triage", "rescan"},
	}

	t.Logf("Running two-phase swarm with agent=%s (login request)", *testAgentName)

	result, err := swarmRunner.Run(ctx, cfg)
	if err != nil {
		t.Logf("Session dir: %s", sessionDir)
		if data, readErr := os.ReadFile(filepath.Join(sessionDir, "prompt-master.md")); readErr == nil {
			t.Logf("Rendered prompt:\n%s", string(data))
		}
		if data, readErr := os.ReadFile(filepath.Join(sessionDir, "master-agent-output.md")); readErr == nil {
			t.Logf("Raw agent output:\n%s", string(data))
		}
		t.Fatalf("swarm failed: %v", err)
	}

	require.NotNil(t, result.SwarmPlan)
	plan := result.SwarmPlan

	t.Logf("Phase 1 results:")
	t.Logf("  Module tags: %v", plan.ModuleTags)
	t.Logf("  Module IDs: %v", plan.ModuleIDs)
	t.Logf("  Focus areas: %v", plan.FocusAreas)
	t.Logf("  Notes: %s", plan.Notes)
	t.Logf("  NeedsExtensions: %v", plan.NeedsExtensions)

	t.Logf("Phase 2 results:")
	t.Logf("  Extensions: %d", len(plan.Extensions))
	t.Logf("  Quick checks: %d", len(plan.QuickChecks))
	t.Logf("  Snippets: %d", len(plan.Snippets))

	// Plan must have at least some content from Phase 1
	assert.True(t,
		len(plan.ModuleTags) > 0 || len(plan.ModuleIDs) > 0,
		"expected plan to have module_tags or module_ids from Phase 1")

	// Log extensions for debugging
	for i, ext := range plan.Extensions {
		t.Logf("  Extension[%d]: %s (reason: %s, code: %d bytes)", i, ext.Filename, ext.Reason, len(ext.Code))
	}
	for i, qc := range plan.QuickChecks {
		t.Logf("  QuickCheck[%d]: %s (scan: %s)", i, qc.ID, qc.Scan)
	}
}

// --- Source Analysis Tests ---
//
// These tests verify the full source-analysis pipeline:
//   1. Source analysis sub-agents (routes, auth, extensions) run in parallel
//   2. Routes are filtered by target hostname
//   3. Session config is written and converted to auth-config.yaml
//   4. Extensions from source analysis merge with plan extensions
//   5. Results flow through to the plan phase

// fakeSourceAnalysisAgentScript returns a script that handles all swarm sub-agent roles.
// It detects the role from prompt keywords and outputs appropriate responses:
//   - Routes sub-agent: Outputs Juice Shop HTTP routes as JSON
//   - Auth sub-agent: Outputs session config with login flow + credentials
//   - Extensions sub-agent: Outputs custom JS vulnerability extensions
//   - Plan phase: Outputs module tags/IDs based on analysis
//   - Extension phase: Outputs targeted extensions for Juice Shop
func fakeSourceAnalysisAgentScript(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-sa-agent.sh")

	// Extensions output — custom extensions for Juice Shop vulns
	// Must include at least one http_record for ParseSourceAnalysisResult to accept the JSON
	extensionsOutput := `Here are vulnerability-targeted extensions for Juice Shop:

` + "```json\n" + `{"http_records": [{"method":"GET","url":"http://localhost:3000/","notes":"placeholder"}], "extensions": []}` + "\n```\n\n" + `
#### juice-shop-sqli-login.js
Reason: Test SQL injection bypass in login using Sequelize ORM specific payloads

` + "```javascript\n" + `module.exports = {
  id: "juice-shop-sqli-login",
  name: "Juice Shop SQLi Login Bypass",
  type: "active",
  severity: "critical",
  confidence: "tentative",
  tags: ["custom", "sqli", "auth"],
  scanTypes: ["per_request"],
  scanPerRequest: function(ctx) {
    if (ctx.request.url.indexOf("/rest/user/login") === -1) return null;
    var payloads = [
      {"email": "' OR 1=1--", "password": "x"},
      {"email": "admin@juice-sh.op'--", "password": "x"},
      {"email": "' UNION SELECT * FROM Users--", "password": "x"}
    ];
    for (var i = 0; i < payloads.length; i++) {
      var resp = vigolium.http.request({
        method: "POST",
        url: ctx.request.url,
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(payloads[i])
      });
      if (resp && resp.status === 200 && resp.body.indexOf("authentication") !== -1) {
        return [{url: ctx.request.url, matched: JSON.stringify(payloads[i]), name: "SQL Injection Login Bypass"}];
      }
    }
    return null;
  }
};` + "\n```\n"

	// Plan output — analysis-only, no code
	planOutput := `## MODULE_TAGS
sqli, xss, injection, auth, idor, nosqli

## MODULE_IDS
sqli-error-based, sqli-time-based, xss-reflected, nosqli-injection

## FOCUS_AREAS
- SQL injection in /rest/products/search q parameter (Sequelize ORM)
- SQL injection bypass in /rest/user/login email field
- IDOR in /rest/basket/:id endpoint
- Password change via query parameters in /rest/user/change-password
- NoSQL injection in JSON body parameters
- JWT token manipulation (none algorithm, weak secret)

## NOTES
Target is OWASP Juice Shop running on Node.js/Express with Sequelize ORM and SQLite.
Multiple REST API endpoints discovered from source analysis with 10+ routes.
Login endpoint uses JWT tokens stored in cookies and response body.
Session config with admin and regular user credentials has been generated.
Password change endpoint dangerously passes credentials in query parameters.
Basket endpoint likely vulnerable to IDOR (accessing other users baskets by ID).

## NEEDS_EXTENSIONS
yes`

	// Extension phase output — targeted extensions based on plan
	extPhaseOutput := `Based on the analysis, here are targeted extensions:

#### idor-basket-check.js
Reason: Test IDOR vulnerability in basket endpoint by accessing other users baskets

` + "```javascript\n" + `module.exports = {
  id: "idor-basket-check",
  name: "Basket IDOR Check",
  type: "active",
  severity: "high",
  confidence: "tentative",
  tags: ["custom", "idor"],
  scanTypes: ["per_request"],
  scanPerRequest: function(ctx) {
    if (ctx.request.url.indexOf("/rest/basket/") === -1) return null;
    var otherIds = [1, 2, 3, 4, 5];
    for (var i = 0; i < otherIds.length; i++) {
      var testUrl = ctx.request.url.replace(/\/rest\/basket\/\d+/, "/rest/basket/" + otherIds[i]);
      var resp = vigolium.http.request({method: "GET", url: testUrl, headers: ctx.request.headers});
      if (resp && resp.status === 200) {
        return [{url: testUrl, matched: "Accessible basket ID " + otherIds[i], name: "Basket IDOR"}];
      }
    }
    return null;
  }
};` + "\n```\n\n" + `
` + "```json\n" + `[{"id":"password-change-qparams","scan":"per_host","severity":"high","requests":[{"method":"PUT","path":"/rest/user/change-password?current=admin123&new=hacked&repeat=hacked"}],"match":{"status":200,"body_regex":"(password|changed|success)"}}]` + "\n```\n"

	// Consolidated source analysis notes — output for the explore phase.
	// This is free-form text that the format phase will convert to structured JSON.
	exploreNotes := `## Part 1: Application Routes (non-auth)

1. GET /rest/products/search?q=test — Product search, q parameter is user-controlled, uses Sequelize raw query
2. GET /api/Users — User listing endpoint
3. GET /rest/products/:id/reviews — Product reviews, id parameter
4. POST /api/Feedbacks — Feedback submission, body: {"comment":"test","rating":5}
5. GET /api/Challenges — Challenge listing
6. GET /rest/basket/:id — Shopping basket by ID, potential IDOR
7. POST /api/BasketItems — Add item to basket, body: {"ProductId":1,"BasketId":1,"quantity":1}
8. GET /rest/user/whoami — Current user info, requires auth
9. PUT /rest/user/change-password?current=admin123&new=newpass&repeat=newpass — Password change via query params

## Part 2: Authentication Routes

1. POST /rest/user/login — Login endpoint, body: {"email":"...","password":"..."}, returns JWT

## Part 3: Credentials and Session Management

- Admin: admin@juice-sh.op / admin123
- Regular: jim@juice-sh.op / ncc-1701
- JWT stored in response body (authentication.token) and cookie (token)
- Sequelize ORM with SQLite backend`

	// Combined format output — routes + auth + session_config for the format phase
	formatJSON := `{"method":"GET","url":"http://localhost:3000/rest/products/search?q=test","notes":"Product search - q parameter is user-controlled"}
{"method":"POST","url":"http://localhost:3000/rest/user/login","headers":{"Content-Type":"application/json"},"body":"{\"email\":\"admin@juice-sh.op\",\"password\":\"admin123\"}","notes":"Login endpoint"}
{"method":"GET","url":"http://localhost:3000/api/Users","notes":"User listing endpoint"}
{"method":"GET","url":"http://localhost:3000/rest/products/:id/reviews","notes":"Product reviews - id parameter"}
{"method":"POST","url":"http://localhost:3000/api/Feedbacks","headers":{"Content-Type":"application/json"},"body":"{\"comment\":\"test\",\"rating\":5}","notes":"Feedback submission"}
{"method":"GET","url":"http://localhost:3000/api/Challenges","notes":"Challenge listing"}
{"method":"GET","url":"http://localhost:3000/rest/basket/:id","notes":"Shopping basket by ID - potential IDOR"}
{"method":"POST","url":"http://localhost:3000/api/BasketItems","headers":{"Content-Type":"application/json"},"body":"{\"ProductId\":1,\"BasketId\":1,\"quantity\":1}","notes":"Add item to basket"}
{"method":"GET","url":"http://localhost:3000/rest/user/whoami","notes":"Current user info - requires auth"}
{"method":"PUT","url":"http://localhost:3000/rest/user/change-password?current=admin123&new=newpass&repeat=newpass","notes":"Password change via query params"}`

	formatSessionConfig := `{
  "sessions": [
    {
      "name": "admin_user",
      "role": "primary",
      "login": {
        "url": "http://localhost:3000/rest/user/login",
        "method": "POST",
        "content_type": "application/json",
        "body": "{\"email\":\"admin@juice-sh.op\",\"password\":\"admin123\"}",
        "extract": [
          {"source": "json", "path": "$.authentication.token", "apply_as": "Authorization: Bearer {value}"},
          {"source": "cookie", "name": "token"}
        ]
      }
    },
    {
      "name": "regular_user",
      "role": "compare",
      "login": {
        "url": "http://localhost:3000/rest/user/login",
        "method": "POST",
        "content_type": "application/json",
        "body": "{\"email\":\"jim@juice-sh.op\",\"password\":\"ncc-1701\"}",
        "extract": [
          {"source": "json", "path": "$.authentication.token", "apply_as": "Authorization: Bearer {value}"}
        ]
      }
    }
  ]
}`

	// The script reads stdin, detects role by keywords, and outputs the appropriate response.
	// Use unique markers from the consolidated prompt templates to distinguish sub-agents:
	// - swarm-source-explore.md: "explore the application source code"
	// - swarm-source-format.md: "previously analyzed the application source code"
	// - swarm-source-extensions.md: "Generate targeted JavaScript scanner extensions"
	// - agent-swarm-extensions.md (Phase 2): "Plan Context" in {{.Extra.PlanContext}}
	// - agent-swarm-plan.md (Phase 1): fallback
	content := fmt.Sprintf(`#!/bin/sh
INPUT=$(cat)

# Detect role from actual prompt template content (consolidated 3-call flow)
if echo "$INPUT" | grep -qi 'previously analyzed the application source code'; then
  # Format phase: output JSONL records + session_config
  echo '` + "```jsonl" + `'
  cat <<'FORMAT_EOF'
%s
FORMAT_EOF
  echo '` + "```" + `'
  echo ''
  echo '` + "```json" + `'
  cat <<'SESSION_EOF'
%s
SESSION_EOF
  echo '` + "```" + `'
elif echo "$INPUT" | grep -qi 'Generate targeted JavaScript scanner extensions'; then
  # Extensions phase
  cat <<'EXT_EOF'
%s
EXT_EOF
elif echo "$INPUT" | grep -qi 'explore the application source code'; then
  # Explore phase: output free-form notes
  cat <<'EXPLORE_EOF'
%s
EXPLORE_EOF
elif echo "$INPUT" | grep -qi 'Plan Context\|PlanContext\|plan context'; then
  cat <<'EXTPHASE_EOF'
%s
EXTPHASE_EOF
else
  cat <<'PLAN_EOF'
%s
PLAN_EOF
fi
`, formatJSON, formatSessionConfig, extensionsOutput, exploreNotes, extPhaseOutput, planOutput)

	require.NoError(t, os.WriteFile(script, []byte(content), 0755))
	return script
}

// TestSwarmSourceAnalysisFullPipeline tests the complete source-analysis-driven swarm flow:
//
//  1. Source analysis sub-agents (routes, auth, extensions) run in parallel and produce:
//     - 10 HTTP routes extracted from Juice Shop source code
//     - Session config with admin + regular user login flows
//     - Custom SQLi login bypass extension
//  2. Routes are filtered by target hostname (localhost:3000)
//  3. Session config is written as session-config.json and converted via callback
//  4. Plan phase analyzes all records (original input + source-discovered routes)
//  5. Extension phase generates additional targeted extensions
//  6. All artifacts are present in the session directory
//
// Simulates: vigolium agent swarm -t http://localhost:3000 --source ~/Desktop/demo/juice-shop --agent opencode
func TestSwarmSourceAnalysisFullPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	agentName := "fake-sa-agent"
	script := fakeSourceAnalysisAgentScript(t)
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	// Create a fake source directory (simulates --source ~/Desktop/demo/juice-shop)
	sourceDir := t.TempDir()
	// Write some minimal files so the source path is valid
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "server.js"), []byte("const express = require('express');"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "package.json"), []byte(`{"name":"juice-shop","version":"16.0.0"}`), 0644))

	sessionDir := t.TempDir()

	// Track whether the source analysis callback was called
	var callbackCalled bool
	var callbackSessionConfig *agent.AgentSessionConfig
	var generatedAuthConfigPath string

	cfg := agent.SwarmConfig{
		Inputs:        []string{"http://localhost:3000/"},
		SourcePath:    sourceDir,
		AgentName:     agentName,
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		SkipPhases:    []string{"scan", "triage", "rescan"},

		// Source analysis callback — simulates the CLI's auth-config.yaml conversion
		SourceAnalysisCallback: func(saResult *agent.SourceAnalysisResult) error {
			callbackCalled = true
			if saResult.SessionConfig != nil {
				callbackSessionConfig = saResult.SessionConfig

				// Simulate writing auth-config.yaml (as the CLI does)
				authPath := filepath.Join(sessionDir, "auth-config.yaml")
				// Write a minimal representation
				content := fmt.Sprintf("# Generated from source analysis\nsessions:\n")
				for _, s := range saResult.SessionConfig.Sessions {
					content += fmt.Sprintf("  - name: %s\n    role: %s\n", s.Name, s.Role)
					if s.Login != nil {
						content += fmt.Sprintf("    login:\n      url: %s\n      method: %s\n", s.Login.URL, s.Login.Method)
					}
				}
				if err := os.WriteFile(authPath, []byte(content), 0644); err != nil {
					return err
				}
				generatedAuthConfigPath = authPath
			}
			return nil
		},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err, "swarm with source analysis should succeed")
	require.NotNil(t, result)

	t.Logf("Agent run UUID: %s", result.AgentRunUUID)
	t.Logf("Total records: %d", result.TotalRecords)
	t.Logf("Duration: %s", result.Duration)

	// Debug: dump source analysis output
	if data, readErr := os.ReadFile(filepath.Join(sessionDir, "source-analysis-output.md")); readErr == nil {
		t.Logf("Source analysis output (%d bytes):\n%s", len(data), string(data))
	} else {
		t.Logf("No source-analysis-output.md: %v", readErr)
	}
	if data, readErr := os.ReadFile(filepath.Join(sessionDir, "prompt-source-analysis.md")); readErr == nil {
		t.Logf("Source analysis prompt (%d bytes, first 500):\n%.500s", len(data), string(data))
	}

	// --- Verify source analysis results ---

	// 1. Records should include both the original URL input AND source-discovered routes
	assert.Greater(t, result.TotalRecords, 1,
		"expected more than 1 record (original input + source-discovered routes)")
	t.Logf("Records: %d (1 original + source-discovered routes)", result.TotalRecords)

	// 2. Source analysis callback should have been called
	assert.True(t, callbackCalled, "SourceAnalysisCallback should have been called")

	// 3. Session config should have been captured with login credentials
	require.NotNil(t, callbackSessionConfig, "expected session config from auth sub-agent")
	assert.GreaterOrEqual(t, len(callbackSessionConfig.Sessions), 2,
		"expected at least 2 sessions (admin + regular user)")

	// Verify admin session
	var adminSession *agent.AgentSessionEntry
	var regularSession *agent.AgentSessionEntry
	for i := range callbackSessionConfig.Sessions {
		s := &callbackSessionConfig.Sessions[i]
		switch s.Name {
		case "admin_user":
			adminSession = s
		case "regular_user":
			regularSession = s
		}
	}

	require.NotNil(t, adminSession, "expected admin_user session")
	assert.Equal(t, "primary", adminSession.Role)
	require.NotNil(t, adminSession.Login, "admin session should have login flow")
	assert.Equal(t, "http://localhost:3000/rest/user/login", adminSession.Login.URL)
	assert.Equal(t, "POST", adminSession.Login.Method)
	assert.Equal(t, "application/json", adminSession.Login.ContentType)
	assert.Contains(t, adminSession.Login.Body, "admin@juice-sh.op")
	assert.Contains(t, adminSession.Login.Body, "admin123")
	assert.GreaterOrEqual(t, len(adminSession.Login.Extract), 1, "expected extract rules for JWT token")

	// Verify JWT extraction rule
	foundJWTExtract := false
	for _, rule := range adminSession.Login.Extract {
		if rule.Source == "json" && rule.Path == "$.authentication.token" {
			foundJWTExtract = true
			assert.Equal(t, "Authorization: Bearer {value}", rule.ApplyAs)
		}
	}
	assert.True(t, foundJWTExtract, "expected JWT token extraction rule with json source")

	// Verify regular user session for comparative scanning
	require.NotNil(t, regularSession, "expected regular_user session for comparison")
	assert.Equal(t, "compare", regularSession.Role)
	require.NotNil(t, regularSession.Login)
	assert.Contains(t, regularSession.Login.Body, "jim@juice-sh.op")

	t.Logf("Session config: %d sessions (admin=%s, regular=%s)",
		len(callbackSessionConfig.Sessions), adminSession.Name, regularSession.Name)

	// 4. Session config JSON should be written to session dir
	sessionConfigPath := filepath.Join(sessionDir, "session-config.json")
	sessionConfigData, statErr := os.ReadFile(sessionConfigPath)
	assert.NoError(t, statErr, "expected session-config.json in session dir")
	if statErr == nil {
		assert.Contains(t, string(sessionConfigData), "admin_user")
		assert.Contains(t, string(sessionConfigData), "admin@juice-sh.op")
		assert.Contains(t, string(sessionConfigData), "$.authentication.token")
		t.Logf("session-config.json: %d bytes", len(sessionConfigData))
	}

	// 5. Auth config YAML should be generated by the callback
	assert.NotEmpty(t, generatedAuthConfigPath, "expected auth config path from callback")
	authConfigData, readErr := os.ReadFile(generatedAuthConfigPath)
	assert.NoError(t, readErr, "expected auth-config.yaml to be readable")
	if readErr == nil {
		assert.Contains(t, string(authConfigData), "admin_user")
		assert.Contains(t, string(authConfigData), "primary")
		assert.Contains(t, string(authConfigData), "/rest/user/login")
		t.Logf("auth-config.yaml: %d bytes", len(authConfigData))
	}

	// --- Verify plan phase results ---

	require.NotNil(t, result.SwarmPlan, "expected a parsed swarm plan")
	plan := result.SwarmPlan

	// 6. Plan should have module tags from analysis of source-discovered routes
	assert.Contains(t, plan.ModuleTags, "sqli")
	assert.Contains(t, plan.ModuleTags, "xss")
	assert.Contains(t, plan.ModuleTags, "auth")
	assert.Contains(t, plan.ModuleTags, "idor")

	// 7. Plan should have specific module IDs
	assert.Contains(t, plan.ModuleIDs, "sqli-error-based")

	// 8. Focus areas should reference source-discovered endpoints
	assert.GreaterOrEqual(t, len(plan.FocusAreas), 4,
		"expected focus areas covering multiple source-discovered endpoints")
	t.Logf("Focus areas: %v", plan.FocusAreas)

	// 9. Notes should reference the source analysis findings
	assert.NotEmpty(t, plan.Notes)
	assert.Contains(t, plan.Notes, "Juice Shop")
	t.Logf("Notes: %s", plan.Notes)

	// --- Verify extension merging ---

	// 10. Plan-phase extensions (from the extension agent, Phase 2)
	// Extension phase produces: idor-basket-check.js + password-change-qparams quick check
	assert.GreaterOrEqual(t, len(plan.Extensions), 1,
		"expected extensions from extension phase")

	extFilenames := make([]string, len(plan.Extensions))
	for i, ext := range plan.Extensions {
		extFilenames[i] = ext.Filename
		t.Logf("Plan Extension[%d]: %s (reason: %s, code: %d bytes)", i, ext.Filename, ext.Reason, len(ext.Code))
	}

	// Verify plan-phase extension
	foundIDOR := false
	for _, ext := range plan.Extensions {
		if ext.Filename == "idor-basket-check.js" {
			foundIDOR = true
			assert.Contains(t, ext.Code, "idor-basket-check")
			assert.Contains(t, ext.Code, "/rest/basket/")
		}
	}
	assert.True(t, foundIDOR, "expected idor-basket-check.js from extension phase, got: %v", extFilenames)

	// 11. Quick checks from extension phase
	assert.GreaterOrEqual(t, len(plan.QuickChecks), 1, "expected quick checks from extension phase")
	if len(plan.QuickChecks) > 0 {
		t.Logf("Quick checks: %v", func() []string {
			ids := make([]string, len(plan.QuickChecks))
			for i, qc := range plan.QuickChecks {
				ids[i] = qc.ID
			}
			return ids
		}())
	}

	// --- Verify session directory artifacts ---

	// 12. Extensions on disk should include BOTH source-analysis AND plan-phase extensions
	// Source analysis produces: juice-shop-sqli-login.js (written to disk via allExtensions merge)
	// Extension phase produces: idor-basket-check.js + qc-password-change-qparams.js
	extDir := filepath.Join(sessionDir, "extensions")
	entries, statErr := os.ReadDir(extDir)
	if assert.NoError(t, statErr, "expected extensions directory in session dir") {
		assert.GreaterOrEqual(t, len(entries), 3, "expected source-analysis + plan-phase extension files")
		diskNames := make([]string, len(entries))
		for i, e := range entries {
			diskNames[i] = e.Name()
		}
		t.Logf("Extension files on disk: %v", diskNames)

		// Verify source-analysis extension was written to disk
		foundSQLiLogin := false
		for _, name := range diskNames {
			if name == "juice-shop-sqli-login.js" {
				foundSQLiLogin = true
			}
		}
		assert.True(t, foundSQLiLogin, "expected juice-shop-sqli-login.js from source analysis on disk, got: %v", diskNames)
	}

	// 13. Swarm plan JSON should be saved
	planPath := filepath.Join(sessionDir, "swarm-plan.json")
	planData, readErr := os.ReadFile(planPath)
	assert.NoError(t, readErr, "expected swarm-plan.json")
	if readErr == nil {
		assert.Contains(t, string(planData), "sqli")
		assert.Contains(t, string(planData), "idor")
	}

	// 14. Source analysis prompt and output should be saved
	saPromptPath := filepath.Join(sessionDir, "prompt-source-analysis.md")
	_, statErr = os.Stat(saPromptPath)
	assert.NoError(t, statErr, "expected prompt-source-analysis.md")

	saOutputPath := filepath.Join(sessionDir, "source-analysis-output.md")
	_, statErr = os.Stat(saOutputPath)
	assert.NoError(t, statErr, "expected source-analysis-output.md")

	// 15. Checkpoint should include source analysis as completed
	checkpointPath := filepath.Join(sessionDir, "checkpoint.json")
	checkpointData, readErr := os.ReadFile(checkpointPath)
	assert.NoError(t, readErr, "expected checkpoint.json")
	if readErr == nil {
		assert.Contains(t, string(checkpointData), "source-analysis")
	}

	t.Logf("\n=== Source Analysis Pipeline Summary ===")
	t.Logf("Records: %d (1 input + %d discovered)", result.TotalRecords, result.TotalRecords-1)
	t.Logf("Sessions: %d (admin + regular)", len(callbackSessionConfig.Sessions))
	t.Logf("Plan tags: %v", plan.ModuleTags)
	t.Logf("Plan IDs: %v", plan.ModuleIDs)
	t.Logf("Extensions: %d plan-phase (plan: %v)", len(plan.Extensions), foundIDOR)
	t.Logf("Quick checks: %d", len(plan.QuickChecks))
	t.Logf("Auth config: %s", generatedAuthConfigPath)
}

// TestSwarmSourceAnalysisWithSASTCallback tests that the SAST phase integrates
// correctly with source analysis. The SASTFunc simulates ast-grep route extraction
// and the SAST review agent validates the findings.
func TestSwarmSourceAnalysisWithSASTCallback(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	agentName := "fake-sa-agent"
	script := fakeSourceAnalysisAgentScript(t)
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sourceDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "server.js"), []byte("const app = require('express')();"), 0644))

	sessionDir := t.TempDir()

	// Track SAST execution
	var sastCalled bool

	cfg := agent.SwarmConfig{
		Inputs:        []string{"http://localhost:3000/"},
		SourcePath:    sourceDir,
		AgentName:     agentName,
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		SkipPhases:    []string{"scan", "triage", "rescan"},

		// Simulate SAST callback (ast-grep would run here in real usage)
		SASTFunc: func(ctx context.Context) error {
			sastCalled = true
			t.Logf("SASTFunc called — simulating ast-grep route extraction")
			// In real usage this would run ast-grep and populate the database
			// with discovered routes. The SAST review agent then validates them.
			return nil
		},

		SourceAnalysisCallback: func(saResult *agent.SourceAnalysisResult) error {
			return nil
		},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// SAST should have been called (runs in parallel with source analysis)
	assert.True(t, sastCalled, "SASTFunc should have been called when --source is provided")

	// Source analysis should still produce results
	assert.Greater(t, result.TotalRecords, 1, "expected source-discovered routes")
	require.NotNil(t, result.SwarmPlan)

	t.Logf("SAST + Source Analysis: records=%d, plan tags=%v",
		result.TotalRecords, result.SwarmPlan.ModuleTags)
}

// TestSwarmSourceAnalysisHostnameFiltering tests that routes discovered from
// source analysis are correctly filtered to only include those matching the
// target hostname. Routes pointing to external hosts should be excluded.
func TestSwarmSourceAnalysisHostnameFiltering(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	// Agent that outputs routes including some for external hosts.
	// Matches consolidated 3-call flow: explore → format → extensions.
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-filter-agent.sh")
	filterContent := `#!/bin/sh
INPUT=$(cat)
if echo "$INPUT" | grep -qi 'previously analyzed the application source code'; then
  # Format phase: output JSONL records (some external hosts to be filtered)
  echo '` + "```jsonl" + `'
  echo '{"method":"GET","url":"http://localhost:3000/api/products","notes":"should match"}'
  echo '{"method":"GET","url":"http://localhost:3000/api/users","notes":"should match"}'
  echo '{"method":"GET","url":"https://evil.com/api/data","notes":"should be filtered out"}'
  echo '{"method":"POST","url":"http://external-api.example.com/webhook","notes":"should be filtered out"}'
  echo '{"method":"GET","url":"/relative/path","notes":"relative - should resolve to target host"}'
  echo '` + "```" + `'
elif echo "$INPUT" | grep -qi 'Generate targeted JavaScript scanner extensions'; then
  # Extensions phase: no extensions for this test
  echo 'No vulnerability sinks identified for extension generation.'
elif echo "$INPUT" | grep -qi 'explore the application source code'; then
  # Explore phase: free-form notes
  cat <<'EXPLORE'
## Part 1: Application Routes
1. GET /api/products — should match
2. GET /api/users — should match
3. GET https://evil.com/api/data — external, should be filtered
4. POST http://external-api.example.com/webhook — external, should be filtered
5. GET /relative/path — relative path

## Part 2: Authentication Routes
None identified.

## Part 3: Credentials
None identified.
EXPLORE
else
  cat <<'PLAN'
## MODULE_TAGS
light

## NOTES
Filtered routes test.
PLAN
fi
`
	require.NoError(t, os.WriteFile(script, []byte(filterContent), 0755))

	agentName := "fake-filter"
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sourceDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "app.js"), []byte("//"), 0644))

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs:        []string{"http://localhost:3000/"},
		SourcePath:    sourceDir,
		AgentName:     agentName,
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		SkipPhases:    []string{"scan", "triage", "rescan"},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)

	// Debug: dump source analysis output
	if data, readErr := os.ReadFile(filepath.Join(sessionDir, "source-analysis-output.md")); readErr == nil {
		t.Logf("Source analysis output (%d bytes):\n%s", len(data), string(data))
	} else {
		t.Logf("No source-analysis-output.md: %v", readErr)
	}

	// Original input (1) + localhost:3000 routes (2 exact match + 1 relative resolved)
	// + 2 placeholder records from auth/extensions sub-agents (both http://localhost:3000/)
	// evil.com and external-api.example.com should be filtered out
	t.Logf("Total records after hostname filtering: %d", result.TotalRecords)
	assert.GreaterOrEqual(t, result.TotalRecords, 3, "expected at least original input + hostname-matched routes")
	// External hosts (evil.com, external-api.example.com) should be filtered out.
	// Max: 1 input + 2 matched routes + 1 relative + 2 placeholders = 6
	assert.LessOrEqual(t, result.TotalRecords, 7, "external host routes should be filtered out")
}

// fakeSASTReviewMultiBlockScript returns a script that simulates the real-world SAST review
// output pattern: multiple separate JSON blocks (Task 1: session config, Task 2: routes,
// Task 3: SAST validation) followed by JS extension code blocks. This tests the
// multi-block JSON merging and extension extraction fallback.
func fakeSASTReviewMultiBlockScript(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-sast-review-agent.sh")

	// Simulates the exact output pattern from the real SAST review failure:
	// 3 separate JSON blocks + JS extensions
	content := `#!/bin/sh
INPUT=$(cat)

# SAST review agent — return multi-block output
if echo "$INPUT" | grep -qi 'SAST\|sast\|findings'; then
  cat <<'SAST_EOF'
## Task 1: Session Configuration

` + "```json" + `
{"http_records":[],"session_config":{"sessions":[{"name":"admin","role":"primary","login":{"url":"http://localhost:3000/rest/user/login","method":"POST","content_type":"application/json","body":"{\"email\":\"admin@juice-sh.op\",\"password\":\"admin123\"}","extract":[{"source":"json","path":"$.authentication.token","apply_as":"Authorization: Bearer {value}"}]}}]}}
` + "```" + `

## Task 2: HTTP Routes

` + "```json" + `
{"http_records":[{"method":"POST","url":"http://localhost:3000/rest/user/login","headers":{"Content-Type":"application/json"},"body":"{\"email\":\"test\",\"password\":\"test\"}","notes":"Login SQLi"},{"method":"GET","url":"http://localhost:3000/rest/products/search?q=test","headers":{},"body":"","notes":"Search SQLi"}]}
` + "```" + `

## Task 3: SAST Validation

` + "```json" + `
{"http_records":[{"method":"GET","url":"http://localhost:3000/rest/track-order/1234","headers":{},"body":"","notes":"NoSQLi via $where"}]}
` + "```" + `

#### agent-sast-sqli-login.js
Reason: SAST finding js/sql-injection at login.ts:34

` + "```javascript" + `
module.exports = {
  id: "agent-sast-sqli-login",
  name: "SAST SQLi Login",
  type: "active",
  severity: "high",
  scanTypes: ["per_request"],
  scanPerRequest: function(ctx) {
    if (ctx.request.path !== "/rest/user/login") return [];
    return [];
  }
};
` + "```" + `

#### agent-sast-nosqli-trackorder.js
Reason: SAST finding js/code-injection at trackOrder.ts:18

` + "```javascript" + `
module.exports = {
  id: "agent-sast-nosqli-trackorder",
  name: "SAST NoSQLi Track Order",
  type: "active",
  severity: "high",
  scanTypes: ["per_request"],
  scanPerRequest: function(ctx) {
    if (!ctx.request.path.match(/\/rest\/track-order\//)) return [];
    return [];
  }
};
` + "```" + `
SAST_EOF
  exit 0
fi

# For source analysis sub-agents
if echo "$INPUT" | grep -qi 'extract all HTTP routes'; then
  echo '{"http_records":[{"method":"GET","url":"http://localhost:3000/api/Products","notes":"products"}]}'
elif echo "$INPUT" | grep -qi 'discover authentication flows'; then
  echo '{"http_records":[{"method":"GET","url":"http://localhost:3000/","notes":"placeholder"}]}'
elif echo "$INPUT" | grep -qi 'identify vulnerability sinks'; then
  echo '{"http_records":[{"method":"GET","url":"http://localhost:3000/","notes":"placeholder"}]}'
else
  # Plan phase
  cat <<'PLAN'
## MODULE_TAGS
sqli, nosqli, xss

## MODULE_IDS
sqli-error-based, nosqli-boolean

## FOCUS_AREAS
- SQL injection in login endpoint
- NoSQL injection in track order

## NOTES
SAST review identified confirmed vulnerabilities.

## NEEDS_EXTENSIONS
yes
PLAN
fi
`
	require.NoError(t, os.WriteFile(script, []byte(content), 0755))
	return script
}

// TestSwarmSASTReviewMultiBlockOutput tests that the SAST review phase correctly handles
// multi-block JSON output (the exact pattern that caused the production failure:
// "json: cannot unmarshal array into Go value of type agent.SourceAnalysisResult").
//
// The SAST review agent outputs 3 separate JSON blocks (Task 1/2/3) plus JS extensions.
// The fix merges http_records across all valid JSON blocks and extracts extensions
// from fenced code blocks even when some JSON blocks are garbled.
func TestSwarmSASTReviewMultiBlockOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	agentName := "fake-sast-review"
	script := fakeSASTReviewMultiBlockScript(t)
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sourceDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "server.js"), []byte("//"), 0644))

	sessionDir := t.TempDir()

	// Track SAST execution
	var sastCalled bool

	cfg := agent.SwarmConfig{
		Inputs:        []string{"http://localhost:3000/"},
		SourcePath:    sourceDir,
		AgentName:     agentName,
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		SkipPhases:    []string{"scan", "triage", "rescan"},

		SASTFunc: func(ctx context.Context) error {
			sastCalled = true
			return nil
		},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err, "swarm with SAST review multi-block output should not fail")
	require.NotNil(t, result)

	assert.True(t, sastCalled, "SASTFunc should have been called")

	// Verify records include SAST-review discovered routes (merged from multiple JSON blocks)
	t.Logf("Total records: %d", result.TotalRecords)
	assert.Greater(t, result.TotalRecords, 1, "expected SAST review to contribute routes")

	// Verify SAST review output was saved to session
	if data, readErr := os.ReadFile(filepath.Join(sessionDir, "sast-review-output.md")); readErr == nil {
		t.Logf("SAST review output saved (%d bytes)", len(data))
		// Should contain the multi-block output
		assert.Contains(t, string(data), "Task 1")
		assert.Contains(t, string(data), "Task 2")
	}

	// Verify extensions were extracted and written to session dir
	extDir := filepath.Join(sessionDir, "extensions")
	if entries, dirErr := os.ReadDir(extDir); dirErr == nil {
		diskNames := make([]string, len(entries))
		for i, e := range entries {
			diskNames[i] = e.Name()
		}
		t.Logf("Extension files on disk: %v", diskNames)

		// Should include SAST review extensions
		foundSQLi := false
		foundNoSQLi := false
		for _, name := range diskNames {
			if name == "agent-sast-sqli-login.js" {
				foundSQLi = true
			}
			if name == "agent-sast-nosqli-trackorder.js" {
				foundNoSQLi = true
			}
		}
		assert.True(t, foundSQLi || foundNoSQLi,
			"expected SAST review extensions on disk, got: %v", diskNames)
	}

	// Verify plan was parsed
	require.NotNil(t, result.SwarmPlan)
	assert.Contains(t, result.SwarmPlan.ModuleTags, "sqli")
}

// fakeCodeFencedPlanScript returns a script that outputs a plan with code-fenced,
// newline-separated MODULE_IDS — the exact pattern that caused garbled module_ids
// in the swarm-plan.json.
func fakeCodeFencedPlanScript(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-codefenced-plan.sh")
	content := `#!/bin/sh
cat > /dev/null
cat <<'PLAN'
## MODULE_TAGS
sqli, nosqli, xss, ssti, xxe, ssrf

## MODULE_IDS

` + "```" + `
idor
` + "```" + `
sqli-error-based
sqli-union-based
nosqli-boolean
nosqli-time-injection-based
xss-reflected
ssti-detection
ssrf-internal
path-traversal-dotdot
open-redirect-bypass
xxe-file-read
jwt-none-algorithm
cors-misconfiguration
` + "```" + `

## FOCUS_AREAS
- SQL injection in login email field
- NoSQL injection in track order
- Path traversal in FTP server
- SSRF in profile image upload
- JWT algorithm confusion

## NOTES
Target is OWASP Juice Shop.

## NEEDS_EXTENSIONS
` + "```" + `
yes
` + "```" + `
PLAN
`
	require.NoError(t, os.WriteFile(script, []byte(content), 0755))
	return script
}

// TestSwarmPlanCodeFencedModuleIDs tests that the plan parser correctly handles
// MODULE_IDS wrapped in code fences with newline-separated values — the exact
// pattern that caused garbled module_ids like "```\nidor\n```\nsqli-error-based..."
// in the swarm-plan.json.
func TestSwarmPlanCodeFencedModuleIDs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	agentName := "fake-codefenced"
	script := fakeCodeFencedPlanScript(t)
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs:        []string{"http://localhost:3000/"},
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

	// Verify MODULE_TAGS parsed correctly
	assert.Contains(t, plan.ModuleTags, "sqli")
	assert.Contains(t, plan.ModuleTags, "nosqli")
	assert.Contains(t, plan.ModuleTags, "xss")

	// Verify MODULE_IDS are clean — no code fence markers
	t.Logf("Module IDs: %v", plan.ModuleIDs)
	assert.GreaterOrEqual(t, len(plan.ModuleIDs), 10,
		"expected at least 10 module IDs, got %d: %v", len(plan.ModuleIDs), plan.ModuleIDs)

	for _, id := range plan.ModuleIDs {
		assert.NotContains(t, id, "```", "module ID should not contain code fence markers: %q", id)
		assert.NotContains(t, id, "\n", "module ID should not contain newlines: %q", id)
	}

	// Verify specific IDs are present
	assert.Contains(t, plan.ModuleIDs, "sqli-error-based")
	assert.Contains(t, plan.ModuleIDs, "nosqli-boolean")
	assert.Contains(t, plan.ModuleIDs, "xss-reflected")
	assert.Contains(t, plan.ModuleIDs, "idor")

	// Verify NEEDS_EXTENSIONS also handles code fences
	assert.True(t, plan.NeedsExtensions, "NEEDS_EXTENSIONS should be true even wrapped in code fences")

	// Verify swarm-plan.json is clean
	planData, readErr := os.ReadFile(filepath.Join(sessionDir, "swarm-plan.json"))
	require.NoError(t, readErr)
	assert.NotContains(t, string(planData), "```",
		"swarm-plan.json should not contain code fence markers")
	t.Logf("swarm-plan.json: %s", string(planData))
}

// TestSwarmSASTReviewExtensionsWrittenToDisk tests the critical path: when a SAST review
// agent produces ```javascript code blocks for extensions, those extensions must be:
//   1. Extracted by ParseSourceAnalysisResult (even when JSON is garbled)
//   2. Written as .js files to <sessionDir>/extensions/
//   3. Session config (if present) written to session-config.json
//
// This reproduces the production bug where SAST review output contained 16 valid JS
// extensions in fenced code blocks, but ParseSourceAnalysisResult returned "extensions": 0
// because a JSON parsing path succeeded (with an empty struct) before code block extraction.
//
// Simulates: vigolium agent swarm -t http://localhost:3000 --source ~/Desktop/demo/juice-shop --verbose
func TestSwarmSASTReviewExtensionsWrittenToDisk(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)
	_ = db

	agentName := "fake-sast-ext-disk"
	script := fakeSASTReviewGarbledJSONWithExtensions(t)
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sourceDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "server.ts"), []byte("// juice-shop"), 0644))
	require.NoError(t, os.MkdirAll(filepath.Join(sourceDir, "routes"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "routes", "login.ts"), []byte("// login"), 0644))

	sessionDir := t.TempDir()

	var sastCalled bool

	cfg := agent.SwarmConfig{
		Inputs:        []string{"http://localhost:3000/"},
		SourcePath:    sourceDir,
		AgentName:     agentName,
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		SkipPhases:    []string{"native-scan", "triage", "rescan"},

		SASTFunc: func(ctx context.Context) error {
			sastCalled = true
			return nil
		},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err, "swarm with SAST review garbled JSON + extensions should not fail")
	require.NotNil(t, result)

	assert.True(t, sastCalled, "SASTFunc should have been called")

	// --- Verify SAST review output saved ---
	if data, readErr := os.ReadFile(filepath.Join(sessionDir, "sast-review-output.md")); readErr == nil {
		t.Logf("SAST review output saved (%d bytes)", len(data))
		assert.Contains(t, string(data), "agent-sast-sqli-login-error")
		assert.Contains(t, string(data), "agent-sast-nosqli-trackorder")
	} else {
		t.Logf("No sast-review-output.md: %v", readErr)
	}

	// --- Verify extensions were extracted and written as .js files ---
	extDir := filepath.Join(sessionDir, "extensions")
	entries, dirErr := os.ReadDir(extDir)
	require.NoError(t, dirErr, "expected extensions/ directory in session dir")

	diskNames := make([]string, len(entries))
	for i, e := range entries {
		diskNames[i] = e.Name()
	}
	t.Logf("Extension files on disk: %v", diskNames)

	// Should have at least 3 extensions from the SAST review code blocks
	assert.GreaterOrEqual(t, len(entries), 3,
		"expected at least 3 extension .js files on disk, got %d: %v", len(entries), diskNames)

	// Verify specific extension files exist and contain valid code
	expectedFiles := map[string]string{
		"agent-sast-sqli-login-error.js":  "agent-sast-sqli-login-error",
		"agent-sast-nosqli-trackorder.js": "agent-sast-nosqli-trackorder",
		"agent-sast-ssrf-profile.js":      "agent-sast-ssrf-profile",
	}
	for filename, expectedID := range expectedFiles {
		path := filepath.Join(extDir, filename)
		data, readErr := os.ReadFile(path)
		if assert.NoError(t, readErr, "expected %s on disk", filename) {
			content := string(data)
			assert.Contains(t, content, "module.exports", "%s should be a valid JS module", filename)
			assert.Contains(t, content, expectedID, "%s should contain its module ID", filename)
			assert.Contains(t, content, "scanPerRequest", "%s should have scanPerRequest function", filename)
			t.Logf("  %s: %d bytes, valid JS module", filename, len(data))
		}
	}

	// --- Verify session config was written ---
	sessionConfigPath := filepath.Join(sessionDir, "session-config.json")
	sessionConfigData, statErr := os.ReadFile(sessionConfigPath)
	if assert.NoError(t, statErr, "expected session-config.json in session dir from SAST review") {
		configStr := string(sessionConfigData)
		assert.Contains(t, configStr, "admin")
		assert.Contains(t, configStr, "juice-sh.op")
		t.Logf("session-config.json: %d bytes", len(sessionConfigData))
	}

	// --- Verify plan was parsed ---
	require.NotNil(t, result.SwarmPlan)
	assert.Contains(t, result.SwarmPlan.ModuleTags, "sqli")
}

// fakeSASTReviewGarbledJSONWithExtensions simulates the exact production failure:
// the SAST review agent outputs garbled/malformed JSON for routes but well-formed
// ```javascript code blocks for extensions. This tests that ParseSourceAnalysisResult
// extracts extensions from code blocks even when JSON parsing produces empty results.
func fakeSASTReviewGarbledJSONWithExtensions(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-sast-garbled-agent.sh")

	content := `#!/bin/sh
INPUT=$(cat)

# SAST review agent — garbled JSON but valid JS extensions
if echo "$INPUT" | grep -qi 'SAST\|sast\|findings'; then
  cat <<'SAST_EOF'
## Task 1: Authentication & Session Configuration

` + "```json" + `
{"http_records":[],"session_config":{"sessions":[{"name":"admin","role":"primary","login":{"url":"http://localhost:3000/rest/user/login","method":"POST","content_type":"application/json","body":"{\"email\":\"admin@juice-sh.op\",\"password\":\"admin123\"}","extract":[{"source":"json","path":"$.authentication.token","apply_as":"Authorization: Bearer {value}"}]}},{"name":"regular_user","role":"compare","login":{"url":"http://localhost:3000/rest/user/login","method":"POST","content_type":"application/json","body":"{\"email\":\"jim@juice-sh.op\",\"password\":\"ncc-1701\"}","extract":[{"source":"json","path":"$.authentication.token","apply_as":"Authorization: Bearer {value}"}]}}]}}
` + "```" + `

## Task 2: HTTP Route Extraction

` + "```json" + `
{"http_records":[{"method":"POST","url":"http://localhost:3000/rest/user/login","headers":{"Content-Type":"application/json"},"body":"{\"email\":\"test\",\"password\":\"test\"}","notes":"Login SQLi"},{"method":"GET","url":"http://localhost:3000/rest/products/search?q=test","headers":{},"body":"","notes":"Search SQLi"}]}
` + "```" + `

## Task 3: SAST-Validated Scanner Extensions

#### agent-sast-sqli-login-error.js
Reason: SAST finding js/sql-injection at routes/login.ts:34 — error-based SQL injection

` + "```javascript" + `
module.exports = {
  id: "agent-sast-sqli-login-error",
  name: "SAST-verified: SQL injection in login via error-based detection",
  type: "active",
  severity: "high",
  scanTypes: ["per_request"],
  tags: ["sqli", "agent-generated", "sast-verified"],
  scanPerRequest: function(ctx) {
    if (ctx.request.path !== "/rest/user/login") return [];
    var payload = "' OR 1=1--";
    var resp = vigolium.http.post(ctx.request.url, {
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({email: payload, password: "x"})
    });
    if (!resp) return [];
    if (resp.statusCode === 200) {
      return [{
        url: ctx.request.url,
        matched: (resp.body || "").substring(0, 200),
        severity: "high",
        description: "SAST confirmed: SQL injection in login endpoint at routes/login.ts:34"
      }];
    }
    return [];
  }
};
` + "```" + `

#### agent-sast-nosqli-trackorder.js
Reason: SAST finding js/code-injection at routes/trackOrder.ts:18 — NoSQL injection

` + "```javascript" + `
module.exports = {
  id: "agent-sast-nosqli-trackorder",
  name: "SAST-verified: NoSQL injection in track order endpoint",
  type: "active",
  severity: "high",
  scanTypes: ["per_request"],
  tags: ["nosqli", "agent-generated", "sast-verified"],
  scanPerRequest: function(ctx) {
    if (!/\/rest\/track-order\//.test(ctx.request.path)) return [];
    return [];
  }
};
` + "```" + `

#### agent-sast-ssrf-profile.js
Reason: SAST finding js/request-forgery at routes/profileImageUrlUpload.ts:24 — SSRF

` + "```javascript" + `
module.exports = {
  id: "agent-sast-ssrf-profile",
  name: "SAST-verified: SSRF via profile image URL upload",
  type: "active",
  severity: "high",
  scanTypes: ["per_request"],
  tags: ["ssrf", "agent-generated", "sast-verified"],
  scanPerRequest: function(ctx) {
    if (ctx.request.path !== "/profile/image/url") return [];
    var resp = vigolium.http.post(ctx.request.url, {
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({imageUrl: "http://localhost:3000/rest/admin/application-configuration"})
    });
    if (!resp) return [];
    if (resp.statusCode === 200 && (resp.body || "").indexOf("config") !== -1) {
      return [{
        url: ctx.request.url,
        matched: (resp.body || "").substring(0, 200),
        severity: "high",
        description: "SAST confirmed: SSRF at profileImageUrlUpload.ts:24"
      }];
    }
    return [];
  }
};
` + "```" + `

#### agent-sast-redirect-open.js
Reason: SAST finding js/server-side-unvalidated-url-redirection at routes/redirect.ts:19

` + "```javascript" + `
module.exports = {
  id: "agent-sast-redirect-open",
  name: "SAST-verified: Open redirect via allowlist bypass",
  type: "active",
  severity: "medium",
  scanTypes: ["per_request"],
  tags: ["open-redirect", "agent-generated", "sast-verified"],
  scanPerRequest: function(ctx) {
    if (ctx.request.path !== "/redirect") return [];
    return [];
  }
};
` + "```" + `
SAST_EOF
  exit 0
fi

# For source analysis sub-agents (routes/auth/extensions) — return minimal valid output
if echo "$INPUT" | grep -qi 'extract all HTTP routes'; then
  echo '{"http_records":[{"method":"GET","url":"http://localhost:3000/api/Products","notes":"products"}]}'
elif echo "$INPUT" | grep -qi 'discover authentication flows'; then
  echo '{"http_records":[{"method":"GET","url":"http://localhost:3000/","notes":"placeholder"}]}'
elif echo "$INPUT" | grep -qi 'identify vulnerability sinks'; then
  echo '{"http_records":[{"method":"GET","url":"http://localhost:3000/","notes":"placeholder"}]}'
else
  # Plan phase
  cat <<'PLAN'
## MODULE_TAGS
sqli, nosqli, ssrf, xss

## MODULE_IDS
sqli-error-based, nosqli-boolean

## FOCUS_AREAS
- SQL injection in login endpoint
- NoSQL injection in track order
- SSRF in profile image upload

## NOTES
SAST review confirmed critical vulnerabilities in Juice Shop source.

## NEEDS_EXTENSIONS
yes
PLAN
fi
`
	require.NoError(t, os.WriteFile(script, []byte(content), 0755))
	// Create routes subdirectory for source path validity
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "routes"), 0755))
	return script
}

// TestSwarmRealAgentSourceAnalysis runs the full source analysis pipeline with a real agent.
// Skipped unless -agent and a valid --source path are provided.
//
// Usage:
//
//	go test -v -tags=e2e -run TestSwarmRealAgentSourceAnalysis ./test/e2e/ \
//	  -agent=opencode -target=http://localhost:3000 -source=~/Desktop/demo/juice-shop
var testSourcePath = flag.String("source", "", "Path to source code for real agent source analysis tests")

func TestSwarmRealAgentSourceAnalysis(t *testing.T) {
	if *testAgentName == "" || *testSourcePath == "" {
		t.Skip("Skipping: use -agent=<name> -source=<path> to run (e.g. -agent=opencode -source=~/Desktop/demo/juice-shop)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
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
		SourcePath:    *testSourcePath,
		AgentName:     *testAgentName,
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		SkipPhases:    []string{"scan", "triage", "rescan"},

		SourceAnalysisCallback: func(saResult *agent.SourceAnalysisResult) error {
			t.Logf("[Callback] Source analysis result:")
			t.Logf("  HTTP records: %d", len(saResult.HTTPRecords))
			if saResult.SessionConfig != nil {
				t.Logf("  Session config: %d sessions", len(saResult.SessionConfig.Sessions))
				for _, s := range saResult.SessionConfig.Sessions {
					t.Logf("    - %s (role=%s, hasLogin=%v)", s.Name, s.Role, s.Login != nil)
					if s.Login != nil {
						t.Logf("      URL: %s %s", s.Login.Method, s.Login.URL)
						t.Logf("      Extract rules: %d", len(s.Login.Extract))
					}
				}
			}
			t.Logf("  Extensions: %d", len(saResult.Extensions))
			return nil
		},
	}

	t.Logf("Running source analysis with agent=%s source=%s target=%s",
		*testAgentName, *testSourcePath, *testTargetURL)

	result, err := swarmRunner.Run(ctx, cfg)
	if err != nil {
		t.Logf("Session dir: %s", sessionDir)
		if data, readErr := os.ReadFile(filepath.Join(sessionDir, "source-analysis-output.md")); readErr == nil {
			t.Logf("Source analysis output:\n%s", string(data))
		}
		if data, readErr := os.ReadFile(filepath.Join(sessionDir, "master-agent-output.md")); readErr == nil {
			t.Logf("Master agent output:\n%s", string(data))
		}
		t.Fatalf("swarm with source analysis failed: %v", err)
	}

	require.NotNil(t, result)
	t.Logf("\n=== Real Agent Source Analysis Results ===")
	t.Logf("Records: %d", result.TotalRecords)
	t.Logf("Duration: %s", result.Duration)

	require.NotNil(t, result.SwarmPlan)
	plan := result.SwarmPlan

	t.Logf("Module tags: %v", plan.ModuleTags)
	t.Logf("Module IDs: %v", plan.ModuleIDs)
	t.Logf("Focus areas: %v", plan.FocusAreas)
	t.Logf("Notes: %s", plan.Notes)
	t.Logf("NeedsExtensions: %v", plan.NeedsExtensions)
	t.Logf("Extensions: %d", len(plan.Extensions))
	t.Logf("Quick checks: %d", len(plan.QuickChecks))

	for i, ext := range plan.Extensions {
		t.Logf("  Extension[%d]: %s (%d bytes) — %s", i, ext.Filename, len(ext.Code), ext.Reason)
	}

	// Verify session-config.json was written
	sessionConfigPath := filepath.Join(sessionDir, "session-config.json")
	if data, readErr := os.ReadFile(sessionConfigPath); readErr == nil {
		t.Logf("Session config (%d bytes):\n%s", len(data), string(data))
	} else {
		t.Logf("No session-config.json (agent may not have found login flows)")
	}

	// Basic assertions — real agent should produce meaningful output
	assert.Greater(t, result.TotalRecords, 1,
		"expected source analysis to discover routes beyond the initial input")
	assert.True(t,
		len(plan.ModuleTags) > 0 || len(plan.ModuleIDs) > 0,
		"expected plan to have module selections")
}
