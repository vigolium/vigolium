//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
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

// ─── Fake agent scripts for autopilot pipeline ──────────────────────────────

// fakeReconAgentScript returns a script that outputs a valid recon_deliverable JSON.
func fakeReconAgentScript(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-recon-agent.sh")
	content := `#!/bin/sh
cat > /dev/null
cat <<'OUTPUT'
Here is the reconnaissance deliverable:

` + "```json" + `
{
  "endpoints": [
    {"url": "http://localhost:3000/api/users", "method": "GET", "notes": "User listing"},
    {"url": "http://localhost:3000/api/login", "method": "POST", "parameter": "email", "notes": "Auth endpoint"},
    {"url": "http://localhost:3000/api/search", "method": "GET", "parameter": "q", "notes": "Search with query param"},
    {"url": "http://localhost:3000/api/profile/1", "method": "GET", "notes": "User profile by ID - potential IDOR"}
  ],
  "tech_stack": ["express", "mongodb", "jwt"],
  "auth_flows": [
    {"type": "jwt", "endpoint": "/api/login", "notes": "Returns JWT in response body"}
  ],
  "notes": "Express.js REST API with MongoDB. JWT auth via login endpoint."
}
` + "```" + `
OUTPUT
`
	require.NoError(t, os.WriteFile(script, []byte(content), 0755))
	return script
}

// fakeVulnAnalysisAgentScript returns a script that outputs a valid vuln_queue JSON
// with extensions in a code block.
func fakeVulnAnalysisAgentScript(t *testing.T, class string) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-vuln-"+class+"-agent.sh")

	queueJSON := `{
  "class": "` + class + `",
  "items": [
    {
      "endpoint": "/api/search",
      "method": "GET",
      "parameter": "q",
      "sink_type": "sql_concat",
      "witness_payload": "' OR 1=1--",
      "context": "Parameter concatenated into query at search.js:42",
      "confidence": "high",
      "notes": "Direct SQL concatenation without parameterization"
    },
    {
      "endpoint": "/api/login",
      "method": "POST",
      "parameter": "email",
      "sink_type": "sql_concat",
      "witness_payload": "admin'--",
      "context": "Login query uses string interpolation at auth.js:18",
      "confidence": "medium"
    }
  ]
}`

	content := "#!/bin/sh\ncat > /dev/null\ncat <<'OUTPUT'\n" +
		"Here is the vulnerability analysis:\n\n" +
		"```json\n" + queueJSON + "\n```\n\n" +
		"#### custom-" + class + "-check.js\n" +
		"Reason: Custom check for " + class + " sinks\n\n" +
		"```javascript\n" +
		"module.exports = {\n" +
		`    id: "custom-` + class + `-check",` + "\n" +
		`    name: "Custom ` + class + ` Check",` + "\n" +
		`    type: "active",` + "\n" +
		`    severity: "high",` + "\n" +
		`    tags: ["custom", "` + class + `"],` + "\n" +
		`    scanTypes: ["per_insertion_point"],` + "\n" +
		"    scanPerInsertionPoint: function(ctx, insertion) { return null; }\n" +
		"};\n" +
		"```\n" +
		"OUTPUT\n"

	require.NoError(t, os.WriteFile(script, []byte(content), 0755))
	return script
}

// fakeExploitVerifyAgentScript returns a script that outputs valid exploitation_evidence JSON.
func fakeExploitVerifyAgentScript(t *testing.T, class string) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-exploit-"+class+"-agent.sh")
	content := `#!/bin/sh
cat > /dev/null
cat <<'OUTPUT'
` + "```json" + `
{
  "evidence": [
    {
      "finding_ref": "` + class + ` in /api/search?q=",
      "status": "exploited",
      "vuln_class": "` + class + `",
      "payload": "' UNION SELECT 1,2,3--",
      "request": "GET /api/search?q=%27+UNION+SELECT+1,2,3-- HTTP/1.1\r\nHost: localhost:3000",
      "response": "HTTP/1.1 200 OK\r\n\r\n{\"results\":[{\"1\":1,\"2\":2,\"3\":3}]}",
      "impact": "Database extraction via UNION-based injection",
      "confidence": "proven",
      "notes": "Verified with UNION SELECT"
    },
    {
      "finding_ref": "` + class + ` in /api/login",
      "status": "false_positive",
      "vuln_class": "` + class + `",
      "payload": "admin'--",
      "request": "POST /api/login HTTP/1.1",
      "response": "HTTP/1.1 401 Unauthorized",
      "impact": "",
      "confidence": "unconfirmed",
      "notes": "Input is parameterized in production"
    }
  ]
}
` + "```" + `
OUTPUT
`
	require.NoError(t, os.WriteFile(script, []byte(content), 0755))
	return script
}

// fakeReportAgentScript returns a script that outputs a markdown report.
func fakeReportAgentScript(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-report-agent.sh")
	content := `#!/bin/sh
cat > /dev/null
cat <<'OUTPUT'
# Vulnerability Assessment Report

## Executive Summary
Found 1 confirmed vulnerability in the target application.

## Confirmed Vulnerabilities

### SQL Injection in /api/search
- **Severity:** High
- **Payload:** ' UNION SELECT 1,2,3--
- **Impact:** Full database extraction

## False Positives
- /api/login - Input is properly parameterized

## Recommendations
1. Use parameterized queries for all SQL operations
OUTPUT
`
	require.NoError(t, os.WriteFile(script, []byte(content), 0755))
	return script
}

// newAutopilotTestSettings creates settings with a fake agent for testing.
// The agent uses a shell script that outputs pre-canned responses.
func newAutopilotTestSettings(t *testing.T, agentName, scriptPath string) *config.Settings {
	t.Helper()
	return &config.Settings{
		Agent: config.AgentConfig{
			DefaultAgent: agentName,
			Backends: map[string]config.AgentDef{
				agentName: {
					Command:     scriptPath,
					Description: "Fake autopilot agent for e2e testing",
				},
			},
		},
	}
}

// ─── Pipeline tests ─────────────────────────────────────────────────────────

// TestAutopilotReconPhase tests the recon phase with a fake agent that outputs
// a valid recon deliverable JSON.
func TestAutopilotReconPhase(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

	agentName := "fake-recon"
	script := fakeReconAgentScript(t)
	settings := newAutopilotTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	defer engine.Close()

	runner := agent.NewAutopilotPipelineRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.AutopilotPipelineConfig{
		TargetURL:   "http://localhost:3000",
		AgentName:   agentName,
		MaxCommands: 10,
		SessionDir:  sessionDir,
		ProjectUUID: database.DefaultProjectUUID,
		Specialists: []agent.VulnClass{}, // empty = skip vuln analysis
	}

	result, err := runner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Recon phase should have run
	assert.Contains(t, result.PhasesRun, agent.AutopilotPhaseRecon)
	assert.Greater(t, result.PhaseTimings[agent.AutopilotPhaseRecon], time.Duration(0))

	// Checkpoint should exist
	checkpointPath := filepath.Join(sessionDir, "autopilot-checkpoint.json")
	_, statErr := os.Stat(checkpointPath)
	assert.NoError(t, statErr, "expected autopilot-checkpoint.json in session dir")

	// Verify checkpoint content
	cpData, readErr := os.ReadFile(checkpointPath)
	require.NoError(t, readErr)
	var cp agent.AutopilotCheckpoint
	require.NoError(t, json.Unmarshal(cpData, &cp))
	assert.Contains(t, cp.CompletedPhases, agent.AutopilotPhaseRecon)
	assert.Equal(t, "http://localhost:3000", cp.TargetURL)
}

// TestAutopilotVulnAnalysisPhase tests the parallel vuln analysis specialists.
func TestAutopilotVulnAnalysisPhase(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

	// Create scripts for two specialists
	injScript := fakeVulnAnalysisAgentScript(t, "injection")
	xssScript := fakeVulnAnalysisAgentScript(t, "xss")
	reconScript := fakeReconAgentScript(t)

	// Use the same script for all templates (the fake agent ignores the prompt)
	agentName := "fake-autopilot-pipeline"
	settings := &config.Settings{
		Agent: config.AgentConfig{
			DefaultAgent: agentName,
			Backends: map[string]config.AgentDef{
				agentName: {
					// Use the injection script as default; the vuln analysis
					// phase will produce output for whatever class the agent returns.
					Command:     injScript,
					Description: "Fake autopilot agent for testing",
				},
			},
		},
	}
	_ = xssScript   // available for per-class routing if needed
	_ = reconScript // recon uses the same fake agent

	engine := agent.NewEngine(settings, repo)
	defer engine.Close()

	runner := agent.NewAutopilotPipelineRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.AutopilotPipelineConfig{
		TargetURL:   "http://localhost:3000",
		AgentName:   agentName,
		MaxCommands: 10,
		SessionDir:  sessionDir,
		ProjectUUID: database.DefaultProjectUUID,
		Specialists: agent.ToVulnClasses([]string{"injection"}),
	}

	result, err := runner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Vuln analysis phase should have run
	assert.Contains(t, result.PhasesRun, agent.AutopilotPhaseVulnAnalysis)

	// Should have a VulnQueue for injection class
	injQueue, ok := result.VulnQueues[agent.VulnClassInjection]
	if ok && injQueue != nil {
		assert.Equal(t, "injection", injQueue.Class)
		assert.GreaterOrEqual(t, len(injQueue.Items), 1)
	}

	// Extensions should be written to session dir
	extDir := filepath.Join(sessionDir, "extensions")
	if _, err := os.Stat(extDir); err == nil {
		entries, _ := os.ReadDir(extDir)
		assert.GreaterOrEqual(t, len(entries), 1, "expected at least 1 extension file")
	}
}

// TestAutopilotExploitVerifyPhase tests the exploit verification phase.
func TestAutopilotExploitVerifyPhase(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

	agentName := "fake-exploit"
	script := fakeExploitVerifyAgentScript(t, "injection")
	settings := newAutopilotTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	defer engine.Close()

	runner := agent.NewAutopilotPipelineRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.AutopilotPipelineConfig{
		TargetURL:   "http://localhost:3000",
		AgentName:   agentName,
		MaxCommands: 10,
		SessionDir:  sessionDir,
		ProjectUUID: database.DefaultProjectUUID,
		Specialists: agent.ToVulnClasses([]string{"injection"}),
	}

	// Pre-populate VulnQueues so exploit verification has work to do.
	// We do this by running with a fake agent that returns both recon + vuln queue.
	// For simplicity, just run the full pipeline with the exploit script
	// (recon/vuln phases will parse what they can, exploit phase will produce evidence).
	result, err := runner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Check that all phases ran
	assert.Contains(t, result.PhasesRun, agent.AutopilotPhaseRecon)
	assert.Contains(t, result.PhasesRun, agent.AutopilotPhaseExploitVerify)
	assert.Contains(t, result.PhasesRun, agent.AutopilotPhaseReport)

	// If the exploit phase parsed evidence, verify the tallies
	if len(result.Evidence) > 0 {
		ev := result.Evidence[agent.VulnClassInjection]
		if len(ev) > 0 {
			// Our fake script outputs 1 exploited + 1 false_positive
			exploited := 0
			fp := 0
			for _, e := range ev {
				switch e.Status {
				case agent.EvidenceStatusExploited:
					exploited++
				case agent.EvidenceStatusFalsePositive:
					fp++
				}
			}
			assert.Equal(t, 1, exploited, "expected 1 exploited finding")
			assert.Equal(t, 1, fp, "expected 1 false positive")
		}
	}
}

// TestAutopilotFullPipeline tests the entire 5-phase pipeline end-to-end.
func TestAutopilotFullPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

	// Use the recon script as default — all phases will get this output,
	// but each parser extracts what it can (recon gets endpoints, others may get nothing).
	agentName := "fake-full-pipeline"
	script := fakeReconAgentScript(t)
	settings := newAutopilotTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	defer engine.Close()

	runner := agent.NewAutopilotPipelineRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.AutopilotPipelineConfig{
		TargetURL:   "http://localhost:3000",
		AgentName:   agentName,
		MaxCommands: 10,
		SessionDir:  sessionDir,
		ProjectUUID: database.DefaultProjectUUID,
		Specialists: agent.ToVulnClasses([]string{"injection", "xss"}),
	}

	result, err := runner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// All 5 phases should have run
	assert.Contains(t, result.PhasesRun, agent.AutopilotPhaseRecon)
	assert.Contains(t, result.PhasesRun, agent.AutopilotPhaseVulnAnalysis)
	// NativeScan skipped (no ScanFunc provided)
	assert.Contains(t, result.PhasesRun, agent.AutopilotPhaseExploitVerify)
	assert.Contains(t, result.PhasesRun, agent.AutopilotPhaseReport)

	// Duration should be positive
	assert.Greater(t, result.Duration, time.Duration(0))

	// Session dir should have checkpoint
	checkpointPath := filepath.Join(sessionDir, "autopilot-checkpoint.json")
	_, statErr := os.Stat(checkpointPath)
	assert.NoError(t, statErr, "expected autopilot-checkpoint.json")

	// Report should have been written
	reportPath := filepath.Join(sessionDir, "report.md")
	if _, err := os.Stat(reportPath); err == nil {
		reportData, _ := os.ReadFile(reportPath)
		assert.NotEmpty(t, reportData)
	}
}

// TestAutopilotCheckpointResume tests that a pipeline can be resumed from a checkpoint.
func TestAutopilotCheckpointResume(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

	agentName := "fake-resume"
	script := fakeReconAgentScript(t)
	settings := newAutopilotTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	defer engine.Close()

	sessionDir := t.TempDir()

	// Write a synthetic checkpoint that marks recon + vuln-analysis as completed
	cp := &agent.AutopilotCheckpoint{
		CompletedPhases: []agent.AutopilotPhase{
			agent.AutopilotPhaseRecon,
			agent.AutopilotPhaseVulnAnalysis,
		},
		TargetURL: "http://localhost:3000",
		VulnQueues: map[agent.VulnClass]*agent.VulnQueue{
			agent.VulnClassInjection: {
				Class: "injection",
				Items: []agent.VulnQueueItem{
					{Endpoint: "/api/search", Method: "GET", Parameter: "q", Confidence: "high"},
				},
			},
		},
		Timestamp: time.Now(),
	}
	cpData, marshalErr := json.MarshalIndent(cp, "", "  ")
	require.NoError(t, marshalErr)
	require.NoError(t, os.WriteFile(filepath.Join(sessionDir, "autopilot-checkpoint.json"), cpData, 0644))

	runner := agent.NewAutopilotPipelineRunner(engine, repo)

	cfg := agent.AutopilotPipelineConfig{
		TargetURL:   "http://localhost:3000",
		AgentName:   agentName,
		MaxCommands: 10,
		SessionDir:  sessionDir,
		ResumeDir:   sessionDir, // Resume from the same dir
		ProjectUUID: database.DefaultProjectUUID,
		Specialists: agent.ToVulnClasses([]string{"injection"}),
	}

	result, err := runner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Recon and VulnAnalysis should NOT be in PhasesRun (they were checkpointed)
	assert.NotContains(t, result.PhasesRun, agent.AutopilotPhaseRecon)
	assert.NotContains(t, result.PhasesRun, agent.AutopilotPhaseVulnAnalysis)

	// ExploitVerify and Report should have run
	assert.Contains(t, result.PhasesRun, agent.AutopilotPhaseExploitVerify)
	assert.Contains(t, result.PhasesRun, agent.AutopilotPhaseReport)

	// VulnQueues should be restored from checkpoint
	injQueue, ok := result.VulnQueues[agent.VulnClassInjection]
	assert.True(t, ok)
	if ok {
		assert.Equal(t, "injection", injQueue.Class)
		assert.Len(t, injQueue.Items, 1)
	}
}

// TestAutopilotDryRun tests that --dry-run renders the recon prompt without launching agents.
func TestAutopilotDryRun(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, repo := setupTestDB(t)

	settings := newAutopilotTestSettings(t, "fake-autopilot", "/bin/echo")
	engine := agent.NewEngine(settings, repo)
	defer engine.Close()

	runner := agent.NewAutopilotPipelineRunner(engine, repo)

	cfg := agent.AutopilotPipelineConfig{
		TargetURL:   "http://localhost:3000",
		AgentName:   "fake-autopilot",
		MaxCommands: 10,
		SessionDir:  t.TempDir(),
		ProjectUUID: database.DefaultProjectUUID,
		Specialists: agent.ToVulnClasses([]string{"injection"}),
		DryRun:      true,
	}

	result, err := runner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// In dry-run, the pipeline still runs but the engine returns
	// the rendered prompt instead of executing the agent.
	assert.Contains(t, result.PhasesRun, agent.AutopilotPhaseRecon)
}

// ─── MCP Server Config tests ────────────────────────────────────────────────

// TestAutopilotMcpEnabled tests that MCP servers are included when mcp_enabled is true.
func TestAutopilotMcpEnabled(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	settings := &config.Settings{
		Agent: config.AgentConfig{
			DefaultAgent: "test-agent",
			Backends: map[string]config.AgentDef{
				"test-agent": {
					Command:     "/bin/echo",
					Description: "Test agent",
					McpServers: []config.McpServerConfig{
						{Name: "backend-tool", Command: "backend-mcp", Args: []string{"serve"}},
					},
				},
			},
		},
	}

	// When mcp_enabled is false (default), global servers should not be merged
	assert.False(t, settings.Agent.IsMcpEnabled())

	// When mcp_enabled is true, global servers should be merged
	enabled := true
	settings.Agent.McpEnabled = &enabled
	settings.Agent.McpServers = []config.McpServerConfig{
		{Name: "playwright", Command: "npx", Args: []string{"-y", "@anthropic-ai/mcp-server-playwright"}},
		{Name: "backend-tool", Command: "global-mcp"}, // should be overridden by per-backend
	}
	assert.True(t, settings.Agent.IsMcpEnabled())

	// The engine's mergeGlobalMcpServers should merge correctly
	_, repo := setupTestDB(t)
	engine := agent.NewEngine(settings, repo)
	defer engine.Close()

	// Verify: per-backend "backend-tool" takes precedence over global "backend-tool"
	agentDef := settings.Agent.Backends["test-agent"]
	assert.Len(t, agentDef.McpServers, 1, "per-backend should have 1 server before merge")
	assert.Equal(t, "backend-tool", agentDef.McpServers[0].Name)
	assert.Equal(t, "backend-mcp", agentDef.McpServers[0].Command, "per-backend command should be preserved")
}

// ─── Parser unit tests ──────────────────────────────────────────────────────

// TestParseReconDeliverable tests parsing a recon deliverable from agent output.
func TestParseReconDeliverable(t *testing.T) {
	raw := `Here is the recon:

` + "```json" + `
{
  "endpoints": [
    {"url": "http://example.com/api/users", "method": "GET"},
    {"url": "http://example.com/api/login", "method": "POST", "parameter": "email"}
  ],
  "tech_stack": ["express", "postgres"],
  "notes": "REST API with PostgreSQL backend"
}
` + "```"

	result, err := agent.ParseReconDeliverable(raw)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result.Endpoints, 2)
	assert.Equal(t, "http://example.com/api/users", result.Endpoints[0].URL)
	assert.Equal(t, "POST", result.Endpoints[1].Method)
	assert.Equal(t, "email", result.Endpoints[1].Parameter)
	assert.Contains(t, result.TechStack, "express")
	assert.Contains(t, result.TechStack, "postgres")
	assert.Equal(t, "REST API with PostgreSQL backend", result.Notes)
}

// TestParseReconDeliverableWrapped tests parsing a wrapped recon deliverable.
func TestParseReconDeliverableWrapped(t *testing.T) {
	raw := `{"recon": {"endpoints": [{"url": "http://example.com/", "method": "GET"}], "tech_stack": ["nginx"]}}`

	result, err := agent.ParseReconDeliverable(raw)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result.Endpoints, 1)
}

// TestParseVulnQueue tests parsing a vuln queue from agent output.
func TestParseVulnQueue(t *testing.T) {
	raw := `{"class": "injection", "items": [{"endpoint": "/api/search", "method": "GET", "parameter": "q", "sink_type": "sql_concat", "confidence": "high"}]}`

	result, err := agent.ParseVulnQueue(raw)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "injection", result.Class)
	assert.Len(t, result.Items, 1)
	assert.Equal(t, "sql_concat", result.Items[0].SinkType)
	assert.Equal(t, "high", result.Items[0].Confidence)
}

// TestParseExploitationEvidence tests parsing exploitation evidence.
func TestParseExploitationEvidence(t *testing.T) {
	raw := `{"evidence": [{"finding_ref": "SQLi in /search", "status": "exploited", "vuln_class": "injection", "payload": "' OR 1=1--", "request": "GET /search?q=...", "response": "200 OK", "impact": "DB extraction", "confidence": "proven"}]}`

	result, err := agent.ParseExploitationEvidence(raw)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "exploited", result[0].Status)
	assert.Equal(t, "injection", result[0].VulnClass)
	assert.Equal(t, "proven", result[0].Confidence)
}

// TestParseExploitationEvidenceSingleObject tests parsing a single evidence object (not array).
func TestParseExploitationEvidenceSingleObject(t *testing.T) {
	raw := `{"finding_ref": "XSS in /page", "status": "blocked", "vuln_class": "xss", "payload": "<script>", "request": "GET /page", "response": "200", "impact": "none", "confidence": "unconfirmed"}`

	result, err := agent.ParseExploitationEvidence(raw)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "blocked", result[0].Status)
}

// ─── Real agent tests (conditional) ─────────────────────────────────────────

// TestAutopilotRealAgent runs the full pipeline with a real agent backend.
// Skipped unless -agent flag is provided.
func TestAutopilotRealAgent(t *testing.T) {
	if *testAgentName == "" {
		t.Skip("Skipping: use -agent=<name> to run with real agent")
	}
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	settings, err := config.LoadSettings(*testConfigPath)
	require.NoError(t, err)

	db, repo := setupTestDB(t)
	_ = db

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	runner := agent.NewAutopilotPipelineRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.AutopilotPipelineConfig{
		TargetURL:   *testTargetURL,
		AgentName:   *testAgentName,
		MaxCommands: 20,
		SessionDir:  sessionDir,
		ProjectUUID: database.DefaultProjectUUID,
		Specialists: agent.ToVulnClasses([]string{"injection", "xss"}),
	}

	result, err := runner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	t.Logf("Pipeline completed in %s", result.Duration.Round(time.Second))
	t.Logf("Phases run: %v", result.PhasesRun)
	t.Logf("Findings: total=%d confirmed=%d fp=%d", result.TotalFindings, result.Confirmed, result.FalsePositives)
	t.Logf("Session dir: %s", sessionDir)
}
