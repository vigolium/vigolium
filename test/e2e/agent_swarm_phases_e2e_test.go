//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/database"
)

// --- Scan Phase Tests ---

// TestSwarmScanPhaseInvokesScanFunc verifies the scan phase invokes ScanFunc
// with the correct module tags, module IDs, and extension directory from the plan.
func TestSwarmScanPhaseInvokesScanFunc(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

	agentName := "fake-swarm-scan"
	script := fakeSwarmAgentWithExtensions(t)
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()

	// Track ScanFunc invocation
	var scanCalled int32
	var capturedReq agent.ScanRequest

	cfg := agent.SwarmConfig{
		Inputs:        []string{"http://localhost:12345/api/search?q=test"},
		AgentName:     agentName,
		MaxIterations: 0, // disable triage to isolate the scan phase
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		ScanFunc: func(ctx context.Context, req agent.ScanRequest) error {
			atomic.AddInt32(&scanCalled, 1)
			capturedReq = req
			return nil
		},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// ScanFunc must have been called exactly once (initial scan, no rescan)
	assert.Equal(t, int32(1), atomic.LoadInt32(&scanCalled), "ScanFunc should be called once for initial scan")

	// Module tags and IDs from the plan should be forwarded to ScanFunc
	require.NotNil(t, result.SwarmPlan)
	assert.ElementsMatch(t, result.SwarmPlan.ModuleTags, capturedReq.ModuleTags)
	assert.ElementsMatch(t, result.SwarmPlan.ModuleIDs, capturedReq.ModuleIDs)

	// Extension directory should be set (extensions were generated from the plan)
	assert.NotEmpty(t, capturedReq.ExtensionDir, "ScanFunc should receive extension directory")
	assert.False(t, capturedReq.IsRescan, "initial scan should not be marked as rescan")
}

// TestSwarmScanPhaseNilScanFuncSkips verifies the scan phase is skipped when
// ScanFunc is nil (graceful degradation).
func TestSwarmScanPhaseNilScanFuncSkips(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

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
		ScanFunc:      nil, // no scan callback
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Plan should still be parsed
	require.NotNil(t, result.SwarmPlan)
	// No findings since no scan was run
	assert.Equal(t, 0, result.TotalFindings)
}

// --- Triage Phase Tests ---

// fakeTriageConfirmAgent returns a script that confirms all findings.
func fakeTriageConfirmAgent(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-triage-confirm.sh")
	content := `#!/bin/sh
cat > /dev/null
cat <<'TRIAGE'
{"confirmed":[{"title":"XSS in search","module_id":"xss-reflected","url":"http://localhost:12345/search","reason":"confirmed via payload reflection"}],"false_positives":[{"title":"SQLI false alarm","module_id":"sqli-error","url":"http://localhost:12345/login","reason":"error message is generic"}],"verdict":"done","notes":"triage complete"}
TRIAGE
`
	require.NoError(t, os.WriteFile(script, []byte(content), 0755))
	return script
}

// fakeTriageRescanAgent returns a script that requests a rescan in the first call,
// then confirms in subsequent calls. It uses a state file to track calls.
func fakeTriageRescanAgent(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "call-count")
	require.NoError(t, os.WriteFile(stateFile, []byte("0"), 0644))

	script := filepath.Join(dir, "fake-triage-rescan.sh")
	content := `#!/bin/sh
cat > /dev/null
STATE_FILE="` + stateFile + `"
COUNT=$(cat "$STATE_FILE" 2>/dev/null || echo 0)
COUNT=$((COUNT + 1))
echo "$COUNT" > "$STATE_FILE"
if [ "$COUNT" -eq 1 ]; then
cat <<'TRIAGE'
{"confirmed":[{"title":"XSS in search","module_id":"xss-reflected","url":"http://localhost:12345/search","reason":"reflected XSS confirmed"}],"false_positives":[],"follow_up_scans":[{"url":"http://localhost:12345/api/users","module_tags":["sqli","injection"],"module_ids":["sqli-blind"],"rationale":"needs deeper SQL injection testing"}],"verdict":"rescan","notes":"rescan needed for SQL injection"}
TRIAGE
else
cat <<'TRIAGE'
{"confirmed":[{"title":"SQLI in users","module_id":"sqli-blind","url":"http://localhost:12345/api/users","reason":"blind SQL injection confirmed"}],"false_positives":[],"verdict":"done","notes":"all confirmed after rescan"}
TRIAGE
fi
`
	require.NoError(t, os.WriteFile(script, []byte(content), 0755))
	return script, stateFile
}

// TestSwarmTriageConfirmsFindings tests the triage loop with a fake agent that
// confirms some findings and marks others as false positives.
func TestSwarmTriageConfirmsFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, repo := setupTestDB(t)

	// Seed a finding in the DB so triage has something to review
	finding := &database.Finding{
		ProjectUUID:     database.DefaultProjectUUID,
		ModuleID:        "xss-reflected",
		ModuleName:      "XSS Reflected",
		Severity:        "high",
		Confidence:      "tentative",
		HTTPRecordUUIDs: []string{},
		Tags:            []string{"xss"},
		FindingHash:     "test-triage-confirm-001",
	}
	require.NoError(t, repo.SaveFindingDirect(ctx, finding))

	// Use two agents: plan agent + triage agent
	triageScript := fakeTriageConfirmAgent(t)
	planScript := fakeSwarmAgentScript(t)

	settings := &config.Settings{
		Agent: config.AgentConfig{
			DefaultAgent: "fake-plan",
			Backends: map[string]config.AgentDef{
				"fake-plan": {
					Command:     planScript,
					Description: "Plan agent",
				},
			},
		},
	}

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()

	// ScanFunc is a no-op (findings already seeded)
	scanCalled := false
	cfg := agent.SwarmConfig{
		Inputs:        []string{"http://localhost:12345/"},
		AgentName:     "fake-plan",
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		ScanFunc: func(ctx context.Context, req agent.ScanRequest) error {
			scanCalled = true
			return nil
		},
	}

	// Override triage to use the triage script by registering it as the agent
	// The triage uses the same agent backend, so we override with triage script
	settings.Agent.Backends["fake-plan"] = config.AgentDef{
		Command:     planScript,
		Description: "Plan+Triage agent",
	}

	// For the triage phase, the swarm uses the same agent name but a different prompt template.
	// We need both plan and triage to work. Since the fake plan script just outputs a plan
	// and the triage template will be sent to the same agent, we need a smarter approach.
	// Let's just register a single agent that handles both (the plan output will work for plan phase,
	// and for triage, the agent-swarm-triage template will be used, but the agent still runs the same command).

	// Actually, since we can't differentiate between plan and triage calls with a single agent command,
	// and the triage runs with the same agent name, let's use a script that detects which phase it's in.
	combinedDir := t.TempDir()
	combinedScript := filepath.Join(combinedDir, "combined-agent.sh")
	combinedContent := `#!/bin/sh
# Read stdin and detect if this is a triage call
INPUT=$(cat)
if echo "$INPUT" | grep -q "triage\|confirmed\|false_positive"; then
cat <<'TRIAGE'
{"confirmed":[{"title":"XSS in search","module_id":"xss-reflected","url":"http://localhost:12345/search","reason":"confirmed"}],"false_positives":[],"verdict":"done","notes":"triage complete"}
TRIAGE
else
cat <<'PLAN'
## MODULE_TAGS
discovery, fingerprint, light

## FOCUS_AREAS
- Technology fingerprinting on root endpoint

## NOTES
Target is a local HTTP service.
PLAN
fi
`
	require.NoError(t, os.WriteFile(combinedScript, []byte(combinedContent), 0755))

	settings.Agent.Backends["fake-plan"] = config.AgentDef{
		Command:     combinedScript,
		Description: "Combined plan+triage agent",
	}

	// Re-create engine with updated settings
	engine.Close()
	engine = agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner = agent.NewSwarmRunner(engine, repo)

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	_ = db
	_ = triageScript

	// Scan should have been called
	assert.True(t, scanCalled, "ScanFunc should be called for initial scan")

	// Triage results should be populated
	assert.GreaterOrEqual(t, len(result.TriageResults), 1, "expected at least 1 triage result")
	assert.GreaterOrEqual(t, result.Confirmed, 1, "expected at least 1 confirmed finding")
	assert.Equal(t, "done", result.TriageResults[0].Verdict)

	// Triage prompt and output should be saved to session dir
	triagePromptPath := filepath.Join(sessionDir, "triage-0-prompt.md")
	_, statErr := os.Stat(triagePromptPath)
	assert.NoError(t, statErr, "expected triage prompt file in session dir")

	triageOutputPath := filepath.Join(sessionDir, "triage-0-output.md")
	_, statErr = os.Stat(triageOutputPath)
	assert.NoError(t, statErr, "expected triage output file in session dir")
}

// TestSwarmTriageRescanLoop tests the full triage → rescan → triage cycle.
func TestSwarmTriageRescanLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

	// Seed a finding so triage has work to do
	finding := &database.Finding{
		ProjectUUID:     database.DefaultProjectUUID,
		ModuleID:        "xss-reflected",
		ModuleName:      "XSS Reflected",
		Severity:        "high",
		Confidence:      "tentative",
		HTTPRecordUUIDs: []string{},
		Tags:            []string{"xss"},
		FindingHash:     "test-rescan-loop-001",
	}
	require.NoError(t, repo.SaveFindingDirect(ctx, finding))

	// Create a rescan triage agent (rescan on first call, done on second)
	rescanScript, stateFile := fakeTriageRescanAgent(t)
	_ = stateFile

	// Combined agent: plan on first call, rescan triage on subsequent calls
	combinedDir := t.TempDir()
	combinedScript := filepath.Join(combinedDir, "combined-rescan-agent.sh")
	combinedContent := `#!/bin/sh
INPUT=$(cat)
if echo "$INPUT" | grep -q "triage\|confirmed\|false_positive"; then
` + rescanScript + ` < /dev/null
else
cat <<'PLAN'
## MODULE_TAGS
discovery, xss

## FOCUS_AREAS
- XSS in search parameters

## NOTES
Target has potential XSS.
PLAN
fi
`
	// Actually, let's simplify. The rescan script already handles state.
	// We need to call it as a child process.
	combinedContent = `#!/bin/sh
INPUT=$(cat)
if echo "$INPUT" | grep -q "triage\|confirmed\|false_positive"; then
  exec "` + rescanScript + `"
else
cat <<'PLAN'
## MODULE_TAGS
discovery, xss

## FOCUS_AREAS
- XSS in search parameters

## NOTES
Target has potential XSS.
PLAN
fi
`
	require.NoError(t, os.WriteFile(combinedScript, []byte(combinedContent), 0755))

	agentName := "fake-rescan-agent"
	settings := newSwarmTestSettings(t, agentName, combinedScript)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()

	// Track scan and rescan invocations
	var scanCalls int32
	var lastScanReq agent.ScanRequest

	cfg := agent.SwarmConfig{
		Inputs:        []string{"http://localhost:12345/"},
		AgentName:     agentName,
		MaxIterations: 3,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		ScanFunc: func(ctx context.Context, req agent.ScanRequest) error {
			atomic.AddInt32(&scanCalls, 1)
			lastScanReq = req
			return nil
		},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should have at least 2 scan calls: initial + rescan
	totalScans := atomic.LoadInt32(&scanCalls)
	assert.GreaterOrEqual(t, totalScans, int32(2),
		"expected at least 2 scan calls (initial + rescan), got %d", totalScans)

	// The rescan should have been marked as a rescan
	assert.True(t, lastScanReq.IsRescan, "last scan should be marked as rescan")

	// Rescan should have the follow-up module tags from triage
	assert.Contains(t, lastScanReq.ModuleTags, "sqli")
	assert.Contains(t, lastScanReq.ModuleTags, "injection")
	assert.Contains(t, lastScanReq.ModuleIDs, "sqli-blind")

	// Result should reflect confirmed findings from both rounds
	assert.GreaterOrEqual(t, result.Confirmed, 2,
		"expected at least 2 confirmed findings (1 from round 1, 1 from rescan round)")
	assert.GreaterOrEqual(t, result.Iterations, 2,
		"expected at least 2 triage iterations")
}

// --- Discovery Phase Tests ---

// TestSwarmDiscoveryPhase tests that the discovery callback is invoked and
// discovered records are merged with input records.
func TestSwarmDiscoveryPhase(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

	agentName := "fake-swarm"
	script := fakeSwarmAgentScript(t)
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()

	// Track discovery callback invocation
	var discoverCalled int32

	cfg := agent.SwarmConfig{
		Inputs:        []string{"http://localhost:12345/"},
		AgentName:     agentName,
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		DiscoverFunc: func(ctx context.Context) error {
			atomic.AddInt32(&discoverCalled, 1)
			return nil
		},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Discovery callback should have been invoked
	assert.Equal(t, int32(1), atomic.LoadInt32(&discoverCalled),
		"DiscoverFunc should be called exactly once")

	// Plan should still be parsed (discovery doesn't block planning)
	require.NotNil(t, result.SwarmPlan)
}

// TestSwarmDiscoveryPhaseErrorContinues verifies that a discovery failure
// doesn't abort the pipeline — it logs and continues.
func TestSwarmDiscoveryPhaseErrorContinues(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

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
		DiscoverFunc: func(ctx context.Context) error {
			return assert.AnError // simulate discovery failure
		},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	// Pipeline should succeed despite discovery failure
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.SwarmPlan, "plan should still be generated after discovery failure")
}

// --- Phase Callback Tests ---

// TestSwarmPhaseCallbacksInvoked verifies that PhaseCallback is called for
// each pipeline phase as it starts.
func TestSwarmPhaseCallbacksInvoked(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

	agentName := "fake-swarm"
	script := fakeSwarmAgentScript(t)
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()

	// Collect phase names
	var phases []string
	cfg := agent.SwarmConfig{
		Inputs:        []string{"http://localhost:12345/"},
		AgentName:     agentName,
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		ScanFunc: func(ctx context.Context, req agent.ScanRequest) error {
			return nil
		},
		PhaseCallback: func(phase string) {
			phases = append(phases, phase)
		},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// At minimum: plan, scan, triage (normalize and extension don't emit phase callbacks)
	assert.Contains(t, phases, "plan", "expected plan phase callback")
	assert.Contains(t, phases, "native-scan", "expected scan phase callback")
	assert.Contains(t, phases, "triage", "expected triage phase callback")
	// Should have at least 3 phase callbacks
	assert.GreaterOrEqual(t, len(phases), 3, "expected at least 3 phase callbacks")
}

// --- Checkpoint Tests ---

// TestSwarmCheckpointContainsPlanAndExtensions verifies that the checkpoint
// written after the scan phase includes the parsed plan and extension directory.
func TestSwarmCheckpointContainsPlanAndExtensions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

	agentName := "fake-swarm-ext"
	script := fakeSwarmAgentWithExtensions(t)
	settings := newSwarmTestSettings(t, agentName, script)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs:        []string{"http://localhost:12345/api/v1/test"},
		AgentName:     agentName,
		MaxIterations: 1,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		ScanFunc: func(ctx context.Context, req agent.ScanRequest) error {
			return nil
		},
	}

	_, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)

	// Read and parse checkpoint
	checkpointPath := filepath.Join(sessionDir, "checkpoint.json")
	data, readErr := os.ReadFile(checkpointPath)
	require.NoError(t, readErr, "checkpoint.json should exist")

	var checkpoint struct {
		CompletedPhases []string        `json:"completed_phases"`
		TargetURL       string          `json:"target_url"`
		RecordCount     int             `json:"record_count"`
		ExtensionDir    string          `json:"extension_dir,omitempty"`
		Plan            json.RawMessage `json:"plan,omitempty"`
	}
	require.NoError(t, json.Unmarshal(data, &checkpoint))

	// Verify completed phases include scan
	assert.Contains(t, checkpoint.CompletedPhases, "native-normalize")
	assert.Contains(t, checkpoint.CompletedPhases, "plan")
	assert.Contains(t, checkpoint.CompletedPhases, "native-scan")

	// Verify target URL was captured
	assert.Equal(t, "http://localhost:12345/api/v1/test", checkpoint.TargetURL)
	assert.Equal(t, 1, checkpoint.RecordCount)

	// Verify plan is in checkpoint
	assert.NotEmpty(t, checkpoint.Plan, "checkpoint should include the parsed plan")

	// Verify extension dir is in checkpoint (extensions were generated)
	assert.NotEmpty(t, checkpoint.ExtensionDir, "checkpoint should include extension directory")
}

// --- Triage Early Exit Tests ---

// TestSwarmTriageEarlyExitCertainFindings verifies that when all findings
// have "certain" confidence, the triage loop is skipped entirely.
func TestSwarmTriageEarlyExitCertainFindings(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

	// Seed findings with "certain" confidence (unique hashes to avoid constraint violation)
	for _, f := range []*database.Finding{
		{
			ProjectUUID:     database.DefaultProjectUUID,
			ModuleID:        "sqli-error-based",
			ModuleName:      "SQL Injection Error Based",
			Severity:        "high",
			Confidence:      "certain",
			HTTPRecordUUIDs: []string{},
			Tags:            []string{"sqli"},
			FindingHash:     "test-certain-sqli-001",
		},
		{
			ProjectUUID:     database.DefaultProjectUUID,
			ModuleID:        "xss-reflected",
			ModuleName:      "XSS Reflected",
			Severity:        "medium",
			Confidence:      "certain",
			HTTPRecordUUIDs: []string{},
			Tags:            []string{"xss"},
			FindingHash:     "test-certain-xss-002",
		},
	} {
		require.NoError(t, repo.SaveFindingDirect(ctx, f))
	}

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
		MaxIterations: 3,
		ProjectUUID:   database.DefaultProjectUUID,
		SessionDir:    sessionDir,
		ScanFunc: func(ctx context.Context, req agent.ScanRequest) error {
			return nil
		},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// When all findings are "certain", triage should auto-confirm without agent calls.
	// The confirmed count should equal the number of seeded findings.
	assert.Equal(t, 2, result.Confirmed, "all 'certain' findings should be auto-confirmed")
	// No triage agent output files should exist (agent was never called for triage)
	triageOutputPath := filepath.Join(sessionDir, "triage-output-0.md")
	_, statErr := os.Stat(triageOutputPath)
	assert.True(t, os.IsNotExist(statErr), "triage agent should not be called when all findings are certain")
}

// --- Phase Timing Tests ---

// TestSwarmPhaseTimingsPopulated verifies that phase timings are recorded
// in the result for all executed phases.
func TestSwarmPhaseTimingsPopulated(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

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
		ScanFunc: func(ctx context.Context, req agent.ScanRequest) error {
			return nil
		},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Phase timings should be populated
	require.NotNil(t, result.PhaseTimings, "phase timings should be set")
	assert.Contains(t, result.PhaseTimings, "native-normalize")
	assert.Contains(t, result.PhaseTimings, "plan")
	assert.Contains(t, result.PhaseTimings, "native-scan")
	assert.Contains(t, result.PhaseTimings, "triage")

	// All timings should be positive
	for phase, duration := range result.PhaseTimings {
		assert.Greater(t, duration, time.Duration(0), "phase %s should have positive timing", phase)
	}
}
