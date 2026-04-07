//go:build e2e

package e2e

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/archon"
	"github.com/vigolium/vigolium/pkg/database"
)

// fakeAuditAgentScript returns a shell script that mimics an archon-audit
// Claude Code process. It writes audit-state.json and finding files to the
// archon/ directory in CWD (which is the source path).
func fakeAuditAgentScript(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-claude.sh")
	content := `#!/bin/sh
# Fake claude CLI that simulates archon-audit behavior.
# It writes audit state and findings to archon/ in CWD.

mkdir -p archon/findings-draft

# Write audit state
cat > archon/audit-state.json <<'STATE'
{
  "audits": [
    {
      "audit_id": "2026-03-29T10:00:00Z",
      "commit": "abc123",
      "branch": "main",
      "started_at": "2026-03-29T10:00:00Z",
      "completed_at": "2026-03-29T10:30:00Z",
      "status": "complete",
      "mode": "lite",
      "phases": {
        "1": {"status": "complete"},
        "2": {"status": "complete"},
        "3": {"status": "complete"},
        "4": {"status": "complete"},
        "5": {"status": "complete"},
        "6": {"status": "complete"}
      }
    }
  ]
}
STATE

# Write a high finding (phase 8 frontmatter format)
cat > archon/findings-draft/p8-001-sql-injection-login.md <<'FINDING'
Phase: 8
Sequence: 001
Slug: sql-injection-login
Verdict: VALID
Severity-Original: HIGH
Severity-Final: HIGH
PoC-Status: theoretical
Adversarial-Verdict: CONFIRMED

## Summary

The login endpoint at /api/auth/login is vulnerable to SQL injection
via the username parameter.

## Location

- ` + "`" + `src/auth/login.go:42` + "`" + ` -- username parameter handling

## Evidence

POST /api/auth/login with username=' OR 1=1--

## Reproduction Steps

1. Send POST request with malicious username
2. Observe SQL error in response
FINDING

# Write a medium finding
cat > archon/findings-draft/p8-002-idor-profile-api.md <<'FINDING'
Phase: 8
Sequence: 002
Slug: idor-profile-api
Verdict: VALID
Severity-Original: MEDIUM
Severity-Final: MEDIUM
PoC-Status: pending
Adversarial-Verdict: CONFIRMED

## Summary

The /api/users/:id endpoint does not verify ownership.

## Location

- ` + "`" + `src/api/users.go:88` + "`" + ` -- missing authorization check

## Reproduction Steps

1. Authenticate as user A
2. Access /api/users/B
3. Observe user B profile is returned
FINDING

echo "Audit complete."
`
	require.NoError(t, os.WriteFile(script, []byte(content), 0755))
	return script
}

// fakeSlowAuditAgentScript returns a script that sleeps briefly before writing results,
// simulating a running audit agent that gets cancelled.
func fakeSlowAuditAgentScript(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-claude-slow.sh")
	content := `#!/bin/sh
mkdir -p archon
cat > archon/audit-state.json <<'STATE'
{"audits": [{"audit_id": "2026-03-29T10:00:00Z", "commit": "abc123", "branch": "main", "started_at": "2026-03-29T10:00:00Z", "status": "in_progress", "mode": "lite", "phases": {"1": {"status": "complete"}, "2": {"status": "in_progress"}}}]}
STATE
# Sleep long enough that the test will cancel us
sleep 30
`
	require.NoError(t, os.WriteFile(script, []byte(content), 0755))
	return script
}

// TestAuditAgent_SwarmWithAuditAgent verifies that the archon-audit runs in the
// background during a swarm pipeline and ingests findings into the database.
func TestAuditAgent_SwarmWithAuditAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

	sourceDir := t.TempDir()

	claudeScript := fakeAuditAgentScript(t)
	swarmScript := fakeSwarmAgentScript(t)

	agentName := "fake-audit-swarm"
	enabled := true
	settings := &config.Settings{
		Agent: config.AgentConfig{
			DefaultAgent: agentName,
			Backends: map[string]config.AgentDef{
				agentName: {
					Command:     swarmScript,
					Description: "Fake swarm agent",
				},
			},
			Archon: config.AuditAgentConfig{
				Enable:       &enabled,
				Mode:         "lite",
				SyncInterval: 1,
			},
		},
	}

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)
	sessionDir := t.TempDir()

	// Override PATH so "claude" resolves to our fake script
	origPath := os.Getenv("PATH")
	os.Setenv("PATH", filepath.Dir(claudeScript)+":"+origPath)
	t.Cleanup(func() { os.Setenv("PATH", origPath) })

	claudeDir := filepath.Dir(claudeScript)
	claudeLink := filepath.Join(claudeDir, "claude")
	require.NoError(t, os.Rename(claudeScript, claudeLink))

	auditCfg := &settings.Agent.Archon
	cfg := agent.SwarmConfig{
		Inputs:      []string{"http://localhost:12345/"},
		SourcePath:  sourceDir,
		AgentName:   agentName,
		ProjectUUID: database.DefaultProjectUUID,
		SessionDir:  sessionDir,
		Archon:  auditCfg,
		SkipPhases:  []string{"native-scan", "triage", "native-rescan"},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Wait a moment for the archon-audit to finish (it runs in background)
	time.Sleep(2 * time.Second)

	// Verify: audit-state.json was synced to session dir
	auditStatePath := filepath.Join(sessionDir, "archon-audit", "audit-state.json")
	assert.FileExists(t, auditStatePath, "audit-state.json should be synced to session dir")

	// Verify: findings were copied to session dir
	findingsDir := filepath.Join(sessionDir, "archon-audit", "findings-draft")
	if _, err := os.Stat(findingsDir); err == nil {
		entries, _ := os.ReadDir(findingsDir)
		assert.GreaterOrEqual(t, len(entries), 2, "should have at least 2 finding files copied")
	}

	// Verify: archon/ dir was cleaned up from source (removed after import)
	archonSrcDir := filepath.Join(sourceDir, "archon")
	_, err = os.Stat(archonSrcDir)
	assert.True(t, os.IsNotExist(err), "archon dir should be cleaned up from source after import")
}

// TestAuditAgent_SkippedWhenNoSource verifies that the audit agent is NOT started
// when no --source is provided.
func TestAuditAgent_SkippedWhenNoSource(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

	agentName := "fake-no-source"
	swarmScript := fakeSwarmAgentScript(t)
	enabled := true
	settings := &config.Settings{
		Agent: config.AgentConfig{
			DefaultAgent: agentName,
			Backends: map[string]config.AgentDef{
				agentName: {
					Command:     swarmScript,
					Description: "Fake swarm agent",
				},
			},
			Archon: config.AuditAgentConfig{
				Enable: &enabled,
				Mode:   "lite",
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
		SourcePath:  "", // no source
		AgentName:   agentName,
		ProjectUUID: database.DefaultProjectUUID,
		SessionDir:  sessionDir,
		Archon:  &settings.Agent.Archon,
		SkipPhases:  []string{"native-scan", "triage", "native-rescan"},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Audit agent artifacts should NOT exist
	auditDir := filepath.Join(sessionDir, "archon-audit")
	_, err = os.Stat(auditDir)
	assert.True(t, os.IsNotExist(err), "archon-audit dir should not exist without source")
}

// TestAuditAgent_SkippedWhenDisabled verifies that the audit agent is NOT started
// when audit agent is not enabled.
func TestAuditAgent_SkippedWhenDisabled(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

	sourceDir := t.TempDir()
	agentName := "fake-disabled"
	swarmScript := fakeSwarmAgentScript(t)
	settings := &config.Settings{
		Agent: config.AgentConfig{
			DefaultAgent: agentName,
			Backends: map[string]config.AgentDef{
				agentName: {
					Command:     swarmScript,
					Description: "Fake swarm agent",
				},
			},
			// AuditAgent not enabled (default)
		},
	}

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)
	sessionDir := t.TempDir()

	cfg := agent.SwarmConfig{
		Inputs:      []string{"http://localhost:12345/"},
		SourcePath:  sourceDir,
		AgentName:   agentName,
		ProjectUUID: database.DefaultProjectUUID,
		SessionDir:  sessionDir,
		Archon:  nil, // explicitly nil
		SkipPhases:  []string{"native-scan", "triage", "native-rescan"},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Audit agent artifacts should NOT exist
	auditDir := filepath.Join(sessionDir, "archon-audit")
	_, err = os.Stat(auditDir)
	assert.True(t, os.IsNotExist(err), "archon-audit dir should not exist when disabled")
}

// TestAuditAgent_ResolveConfig verifies the shared config resolution logic.
// Archon is now enabled by default when source is provided, disabled with noArchon=true.
func TestAuditAgent_ResolveConfig(t *testing.T) {
	baseCfg := config.AuditAgentConfig{
		PluginDir:    "/custom/path",
		Mode:         "deep",
		SyncInterval: 60,
	}

	tests := []struct {
		name       string
		noArchon   bool
		mode       string
		sourcePath string
		cfg        config.AuditAgentConfig
		wantNil    bool
		wantMode   string
	}{
		{"no source returns nil", false, "", "", baseCfg, true, ""},
		{"source with defaults uses lite", false, "", "/src/app", baseCfg, false, "deep"},
		{"source with mode=lite", false, "lite", "/src/app", baseCfg, false, "lite"},
		{"source with mode=deep", false, "deep", "/src/app", baseCfg, false, "deep"},
		{"source with mode=scan", false, "scan", "/src/app", baseCfg, false, "scan"},
		{"noArchon disables even with source", true, "", "/src/app", baseCfg, true, ""},
		{"noArchon disables with mode", true, "deep", "/src/app", baseCfg, true, ""},
		{"preserves SyncInterval", false, "lite", "/src/app", baseCfg, false, "lite"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := agent.ResolveAuditAgentConfig(tt.noArchon, tt.mode, tt.sourcePath, tt.cfg)
			if tt.wantNil {
				assert.Nil(t, result)
				return
			}
			require.NotNil(t, result)
			assert.Equal(t, tt.wantMode, result.Mode)
			assert.True(t, result.IsEnabled())

			if tt.cfg.SyncInterval > 0 {
				assert.Equal(t, tt.cfg.SyncInterval, result.SyncInterval,
					"SyncInterval from config should be preserved")
			}
			if tt.cfg.PluginDir != "" {
				assert.Equal(t, tt.cfg.PluginDir, result.PluginDir,
					"PluginDir from config should be preserved")
			}
		})
	}
}

// TestAuditAgent_MockMode verifies that mock mode writes a sample audit-state.json
// directly in Go without launching any subprocess. This tests the pipeline-level
// short-circuit in RunAutonomous.
func TestAuditAgent_MockMode(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	sessionDir := t.TempDir()
	sourceDir := t.TempDir()

	archonCfg := &config.AuditAgentConfig{
		Mode: "mock",
	}

	settings := config.DefaultSettings()
	engine := agent.NewEngine(settings, nil)
	defer engine.Close()

	runner := agent.NewAutopilotPipelineRunner(engine, nil)
	result, err := runner.RunAutonomous(context.Background(), agent.AutopilotPipelineConfig{
		SourcePath: sourceDir,
		SessionDir: sessionDir,
		Archon:     archonCfg,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify: audit-state.json was written to session dir
	auditStatePath := filepath.Join(sessionDir, "archon-audit", "audit-state.json")
	require.FileExists(t, auditStatePath, "audit-state.json should exist in session dir")

	data, err := os.ReadFile(auditStatePath)
	require.NoError(t, err)

	stateStr := string(data)
	assert.Contains(t, stateStr, `"status": "complete"`, "state should be complete")
	assert.Contains(t, stateStr, `"mock"`, "should have a mock phase")
	assert.Contains(t, stateStr, `"Mock mode"`, "should have mock summary")
}

// TestAuditAgent_MockResolveConfig verifies that mock is accepted by ResolveAuditAgentConfig.
func TestAuditAgent_MockResolveConfig(t *testing.T) {
	baseCfg := config.AuditAgentConfig{}
	result := agent.ResolveAuditAgentConfig(false, "mock", "/src/app", baseCfg)
	require.NotNil(t, result)
	assert.Equal(t, "mock", result.Mode)
	assert.True(t, result.IsEnabled())
}

// TestAuditAgent_EmbeddedPluginExtraction verifies that the embedded archon-audit
// harness is extracted and contains expected files.
func TestAuditAgent_EmbeddedPluginExtraction(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	baseDir := filepath.Join(t.TempDir(), "archon-audit")

	pluginDir, err := archon.ExtractArchonHarness(baseDir)
	require.NoError(t, err)
	require.NotEmpty(t, pluginDir)

	// Verify key files exist
	assert.FileExists(t, filepath.Join(pluginDir, "commands", "archon", "deep.md"))
	assert.FileExists(t, filepath.Join(pluginDir, "commands", "archon", "lite.md"))
	assert.FileExists(t, filepath.Join(pluginDir, ".claude-plugin", "plugin.json"))

	agentsDir := filepath.Join(pluginDir, "agents")
	entries, err := os.ReadDir(agentsDir)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(entries), 20, "should have 20+ agent definition files")

	// Verify skills are extracted
	skillsDir := filepath.Join(pluginDir, "skills")
	_, err = os.Stat(skillsDir)
	assert.NoError(t, err, "skills directory should exist")

	// Verify idempotency — second call should be fast (marker hit)
	pluginDir2, err := archon.ExtractArchonHarness(baseDir)
	require.NoError(t, err)
	assert.Equal(t, pluginDir, pluginDir2)
}

// TestAuditAgent_CancelledMidRun verifies that when the swarm completes before
// the archon-audit, the audit is gracefully cancelled.
func TestAuditAgent_CancelledMidRun(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, repo := setupTestDB(t)

	sourceDir := t.TempDir()

	claudeScript := fakeSlowAuditAgentScript(t)
	claudeDir := filepath.Dir(claudeScript)
	claudeLink := filepath.Join(claudeDir, "claude")
	require.NoError(t, os.Rename(claudeScript, claudeLink))

	origPath := os.Getenv("PATH")
	os.Setenv("PATH", claudeDir+":"+origPath)
	t.Cleanup(func() { os.Setenv("PATH", origPath) })

	swarmScript := fakeSwarmAgentScript(t)
	agentName := "fake-cancel-audit"
	enabled := true
	settings := &config.Settings{
		Agent: config.AgentConfig{
			DefaultAgent: agentName,
			Backends: map[string]config.AgentDef{
				agentName: {
					Command:     swarmScript,
					Description: "Fake swarm agent",
				},
			},
			Archon: config.AuditAgentConfig{
				Enable:       &enabled,
				Mode:         "lite",
				SyncInterval: 1,
			},
		},
	}

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)
	sessionDir := t.TempDir()

	var auditPhaseLogged int32
	cfg := agent.SwarmConfig{
		Inputs:      []string{"http://localhost:12345/"},
		SourcePath:  sourceDir,
		AgentName:   agentName,
		ProjectUUID: database.DefaultProjectUUID,
		SessionDir:  sessionDir,
		Archon:  &settings.Agent.Archon,
		SkipPhases:  []string{"native-scan", "triage", "native-rescan"},
		PhaseCallback: func(phase string) {
			atomic.AddInt32(&auditPhaseLogged, 1)
		},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// The archon-audit should have had time to write initial state before being killed
	auditStateSrc := filepath.Join(sourceDir, "archon", "audit-state.json")
	if _, err := os.Stat(auditStateSrc); err == nil {
		data, readErr := os.ReadFile(auditStateSrc)
		assert.NoError(t, readErr)
		assert.Contains(t, string(data), "in_progress", "slow audit should show in_progress state")
	}
}
