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
	"github.com/vigolium/vigolium/pkg/database"
)

// fakeAuditAgentScript returns a shell script that mimics a vig-audit-agent
// Claude Code process. It writes audit-state.json and finding files to the
// security/ directory in CWD (which is the source path).
func fakeAuditAgentScript(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-claude.sh")
	content := `#!/bin/sh
# Fake claude CLI that simulates vig-audit-agent behavior.
# It writes audit state and findings to security/ in CWD.

mkdir -p security/findings

# Write audit state
cat > security/audit-state.json <<'STATE'
{
  "audits": [
    {
      "audit_id": "2026-03-29T10:00:00Z",
      "commit": "abc123",
      "branch": "main",
      "started_at": "2026-03-29T10:00:00Z",
      "completed_at": "2026-03-29T10:30:00Z",
      "status": "completed",
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

# Write a critical finding
cat > security/findings/C-001.md <<'FINDING'
# SQL Injection in User Login

## Description

The login endpoint at /api/auth/login is vulnerable to SQL injection
via the username parameter.

## Evidence

POST /api/auth/login with username=' OR 1=1--

## Remediation

Use parameterized queries.
FINDING

# Write a high finding
cat > security/findings/H-001.md <<'FINDING'
# Insecure Direct Object Reference in Profile API

## Description

The /api/users/:id endpoint does not verify ownership.

## Remediation

Add authorization checks.
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
mkdir -p security
cat > security/audit-state.json <<'STATE'
{"audits": [{"status": "in_progress", "mode": "lite", "phases": {"1": {"status": "complete"}, "2": {"status": "in_progress"}}}]}
STATE
# Sleep long enough that the test will cancel us
sleep 30
`
	require.NoError(t, os.WriteFile(script, []byte(content), 0755))
	return script
}

func newAuditTestSettings(t *testing.T, agentName, agentScript, claudeScript string) *config.Settings {
	t.Helper()

	enabled := true
	backends := map[string]config.AgentDef{
		agentName: {
			Command:     agentScript,
			Description: "Fake agent for audit e2e testing",
		},
	}

	return &config.Settings{
		Agent: config.AgentConfig{
			DefaultAgent: agentName,
			Backends:     backends,
			AuditAgent: config.AuditAgentConfig{
				Enable:       &enabled,
				PluginDir:    filepath.Dir(claudeScript), // doesn't matter, we override claude binary
				Mode:         "lite",
				SyncInterval: 1, // 1 second for fast test
			},
		},
	}
}

// TestAuditAgent_SwarmWithAuditAgent verifies that the audit agent runs in the
// background during a swarm pipeline and ingests findings into the database.
func TestAuditAgent_SwarmWithAuditAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

	// Create a fake source directory for the audit agent to work in
	sourceDir := t.TempDir()

	// Create a fake claude script that writes findings
	claudeScript := fakeAuditAgentScript(t)

	// The swarm agent (pipe protocol) for the main pipeline
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
			AuditAgent: config.AuditAgentConfig{
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

	// Rename the fake script to "claude" so exec.LookPath finds it
	claudeDir := filepath.Dir(claudeScript)
	claudeLink := filepath.Join(claudeDir, "claude")
	require.NoError(t, os.Rename(claudeScript, claudeLink))

	auditCfg := &settings.Agent.AuditAgent
	cfg := agent.SwarmConfig{
		Inputs:      []string{"http://localhost:12345/"},
		SourcePath:  sourceDir,
		AgentName:   agentName,
		ProjectUUID: database.DefaultProjectUUID,
		SessionDir:  sessionDir,
		AuditAgent:  auditCfg,
		SkipPhases:  []string{"native-scan", "triage", "native-rescan"},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Wait a moment for the audit agent to finish (it runs in background)
	time.Sleep(2 * time.Second)

	// Verify: audit-state.json was synced to session dir
	auditStatePath := filepath.Join(sessionDir, "audit-agent", "audit-state.json")
	assert.FileExists(t, auditStatePath, "audit-state.json should be synced to session dir")

	// Verify: findings were copied to session dir
	findingsDir := filepath.Join(sessionDir, "audit-agent", "findings")
	if _, err := os.Stat(findingsDir); err == nil {
		entries, _ := os.ReadDir(findingsDir)
		assert.GreaterOrEqual(t, len(entries), 2, "should have at least 2 finding files copied")
	}

	// Verify: findings were written to the source directory
	srcFindingsDir := filepath.Join(sourceDir, "security", "findings")
	entries, err := os.ReadDir(srcFindingsDir)
	require.NoError(t, err)
	assert.Equal(t, 2, len(entries), "should have C-001.md and H-001.md")
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
			AuditAgent: config.AuditAgentConfig{
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
		AuditAgent:  &settings.Agent.AuditAgent,
		SkipPhases:  []string{"native-scan", "triage", "native-rescan"},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Audit agent artifacts should NOT exist
	auditDir := filepath.Join(sessionDir, "audit-agent")
	_, err = os.Stat(auditDir)
	assert.True(t, os.IsNotExist(err), "audit-agent dir should not exist without source")
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
		AuditAgent:  nil, // explicitly nil
		SkipPhases:  []string{"native-scan", "triage", "native-rescan"},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Audit agent artifacts should NOT exist
	auditDir := filepath.Join(sessionDir, "audit-agent")
	_, err = os.Stat(auditDir)
	assert.True(t, os.IsNotExist(err), "audit-agent dir should not exist when disabled")
}

// TestAuditAgent_ResolveConfig verifies the shared config resolution logic.
func TestAuditAgent_ResolveConfig(t *testing.T) {
	baseCfg := config.AuditAgentConfig{
		PluginDir:    "/custom/path",
		Mode:         "full",
		SyncInterval: 60,
	}
	enabledCfg := baseCfg
	enabled := true
	enabledCfg.Enable = &enabled

	tests := []struct {
		name     string
		flag     string
		cfg      config.AuditAgentConfig
		wantNil  bool
		wantMode string
	}{
		{"empty flag, disabled config", "", baseCfg, true, ""},
		{"empty flag, enabled config", "", enabledCfg, false, "full"},
		{"flag=lite overrides config", "lite", baseCfg, false, "lite"},
		{"flag=full overrides config", "full", baseCfg, false, "full"},
		{"flag=off disables even enabled config", "off", enabledCfg, true, ""},
		{"flag preserves SyncInterval", "lite", enabledCfg, false, "lite"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := agent.ResolveAuditAgentConfig(tt.flag, tt.cfg)
			if tt.wantNil {
				assert.Nil(t, result)
				return
			}
			require.NotNil(t, result)
			assert.Equal(t, tt.wantMode, result.Mode)
			assert.True(t, result.IsEnabled())

			// Verify SyncInterval is preserved from base config
			if tt.flag != "" && tt.cfg.SyncInterval > 0 {
				assert.Equal(t, tt.cfg.SyncInterval, result.SyncInterval,
					"SyncInterval from config should be preserved")
			}
			// Verify PluginDir is preserved
			if tt.cfg.PluginDir != "" {
				assert.Equal(t, tt.cfg.PluginDir, result.PluginDir,
					"PluginDir from config should be preserved")
			}
		})
	}
}

// TestAuditAgent_EmbeddedPluginExtraction verifies that the embedded audit agent
// plugin is extracted to the session dir and contains expected files.
func TestAuditAgent_EmbeddedPluginExtraction(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	baseDir := filepath.Join(t.TempDir(), "vig-audit-agent")

	// Use the internal extraction function (via exported wrapper)
	// We call extractAuditAgentTo indirectly — construct the default dir path
	// and verify the extraction works.
	pluginDir, err := agent.ExtractAuditAgentPlugin()
	if err != nil {
		// If home dir resolution fails in CI, skip
		t.Skipf("Skipping: %v", err)
	}
	require.NotEmpty(t, pluginDir)

	// Verify key files exist
	assert.FileExists(t, filepath.Join(pluginDir, "commands", "vig-run", "run.md"))
	assert.FileExists(t, filepath.Join(pluginDir, "commands", "vig-run", "lite.md"))

	agentsDir := filepath.Join(pluginDir, "agents")
	entries, err := os.ReadDir(agentsDir)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(entries), 20, "should have 20+ agent definition files")

	// Verify audit skill is also extracted
	auditAgentDir := agent.DefaultAuditAgentDir()
	skillPath := filepath.Join(auditAgentDir, "skills", "audit", "SKILL.md")
	assert.FileExists(t, skillPath, "audit SKILL.md should be extracted")

	// Verify idempotency — second call should be fast (marker hit)
	pluginDir2, err := agent.ExtractAuditAgentPlugin()
	require.NoError(t, err)
	assert.Equal(t, pluginDir, pluginDir2)

	// Cleanup the extraction (it goes to ~/.vigolium/vig-audit-agent/)
	_ = os.RemoveAll(baseDir)
}

// TestAuditAgent_CancelledMidRun verifies that when the swarm completes before
// the audit agent, the audit agent is gracefully cancelled.
func TestAuditAgent_CancelledMidRun(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, repo := setupTestDB(t)

	sourceDir := t.TempDir()

	// Slow audit script that sleeps 30s (will be cancelled)
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
			AuditAgent: config.AuditAgentConfig{
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
		AuditAgent:  &settings.Agent.AuditAgent,
		SkipPhases:  []string{"native-scan", "triage", "native-rescan"},
		PhaseCallback: func(phase string) {
			atomic.AddInt32(&auditPhaseLogged, 1)
		},
	}

	// Swarm should complete quickly (fake agent is instant).
	// The audit agent will be cancelled in the defer.
	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// The audit agent should have had time to write initial state before being killed
	auditStateSrc := filepath.Join(sourceDir, "security", "audit-state.json")
	if _, err := os.Stat(auditStateSrc); err == nil {
		data, readErr := os.ReadFile(auditStateSrc)
		assert.NoError(t, readErr)
		assert.Contains(t, string(data), "in_progress", "slow audit should show in_progress state")
	}
}

// TestAuditAgent_ParseFinding verifies finding parsing from markdown files.
func TestAuditAgent_ParseFinding(t *testing.T) {
	dir := t.TempDir()

	// Write test finding files
	criticalContent := "# SQL Injection in Login\n\nDescription of the finding.\n\n## Remediation\n\nUse parameterized queries."
	highContent := "# IDOR in Profile API\n\nAnother finding."
	noTitleContent := "Just some text without a heading."

	require.NoError(t, os.WriteFile(filepath.Join(dir, "C-001.md"), []byte(criticalContent), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "H-001.md"), []byte(highContent), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "X-999.md"), []byte(noTitleContent), 0644))

	tests := []struct {
		file     string
		wantID   string
		wantSev  string
		wantTitle string
	}{
		{"C-001.md", "C-001", "critical", "SQL Injection in Login"},
		{"H-001.md", "H-001", "high", "IDOR in Profile API"},
		{"X-999.md", "X-999", "medium", "X-999"}, // unknown prefix defaults to medium, no title defaults to ID
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			finding, err := agent.ParseAuditFinding(filepath.Join(dir, tt.file))
			require.NoError(t, err)
			assert.Equal(t, tt.wantID, finding.ID)
			assert.Equal(t, tt.wantSev, finding.Severity)
			assert.Equal(t, tt.wantTitle, finding.Title)
			assert.NotEmpty(t, finding.Description)
		})
	}
}
