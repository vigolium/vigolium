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

// fakeAuthAgentWithConfigScript returns a script that writes auth-config.yaml
// to the session directory AND outputs a valid swarm plan (so both auth and plan
// phases succeed when using the same agent script).
func fakeAuthAgentWithConfigScript(t *testing.T, sessionDir string) string {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-auth-config-agent.sh")
	content := `#!/bin/sh
cat > /dev/null
# Write auth-config.yaml (simulating agent-browser cookie capture)
cat > "` + sessionDir + `/auth-config.yaml" <<'YAML'
sessions:
  - type: cookie
    headers:
      Cookie: "session_id=abc123def456; csrf_token=xyz789"
YAML
# Also output a valid swarm plan so the plan phase doesn't fail
cat <<'PLAN'
## MODULE_TAGS
discovery, light

## FOCUS_AREAS
- Authenticated endpoint scanning

## NOTES
Auth config captured successfully.
PLAN
`
	require.NoError(t, os.WriteFile(script, []byte(content), 0755))
	return script
}

func newBrowserTestSettings(t *testing.T, agentName, scriptPath string, browserEnabled bool) *config.Settings {
	t.Helper()
	enabled := browserEnabled
	backends := map[string]config.AgentDef{
		agentName: {
			Command:     scriptPath,
			Description: "Fake agent for browser e2e testing",
		},
	}
	return &config.Settings{
		Agent: config.AgentConfig{
			DefaultAgent: agentName,
			Backends:     backends,
			Browser: config.BrowserConfig{
				Enable: &enabled,
			},
		},
	}
}

// TestSwarmAuthPhaseSkippedWhenDisabled verifies that the auth phase is NOT
// invoked when Browser or Auth flags are false.
func TestSwarmAuthPhaseSkippedWhenDisabled(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

	agentName := "fake-no-auth"
	script := fakeSwarmAgentScript(t)
	settings := newBrowserTestSettings(t, agentName, script, false)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()

	// Track phases via callback
	var phases []string
	cfg := agent.SwarmConfig{
		Inputs:      []string{"http://localhost:12345/"},
		AgentName:   agentName,
		ProjectUUID: database.DefaultProjectUUID,
		SessionDir:  sessionDir,
		Browser:     false,
		Auth:        false,
		SkipPhases:  []string{"native-scan", "triage", "native-rescan"},
		PhaseCallback: func(phase string) {
			phases = append(phases, phase)
		},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Auth phase should NOT be in the phases list
	for _, p := range phases {
		if p == agent.SwarmPhaseAuth {
			t.Error("auth phase should not be invoked when Browser=false and Auth=false")
		}
	}

	// Auth prompt/output files should not exist
	_, err = os.Stat(filepath.Join(sessionDir, "auth-prompt.md"))
	assert.True(t, os.IsNotExist(err), "auth-prompt.md should not exist when auth is disabled")
}

// TestSwarmAuthPhaseInvoked verifies that the auth phase IS invoked when
// both Browser and Auth flags are true, and that it produces session artifacts.
func TestSwarmAuthPhaseInvoked(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

	agentName := "fake-auth"
	// Use the standard swarm agent script — it outputs valid plan markdown
	// for both auth and plan phases (pipe protocol runs the script per call).
	script := fakeSwarmAgentScript(t)
	settings := newBrowserTestSettings(t, agentName, script, true)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()

	var authPhaseInvoked int32
	cfg := agent.SwarmConfig{
		Inputs:      []string{"http://localhost:12345/"},
		AgentName:   agentName,
		ProjectUUID: database.DefaultProjectUUID,
		SessionDir:  sessionDir,
		Browser:     true,
		Auth:        true,
		Credentials: "username=admin,password=secret",
		SkipPhases:  []string{"native-scan", "triage", "native-rescan"},
		PhaseCallback: func(phase string) {
			if phase == agent.SwarmPhaseAuth {
				atomic.AddInt32(&authPhaseInvoked, 1)
			}
		},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Auth phase should have been invoked
	assert.Equal(t, int32(1), atomic.LoadInt32(&authPhaseInvoked),
		"auth phase should be invoked exactly once")

	// Auth output file should exist in session dir
	authOutput := filepath.Join(sessionDir, "auth-output.md")
	_, statErr := os.Stat(authOutput)
	assert.NoError(t, statErr, "auth-output.md should exist in session dir")
}

// TestSwarmAuthPhaseWritesConfig verifies that when the auth agent writes
// auth-config.yaml to the session directory, the swarm pipeline detects it.
func TestSwarmAuthPhaseWritesConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

	sessionDir := t.TempDir()

	agentName := "fake-auth-config"
	script := fakeAuthAgentWithConfigScript(t, sessionDir)
	settings := newBrowserTestSettings(t, agentName, script, true)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	cfg := agent.SwarmConfig{
		Inputs:      []string{"http://localhost:12345/"},
		AgentName:   agentName,
		ProjectUUID: database.DefaultProjectUUID,
		SessionDir:  sessionDir,
		Browser:     true,
		Auth:        true,
		SkipPhases:  []string{"native-scan", "triage", "native-rescan"},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// auth-config.yaml should exist (written by the fake agent script)
	authConfigPath := filepath.Join(sessionDir, "auth-config.yaml")
	data, readErr := os.ReadFile(authConfigPath)
	require.NoError(t, readErr, "auth-config.yaml should exist in session dir")
	assert.Contains(t, string(data), "session_id=abc123def456",
		"auth-config.yaml should contain captured cookies")
}

// TestSwarmAuthPhaseNotInvokedWithoutAuthFlag verifies that Browser=true alone
// does NOT trigger the auth phase — the Auth flag is also required.
func TestSwarmAuthPhaseNotInvokedWithoutAuthFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

	agentName := "fake-browser-only"
	script := fakeSwarmAgentScript(t)
	settings := newBrowserTestSettings(t, agentName, script, true)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()

	var authPhaseInvoked int32
	cfg := agent.SwarmConfig{
		Inputs:      []string{"http://localhost:12345/"},
		AgentName:   agentName,
		ProjectUUID: database.DefaultProjectUUID,
		SessionDir:  sessionDir,
		Browser:     true,
		Auth:        false, // Browser on, Auth off
		SkipPhases:  []string{"native-scan", "triage", "native-rescan"},
		PhaseCallback: func(phase string) {
			if phase == agent.SwarmPhaseAuth {
				atomic.AddInt32(&authPhaseInvoked, 1)
			}
		},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Auth phase should NOT be invoked when only Browser is true
	assert.Equal(t, int32(0), atomic.LoadInt32(&authPhaseInvoked),
		"auth phase should not be invoked when Auth=false")
}

// TestSwarmSkillsCopiedWithBrowser verifies that when Browser is enabled,
// the agent-browser skill is copied to the session directory.
func TestSwarmSkillsCopiedWithBrowser(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

	agentName := "fake-browser-skills"
	script := fakeSwarmAgentScript(t)
	settings := newBrowserTestSettings(t, agentName, script, true)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs:      []string{"http://localhost:12345/"},
		AgentName:   agentName,
		ProjectUUID: database.DefaultProjectUUID,
		SessionDir:  sessionDir,
		Browser:     true,
		SkipPhases:  []string{"native-scan", "triage", "native-rescan"},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Both skills should be copied
	scannerSkill := filepath.Join(sessionDir, "skills", "vigolium-scanner", "SKILL.md")
	browserSkill := filepath.Join(sessionDir, "skills", "agent-browser", "SKILL.md")

	assert.FileExists(t, scannerSkill, "vigolium-scanner skill should be copied")
	assert.FileExists(t, browserSkill, "agent-browser skill should be copied when Browser=true")
}

// TestSwarmSkillsNoBrowserSkillWhenDisabled verifies that when Browser is disabled,
// only the vigolium-scanner skill is copied (no agent-browser).
func TestSwarmSkillsNoBrowserSkillWhenDisabled(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	_, repo := setupTestDB(t)

	agentName := "fake-no-browser-skills"
	script := fakeSwarmAgentScript(t)
	settings := newBrowserTestSettings(t, agentName, script, false)

	engine := agent.NewEngine(settings, repo)
	engine.EnsureWarmSessions()
	defer engine.Close()

	swarmRunner := agent.NewSwarmRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.SwarmConfig{
		Inputs:      []string{"http://localhost:12345/"},
		AgentName:   agentName,
		ProjectUUID: database.DefaultProjectUUID,
		SessionDir:  sessionDir,
		Browser:     false,
		SkipPhases:  []string{"native-scan", "triage", "native-rescan"},
	}

	result, err := swarmRunner.Run(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// vigolium-scanner should be copied
	scannerSkill := filepath.Join(sessionDir, "skills", "vigolium-scanner", "SKILL.md")
	assert.FileExists(t, scannerSkill, "vigolium-scanner skill should always be copied")

	// agent-browser should NOT be copied
	browserSkill := filepath.Join(sessionDir, "skills", "agent-browser", "SKILL.md")
	_, err = os.Stat(browserSkill)
	assert.True(t, os.IsNotExist(err), "agent-browser skill should NOT be copied when Browser=false")
}
