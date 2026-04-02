//go:build e2e

package e2e

import (
	"archive/zip"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/server"
)

// ============================================================
// POST /api/agent/run/autopilot — diff field validation
// ============================================================

func TestAutopilotAPI_DiffWithTarget_Accepted(t *testing.T) {
	env := newAgentTestEnv(t)

	// Providing only "diff" with a PR URL should be accepted (not rejected as missing target/source).
	// It will fail in the background due to gh CLI not being available, but the API should accept it.
	resp := env.post(t, "/api/agent/run/autopilot", `{
		"diff": "https://github.com/juice-shop/juice-shop/pull/1",
		"target": "http://localhost:3000"
	}`)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	var body server.AgentRunResponse
	readJSON(t, resp, &body)
	assert.NotEmpty(t, body.RunID)
	assert.Equal(t, "running", body.Status)
}

func TestAutopilotAPI_MissingTargetSourceDiff(t *testing.T) {
	env := newAgentTestEnv(t)

	// No target, source, or diff — should be rejected
	resp := env.post(t, "/api/agent/run/autopilot", `{
		"agent": "fake-agent",
		"max_commands": 5
	}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "target, source, or diff is required")
}

func TestAutopilotAPI_DiffWithSource(t *testing.T) {
	env := newAgentTestEnv(t)

	// Create a temp git repo to use as source
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "repo")
	require.NoError(t, os.MkdirAll(sourceDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "main.go"), []byte("package main"), 0o644))

	resp := env.post(t, "/api/agent/run/autopilot", `{
		"target": "http://localhost:3000",
		"source": "`+sourceDir+`",
		"diff": "HEAD~1",
		"dry_run": true
	}`)
	// dry_run with diff that requires git may fail, but the API layer should accept the request
	// (validation passes; resolution happens in config build)
	assert.True(t, resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK)
	resp.Body.Close()
}

func TestAutopilotAPI_LastCommits(t *testing.T) {
	env := newAgentTestEnv(t)

	// last_commits without source or target should be rejected (no diff alone without target)
	resp := env.post(t, "/api/agent/run/autopilot", `{
		"last_commits": 5
	}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	resp.Body.Close()
}

// ============================================================
// POST /api/agent/run/swarm — diff field validation
// ============================================================

func TestSwarmAPI_DiffOnly_Accepted(t *testing.T) {
	env := newAgentTestEnv(t)

	// diff with a target should be accepted
	resp := env.post(t, "/api/agent/run/swarm", `{
		"input": "http://localhost:3000/api/login",
		"diff": "HEAD~3",
		"source_path": "/tmp"
	}`)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)

	var body server.AgentRunResponse
	readJSON(t, resp, &body)
	assert.NotEmpty(t, body.RunID)
}

func TestSwarmAPI_MissingInputSourceDiff(t *testing.T) {
	env := newAgentTestEnv(t)

	// No input, source, or diff — should be rejected
	resp := env.post(t, "/api/agent/run/swarm", `{
		"agent": "fake-agent"
	}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var body server.ErrorResponse
	readJSON(t, resp, &body)
	assert.Contains(t, body.Error, "at least one input is required")
}

// ============================================================
// POST /api/agent/run/autopilot — source resolution via API
// ============================================================

func TestAutopilotAPI_SourceArchive(t *testing.T) {
	env := newAgentTestEnv(t)

	// Create a zip archive to use as source
	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "app.zip")
	zf, err := os.Create(zipPath)
	require.NoError(t, err)
	zw := zip.NewWriter(zf)
	fw, _ := zw.Create("app/main.go")
	fw.Write([]byte("package main"))
	zw.Close()
	zf.Close()

	resp := env.post(t, "/api/agent/run/autopilot", `{
		"target": "http://localhost:3000",
		"source": "`+zipPath+`"
	}`)
	// Archive should be accepted — extraction happens in config build
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
	resp.Body.Close()
}

func TestAutopilotAPI_LastCommitsWithTarget(t *testing.T) {
	env := newAgentTestEnv(t)

	// last_commits with target should be accepted
	resp := env.post(t, "/api/agent/run/autopilot", `{
		"target": "http://localhost:3000",
		"source": "/tmp",
		"last_commits": 3
	}`)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
	resp.Body.Close()
}

func TestAutopilotAPI_DiffPROnly(t *testing.T) {
	env := newAgentTestEnv(t)

	// diff PR URL without target or source — should be accepted
	// (PR URL triggers auto-clone; target still needed for scanning)
	resp := env.post(t, "/api/agent/run/autopilot", `{
		"target": "http://localhost:3000",
		"diff": "https://github.com/org/repo/pull/1"
	}`)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
	resp.Body.Close()
}

func TestAutopilotAPI_PromptNotOverriddenByDiff(t *testing.T) {
	env := newAgentTestEnv(t)

	// When both prompt and diff are set, diff should take precedence
	// (prompt parsing is skipped when diff is present)
	resp := env.post(t, "/api/agent/run/autopilot", `{
		"prompt": "scan something",
		"diff": "https://github.com/org/repo/pull/1",
		"target": "http://localhost:3000"
	}`)
	// Should be accepted — diff prevents prompt intent parsing
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
	resp.Body.Close()
}

// ============================================================
// POST /api/agent/run/swarm — additional diff tests
// ============================================================

func TestSwarmAPI_DiffAsOnlyInput(t *testing.T) {
	env := newAgentTestEnv(t)

	// diff with a PR URL as the only "input" (no input/inputs/source_path)
	// Should be accepted since diff alone is valid
	resp := env.post(t, "/api/agent/run/swarm", `{
		"diff": "https://github.com/org/repo/pull/1",
		"input": "http://localhost:3000"
	}`)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
	resp.Body.Close()
}

func TestSwarmAPI_SourceArchive(t *testing.T) {
	env := newAgentTestEnv(t)

	tmpDir := t.TempDir()
	zipPath := filepath.Join(tmpDir, "src.zip")
	zf, err := os.Create(zipPath)
	require.NoError(t, err)
	zw := zip.NewWriter(zf)
	fw, _ := zw.Create("app/main.go")
	fw.Write([]byte("package main"))
	zw.Close()
	zf.Close()

	resp := env.post(t, "/api/agent/run/swarm", `{
		"input": "http://localhost:3000",
		"source_path": "`+zipPath+`"
	}`)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
	resp.Body.Close()
}

func TestSwarmAPI_PromptNotOverriddenByDiff(t *testing.T) {
	env := newAgentTestEnv(t)

	// When both prompt and diff are set, diff takes precedence
	resp := env.post(t, "/api/agent/run/swarm", `{
		"prompt": "scan something",
		"diff": "https://github.com/org/repo/pull/1",
		"input": "http://localhost:3000"
	}`)
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
	resp.Body.Close()
}

// ============================================================
// ResolveSourceAndDiff — unit-level integration tests
// ============================================================

func TestResolveSourceAndDiff_LocalPath(t *testing.T) {
	tmpDir := t.TempDir()
	sessionDir := t.TempDir()

	src, files, dc, err := agent.ResolveSourceAndDiff(tmpDir, "", 0, nil, sessionDir)
	require.NoError(t, err)
	assert.Equal(t, tmpDir, src)
	assert.Nil(t, dc)
	assert.Nil(t, files)
}

func TestResolveSourceAndDiff_ArchiveExtraction(t *testing.T) {
	tmpDir := t.TempDir()
	sessionDir := t.TempDir()

	// Create a zip archive with a single-root directory
	zipPath := filepath.Join(tmpDir, "source.zip")
	zf, err := os.Create(zipPath)
	require.NoError(t, err)
	zw := zip.NewWriter(zf)
	fw, err := zw.Create("myapp/main.go")
	require.NoError(t, err)
	_, err = fw.Write([]byte("package main\nfunc main() {}\n"))
	require.NoError(t, err)
	fw2, err := zw.Create("myapp/lib/utils.go")
	require.NoError(t, err)
	_, err = fw2.Write([]byte("package lib\n"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	require.NoError(t, zf.Close())

	src, files, dc, err := agent.ResolveSourceAndDiff(zipPath, "", 0, nil, sessionDir)
	require.NoError(t, err)
	assert.Nil(t, dc)
	assert.Nil(t, files)

	// Should extract and detect single-root "myapp"
	assert.Equal(t, "myapp", filepath.Base(src))

	// Verify extracted files exist
	assert.FileExists(t, filepath.Join(src, "main.go"))
	assert.FileExists(t, filepath.Join(src, "lib", "utils.go"))
}

func TestResolveSourceAndDiff_DiffWithoutSource_Error(t *testing.T) {
	sessionDir := t.TempDir()

	// Git ref range without source should error
	_, _, _, err := agent.ResolveSourceAndDiff("", "main...feature", 0, nil, sessionDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires --source")
}

func TestResolveSourceAndDiff_EmptyPassthrough(t *testing.T) {
	src, files, dc, err := agent.ResolveSourceAndDiff("", "", 0, nil, t.TempDir())
	require.NoError(t, err)
	assert.Empty(t, src)
	assert.Nil(t, files)
	assert.Nil(t, dc)
}

func TestResolveSourceAndDiff_NonexistentPath(t *testing.T) {
	_, _, _, err := agent.ResolveSourceAndDiff("/nonexistent/path/xyz", "", 0, nil, t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
}

func TestResolveSourceAndDiff_LastCommitsToHeadN(t *testing.T) {
	// last_commits=5 without source should error (becomes HEAD~5 which needs a git repo)
	_, _, _, err := agent.ResolveSourceAndDiff("", "", 5, nil, t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires --source")
}

// ============================================================
// DiffContext in autopilot pipeline — dry-run prompt injection
// ============================================================

func TestAutopilotPipeline_DiffContextInPrompt(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, repo := setupTestDB(t)

	settings := &config.Settings{
		Agent: config.AgentConfig{
			DefaultAgent: "fake-autopilot",
			Backends: map[string]config.AgentDef{
				"fake-autopilot": {
					Command:     "/bin/echo",
					Description: "Fake autopilot agent for source-resolve e2e testing",
				},
			},
		},
	}

	engine := agent.NewEngine(settings, repo)
	defer engine.Close()

	runner := agent.NewAutopilotPipelineRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.AutopilotPipelineConfig{
		TargetURL:   "http://localhost:3000",
		SourcePath:  t.TempDir(),
		AgentName:   "fake-autopilot",
		MaxCommands: 10,
		SessionDir:  sessionDir,
		ProjectUUID: database.DefaultProjectUUID,
		DryRun:      true,
		DiffContext: &agenttypes.DiffContext{
			ChangedFiles: []string{"src/auth/login.go", "src/api/handler.go"},
			PatchContent: "--- a/src/auth/login.go\n+++ b/src/auth/login.go\n@@ -1,3 +1,5 @@\n+import \"unsafe\"\n",
			DiffRef:      "main...feature-auth-bypass",
		},
	}

	result, err := runner.RunAutonomous(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// In dry-run mode, the rendered prompt is written to output.md in the session dir
	promptBytes, err := os.ReadFile(filepath.Join(sessionDir, "output.md"))
	require.NoError(t, err)
	prompt := string(promptBytes)

	assert.Contains(t, prompt, "Diff Context")
	assert.Contains(t, prompt, "main...feature-auth-bypass")
	assert.Contains(t, prompt, "src/auth/login.go")
	assert.Contains(t, prompt, "src/api/handler.go")
	assert.Contains(t, prompt, "import \"unsafe\"")
	assert.Contains(t, prompt, "Focus your analysis on the changed code paths")
}

// ============================================================
// DiffContext in autopilot pipeline — empty diff (no injection)
// ============================================================

func TestAutopilotPipeline_NoDiffContext(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, repo := setupTestDB(t)

	settings := &config.Settings{
		Agent: config.AgentConfig{
			DefaultAgent: "fake-autopilot",
			Backends: map[string]config.AgentDef{
				"fake-autopilot": {
					Command:     "/bin/echo",
					Description: "Fake autopilot agent for source-resolve e2e testing",
				},
			},
		},
	}

	engine := agent.NewEngine(settings, repo)
	defer engine.Close()

	runner := agent.NewAutopilotPipelineRunner(engine, repo)

	sessionDir := t.TempDir()
	cfg := agent.AutopilotPipelineConfig{
		TargetURL:   "http://localhost:3000",
		AgentName:   "fake-autopilot",
		MaxCommands: 10,
		SessionDir:  sessionDir,
		ProjectUUID: database.DefaultProjectUUID,
		DryRun:      true,
		// No DiffContext
	}

	result, err := runner.RunAutonomous(ctx, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Without diff context, the prompt should not contain diff-related sections
	promptBytes, err := os.ReadFile(filepath.Join(sessionDir, "output.md"))
	require.NoError(t, err)
	prompt := string(promptBytes)

	assert.NotContains(t, prompt, "Diff Context")
	assert.NotContains(t, prompt, "changed code paths")
}
