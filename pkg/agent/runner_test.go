package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/internal/config"
)

func TestRunAgent_Echo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	agentDef := config.AgentDef{
		Command: "cat", // cat will echo stdin to stdout
		Args:    nil,
	}

	ctx := context.Background()
	stdout, _, err := RunAgent(ctx, agentDef, "hello world", nil)
	if err != nil {
		t.Fatalf("RunAgent() error = %v", err)
	}

	if strings.TrimSpace(stdout) != "hello world" {
		t.Errorf("stdout = %q, want %q", stdout, "hello world")
	}
}

func TestRunAgent_MissingCommand(t *testing.T) {
	agentDef := config.AgentDef{
		Command: "nonexistent-command-12345",
		Args:    nil,
	}

	ctx := context.Background()
	_, _, err := RunAgent(ctx, agentDef, "test", nil)
	if err == nil {
		t.Error("RunAgent() should return error for missing command")
	}
}

func TestRunAgent_EmptyCommand(t *testing.T) {
	agentDef := config.AgentDef{
		Command: "",
		Args:    nil,
	}

	ctx := context.Background()
	_, _, err := RunAgent(ctx, agentDef, "test", nil)
	if err == nil {
		t.Error("RunAgent() should return error for empty command")
	}
}

func TestRunAgent_WithEnv(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	agentDef := config.AgentDef{
		Command: "env",
		Args:    nil,
		Env: map[string]string{
			"TEST_AGENT_VAR": "test_value",
		},
	}

	ctx := context.Background()
	stdout, _, err := RunAgent(ctx, agentDef, "", nil)
	if err != nil {
		t.Fatalf("RunAgent() error = %v", err)
	}

	if !strings.Contains(stdout, "TEST_AGENT_VAR=test_value") {
		t.Errorf("stdout should contain env var, got %q", stdout)
	}
}

func TestRunAgent_ContextCancel(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	agentDef := config.AgentDef{
		Command: "sleep",
		Args:    []string{"10"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, _, err := RunAgent(ctx, agentDef, "", nil)
	if err == nil {
		t.Error("RunAgent() should return error for cancelled context")
	}
}
