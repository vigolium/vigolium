package agent

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"go.uber.org/zap"
)

const pingPrompt = "Respond with exactly one word: pong"

// Ping sends a minimal test prompt to an agent backend and verifies it responds.
// Returns the trimmed response text on success, or an error if the agent fails to respond.
// The context should carry a timeout (e.g. 30s) to avoid hanging on unresponsive backends.
//
// cmdPath is the already-resolved absolute path to the agent binary (from exec.LookPath).
func Ping(ctx context.Context, agentDef config.AgentDef, cmdPath string) (string, error) {
	switch agentDef.EffectiveProtocol() {
	case "sdk":
		// Claude Code CLI supports lightweight single-shot print mode.
		return pingCLIPrint(ctx, cmdPath, agentDef.Env)
	default:
		// All other protocols (acp, codex-sdk, opencode-sdk, pipe) — use stdin/stdout.
		return pingPipe(ctx, agentDef)
	}
}

// pingCLIPrint runs `claude -p "<prompt>" --output-format text --max-turns 1 --bare`
// using the Claude Code CLI's single-shot print mode.
func pingCLIPrint(ctx context.Context, cmdPath string, env map[string]string) (string, error) {
	args := []string{
		"-p", pingPrompt,
		"--output-format", "text",
		"--max-turns", "1",
		"--no-session-persistence",
		"--bare",
	}

	zap.L().Debug("pinging agent via print mode",
		zap.String("command", cmdPath),
		zap.Strings("args", args))

	cmd := exec.CommandContext(ctx, cmdPath, args...)

	// Close stdin immediately — claude CLI reads stdin by default and will
	// hang or warn ("no stdin data received") if it remains open.
	cmd.Stdin = strings.NewReader("")

	if len(env) > 0 {
		cmd.Env = cmd.Environ()
		for k, v := range env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// claude CLI prints some errors (auth, config) to stdout rather than stderr
		return "", wrapPingError(err, stderr.String(), stdout.String())
	}

	response := strings.TrimSpace(stdout.String())
	if response == "" {
		return "", fmt.Errorf("agent returned empty response")
	}

	return response, nil
}

// pingPipe runs the agent command with the prompt piped to stdin and reads stdout.
func pingPipe(ctx context.Context, agentDef config.AgentDef) (string, error) {
	stdout, stderr, err := RunAgent(ctx, agentDef, pingPrompt, nil)
	if err != nil {
		return "", wrapPingError(err, stderr, stdout)
	}

	response := strings.TrimSpace(stdout)
	if response == "" {
		return "", fmt.Errorf("agent returned empty response")
	}

	return response, nil
}

// wrapPingError builds an informative error from the exit error plus any output.
// Checks stderr first, then stdout (some CLIs print errors to stdout).
func wrapPingError(err error, stderr, stdout string) error {
	if s := strings.TrimSpace(stderr); s != "" {
		return fmt.Errorf("agent ping failed: %w — %s", err, s)
	}
	if s := strings.TrimSpace(stdout); s != "" {
		return fmt.Errorf("agent ping failed: %w — %s", err, s)
	}
	return fmt.Errorf("agent ping failed: %w", err)
}
