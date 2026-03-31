package backend

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/vigolium/vigolium/internal/config"
	"go.uber.org/zap"
)

// RunAgent executes an AI agent with the given prompt piped to stdin.
// When streamWriter is non-nil, stdout is tee'd to it in real-time.
// Returns the agent's stdout, stderr, and any execution error.
func RunAgent(ctx context.Context, agentDef config.AgentDef, prompt string, streamWriter io.Writer) (stdout string, stderr string, err error) {
	if agentDef.Command == "" {
		return "", "", fmt.Errorf("agent command is empty")
	}

	// Look up the command in PATH
	cmdPath, err := exec.LookPath(agentDef.Command)
	if err != nil {
		return "", "", fmt.Errorf("agent command %q not found in PATH: %w", agentDef.Command, err)
	}

	cmdLine := cmdPath + " " + strings.Join(agentDef.Args, " ")
	zap.L().Debug("starting agent subprocess (pipe mode)",
		zap.String("cmd", cmdLine),
		zap.Int("promptLength", len(prompt)))

	cmd := exec.CommandContext(ctx, cmdPath, agentDef.Args...)

	// Set up environment variables
	if len(agentDef.Env) > 0 {
		cmd.Env = cmd.Environ()
		for k, v := range agentDef.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}

	// Pipe prompt to stdin
	cmd.Stdin = strings.NewReader(prompt)

	var stdoutBuf, stderrBuf bytes.Buffer
	if streamWriter != nil {
		cmd.Stdout = io.MultiWriter(&stdoutBuf, streamWriter)
	} else {
		cmd.Stdout = &stdoutBuf
	}
	cmd.Stderr = &stderrBuf

	if err := cmd.Run(); err != nil {
		zap.L().Debug("agent subprocess failed (pipe mode)",
			zap.Error(err),
			zap.Int("stdoutBytes", stdoutBuf.Len()),
			zap.Int("stderrBytes", stderrBuf.Len()))
		return stdoutBuf.String(), stderrBuf.String(), fmt.Errorf("agent command failed: %w", err)
	}

	zap.L().Debug("agent subprocess completed (pipe mode)",
		zap.Int("stdoutBytes", stdoutBuf.Len()),
		zap.Int("stderrBytes", stderrBuf.Len()))

	return stdoutBuf.String(), stderrBuf.String(), nil
}
