package toolexec

import (
	"bytes"
	"context"
	"os/exec"

	"go.uber.org/zap"
)

// Run executes a command with the given context and returns structured output.
//
// It tolerates non-zero exit codes when stdout has data — many security tools
// (e.g., kingfisher) exit 1 when they find matches, which is not an error.
//
// The full command string is logged at debug level.
func Run(ctx context.Context, name string, args ...string) (*ExecResult, error) {
	cmd := exec.CommandContext(ctx, name, args...)

	zap.L().Debug("toolexec command", zap.String("cmd", cmd.String()))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	result := &ExecResult{
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		ExitCode: -1,
	}
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}

	// Tolerate non-zero exit when stdout has data.
	if err != nil && len(result.Stdout) == 0 {
		return result, err
	}

	return result, nil
}
