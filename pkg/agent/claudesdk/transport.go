package claudesdk

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// process manages a Claude Code CLI subprocess with JSON-lines I/O.
type process struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	reader *bufio.Reader
	stderr bytes.Buffer

	done      chan struct{} // closed when process exits
	closeOnce sync.Once
}

// startProcess spawns the claude CLI with the given options.
func startProcess(ctx context.Context, opts *Options) (*process, error) {
	executable := opts.Executable
	if executable == "" {
		executable = "claude"
	}

	cmdPath, err := exec.LookPath(executable)
	if err != nil {
		return nil, fmt.Errorf("claude executable %q not found in PATH: %w", executable, err)
	}

	args := opts.buildArgs()

	// Log a readable command line for debugging (truncate long args)
	var cmdLine strings.Builder
	cmdLine.WriteString(cmdPath)
	for _, a := range args {
		cmdLine.WriteByte(' ')
		display := a
		if len(a) > 200 {
			display = a[:200] + fmt.Sprintf("... [%d bytes truncated]", len(a)-200)
		}
		if strings.ContainsAny(display, " \t\n'\"\\") {
			cmdLine.WriteString("'" + strings.ReplaceAll(display, "'", "'\\''") + "'")
		} else {
			cmdLine.WriteString(display)
		}
	}
	zap.L().Debug("starting claude SDK subprocess",
		zap.String("command", cmdLine.String()),
		zap.String("cwd", opts.Cwd))

	cmd := exec.CommandContext(ctx, cmdPath, args...)

	// Create a new process group so we can kill the entire tree on close.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if opts.Cwd != "" {
		cmd.Dir = opts.Cwd
	}

	// Environment variables
	if len(opts.Env) > 0 {
		cmd.Env = cmd.Environ()
		for k, v := range opts.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start claude process: %w", err)
	}

	p := &process{
		cmd:    cmd,
		stdin:  stdinPipe,
		reader: bufio.NewReaderSize(stdoutPipe, 1024*1024), // 1MB buffer
		done:   make(chan struct{}),
	}

	// Drain stderr in background
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := scanner.Text()
			p.stderr.WriteString(line)
			p.stderr.WriteByte('\n')
			zap.L().Debug("claude stderr", zap.String("line", line))
		}
	}()

	// Wait for process exit in background
	go func() {
		_ = cmd.Wait()
		close(p.done)
	}()

	return p, nil
}

// readLine reads one newline-delimited JSON message from stdout.
// Returns io.EOF when the process has closed stdout.
func (p *process) readLine(ctx context.Context) ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)

	go func() {
		line, err := p.reader.ReadBytes('\n')
		ch <- result{line, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			if isProcessPipeClosedError(r.err) {
				return nil, io.EOF
			}
			return nil, r.err
		}
		return bytes.TrimRight(r.data, "\n"), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.done:
		// Process exited — still wait for the in-flight read to drain any
		// buffered stdout before reporting EOF.
		r := <-ch
		if r.err != nil {
			if isProcessPipeClosedError(r.err) {
				return nil, io.EOF
			}
			return nil, io.EOF
		}
		return bytes.TrimRight(r.data, "\n"), nil
	}
}

func isProcessPipeClosedError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "file already closed") || strings.Contains(msg, "closed pipe")
}

// writeLine writes a JSON message followed by a newline to stdin.
func (p *process) writeLine(data []byte) error {
	buf := make([]byte, len(data)+1)
	copy(buf, data)
	buf[len(data)] = '\n'
	_, err := p.stdin.Write(buf)
	return err
}

// close gracefully shuts down the process group: SIGTERM first, then SIGKILL after timeout.
func (p *process) close() {
	p.closeOnce.Do(func() {
		_ = p.stdin.Close()

		if p.cmd != nil && p.cmd.Process != nil {
			pid := p.cmd.Process.Pid

			// Graceful: send SIGTERM to entire process group first.
			if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
				zap.L().Debug("failed to SIGTERM claude process group",
					zap.Int("pid", pid), zap.Error(err))
			}

			// Wait up to 5s for graceful exit, then escalate to SIGKILL.
			select {
			case <-p.done:
				return
			case <-time.After(5 * time.Second):
				zap.L().Debug("SIGTERM timeout, sending SIGKILL to claude process group",
					zap.Int("pid", pid))
				_ = syscall.Kill(-pid, syscall.SIGKILL)
			}
		}

		// Final wait with timeout to avoid hanging on stuck I/O.
		if p.cmd != nil {
			select {
			case <-p.done:
			case <-time.After(3 * time.Second):
				if p.cmd.Process != nil {
					_ = p.cmd.Process.Kill()
				}
			}
		}
	})
}
