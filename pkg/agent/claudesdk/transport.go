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

	"go.uber.org/zap"
)

// process manages a Claude Code CLI subprocess with JSON-lines I/O.
type process struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	reader *bufio.Reader
	stderr bytes.Buffer

	done     chan struct{} // closed when process exits
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

	// Log as a copy-pasteable command line for debugging
	var cmdLine strings.Builder
	cmdLine.WriteString(cmdPath)
	for _, a := range args {
		cmdLine.WriteByte(' ')
		if strings.ContainsAny(a, " \t\n'\"\\") {
			cmdLine.WriteString("'" + strings.ReplaceAll(a, "'", "'\\''") + "'")
		} else {
			cmdLine.WriteString(a)
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
			return nil, r.err
		}
		return bytes.TrimRight(r.data, "\n"), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.done:
		// Process exited — try to read any remaining data
		select {
		case r := <-ch:
			if r.err != nil {
				return nil, io.EOF
			}
			return bytes.TrimRight(r.data, "\n"), nil
		default:
			return nil, io.EOF
		}
	}
}

// writeLine writes a JSON message followed by a newline to stdin.
func (p *process) writeLine(data []byte) error {
	buf := make([]byte, len(data)+1)
	copy(buf, data)
	buf[len(data)] = '\n'
	_, err := p.stdin.Write(buf)
	return err
}

// close kills the process group and cleans up resources.
func (p *process) close() {
	p.closeOnce.Do(func() {
		_ = p.stdin.Close()

		if p.cmd != nil && p.cmd.Process != nil {
			// Kill the entire process group
			err := syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
			if err != nil && !errors.Is(err, syscall.ESRCH) {
				zap.L().Debug("failed to kill claude process group",
					zap.Int("pid", p.cmd.Process.Pid),
					zap.Error(err))
			}
		}

		// Wait for exit
		if p.cmd != nil {
			select {
			case <-p.done:
			default:
				_ = p.cmd.Wait()
			}
		}
	})
}
