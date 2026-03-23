package codexsdk

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

// process manages a codex app-server subprocess with JSONL I/O over stdio.
type process struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	reader *bufio.Reader
	stderr bytes.Buffer

	done      chan struct{} // closed when process exits
	closeOnce sync.Once
}

// startProcess spawns the codex app-server with the given options.
func startProcess(ctx context.Context, opts *Options) (*process, error) {
	executable := opts.Executable
	if executable == "" {
		executable = "codex"
	}

	cmdPath, err := exec.LookPath(executable)
	if err != nil {
		return nil, fmt.Errorf("codex executable %q not found in PATH: %w", executable, err)
	}

	args := opts.buildArgs()

	// Log a readable command line for debugging
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
	zap.L().Debug("starting codex app-server subprocess",
		zap.String("command", cmdLine.String()),
		zap.String("cwd", opts.Cwd))

	cmd := exec.CommandContext(ctx, cmdPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if opts.Cwd != "" {
		cmd.Dir = opts.Cwd
	}

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
		return nil, fmt.Errorf("failed to start codex app-server: %w", err)
	}

	p := &process{
		cmd:    cmd,
		stdin:  stdinPipe,
		reader: bufio.NewReaderSize(stdoutPipe, 1024*1024),
		done:   make(chan struct{}),
	}

	// Drain stderr in background
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := scanner.Text()
			p.stderr.WriteString(line)
			p.stderr.WriteByte('\n')
			zap.L().Debug("codex stderr", zap.String("line", line))
		}
	}()

	// Wait for process exit in background
	go func() {
		_ = cmd.Wait()
		close(p.done)
	}()

	return p, nil
}

// readLine reads one JSONL message from stdout.
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

// writeLine writes a JSONL message to stdin.
func (p *process) writeLine(data []byte) error {
	buf := make([]byte, len(data)+1)
	copy(buf, data)
	buf[len(data)] = '\n'
	_, err := p.stdin.Write(buf)
	return err
}

// close kills the process group and cleans up.
func (p *process) close() {
	p.closeOnce.Do(func() {
		_ = p.stdin.Close()

		if p.cmd != nil && p.cmd.Process != nil {
			err := syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
			if err != nil && !errors.Is(err, syscall.ESRCH) {
				zap.L().Debug("failed to kill codex process group",
					zap.Int("pid", p.cmd.Process.Pid),
					zap.Error(err))
			}
		}

		// Wait for the process to exit with a timeout.
		// cmd.Wait blocks until all I/O is drained, which can hang
		// if reader goroutines are stuck. Use the done channel with a deadline.
		if p.cmd != nil {
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case <-p.done:
			case <-timer.C:
				// Force kill individual process as a last resort
				if p.cmd.Process != nil {
					_ = p.cmd.Process.Kill()
				}
			}
		}
	})
}

// alive returns true if the process is still running.
func (p *process) alive() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}
