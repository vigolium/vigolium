package agent

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
)

const (
	defaultMaxCalls       = 100
	defaultCommandTimeout = 5 * time.Minute
)

// shellMetachars contains characters that could enable shell injection.
const shellMetachars = ";|&`$(){}!><\n"

// terminalSession holds the state for a single terminal command execution.
type terminalSession struct {
	id       string
	cmd      *exec.Cmd
	mu       sync.Mutex
	output   bytes.Buffer // guarded by mu
	done     chan struct{}
	exitCode int
}

// syncWriter is a mutex-protected writer for safe concurrent stdout/stderr capture.
type syncWriter struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

// terminalManager manages terminal sessions for autopilot mode.
// It enforces command allowlisting, call limits, and per-command timeouts.
type terminalManager struct {
	mu             sync.Mutex
	sessions       map[string]*terminalSession
	cwd            string
	env            []string
	maxCalls       int
	callCount      atomic.Int32
	commandTimeout time.Duration
	allowedCmds    []string
	blockedSubcmds [][]string // each entry is a sequence of subcommand words to match
	nextID         atomic.Int64
}

// newTerminalManager creates a terminal manager with the given working directory and call limit.
// Extra commands are appended to the default allowlist (which always includes "vigolium").
func newTerminalManager(cwd string, maxCalls int, extraCmds ...string) *terminalManager {
	if maxCalls <= 0 {
		maxCalls = defaultMaxCalls
	}
	allowed := []string{"vigolium"}
	allowed = append(allowed, extraCmds...)
	return &terminalManager{
		sessions:       make(map[string]*terminalSession),
		cwd:            cwd,
		maxCalls:       maxCalls,
		commandTimeout: defaultCommandTimeout,
		allowedCmds:    allowed,
		blockedSubcmds: [][]string{
			{"db", "clean"},
			{"db", "seed"},
			{"db", "drop"},
		},
	}
}

// withTerminal enables terminal execution. Extra commands are appended to the
// default allowlist (which always includes "vigolium").
func withTerminal(cwd string, maxCalls int, extraCmds ...string) acpClientOption {
	return func(c *acpClient) {
		c.termMgr = newTerminalManager(cwd, maxCalls, extraCmds...)
	}
}

// validateCommand checks that a command is allowed.
func (tm *terminalManager) validateCommand(command string) error {
	// Reject shell metacharacters to prevent injection (command is passed to exec directly, not sh -c)
	if strings.ContainsAny(command, shellMetachars) {
		return fmt.Errorf("command contains disallowed shell metacharacters")
	}

	parts := strings.Fields(command)
	if len(parts) == 0 {
		return fmt.Errorf("empty command")
	}

	// Check command is in allowlist
	cmd := filepath.Base(parts[0])
	allowed := false
	for _, a := range tm.allowedCmds {
		if cmd == a {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("command %q not allowed; only vigolium commands are permitted", cmd)
	}

	// Block destructive subcommands using exact word sequence matching
	if len(parts) > 1 {
		for _, blocked := range tm.blockedSubcmds {
			if matchesSubcommand(parts[1:], blocked) {
				return fmt.Errorf("destructive command %q not allowed in autopilot mode", strings.Join(blocked, " "))
			}
		}
	}

	// Check call limit (only increment after all validation passes)
	count := int(tm.callCount.Add(1))
	if count > tm.maxCalls {
		return fmt.Errorf("maximum command limit (%d) exceeded", tm.maxCalls)
	}

	return nil
}

// matchesSubcommand checks if args starts with the given subcommand word sequence.
func matchesSubcommand(args []string, subcmd []string) bool {
	if len(args) < len(subcmd) {
		return false
	}
	for i, word := range subcmd {
		if args[i] != word {
			return false
		}
	}
	return true
}

// createSession creates and starts a new terminal session for the given command.
func (tm *terminalManager) createSession(ctx context.Context, command string) (*terminalSession, error) {
	id := fmt.Sprintf("term-%d", tm.nextID.Add(1))

	// Apply per-command timeout
	cmdCtx, cancel := context.WithTimeout(ctx, tm.commandTimeout)

	// Parse command into args and execute directly (no shell) to prevent injection
	parts := strings.Fields(command)
	cmd := exec.CommandContext(cmdCtx, parts[0], parts[1:]...)
	cmd.Dir = tm.cwd
	// Set process group so we can kill terminal child processes on cleanup
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if len(tm.env) > 0 {
		cmd.Env = append(cmd.Environ(), tm.env...)
	}

	sess := &terminalSession{
		id:   id,
		cmd:  cmd,
		done: make(chan struct{}),
	}

	// Use a synchronized writer for safe concurrent stdout/stderr capture
	sw := &syncWriter{mu: &sess.mu, buf: &sess.output}
	cmd.Stdout = sw
	cmd.Stderr = sw

	zap.L().Debug("terminal: starting command",
		zap.String("id", id),
		zap.String("command", command),
		zap.String("cwd", tm.cwd))

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to start command: %w", err)
	}

	// Wait for completion in background
	go func() {
		defer cancel()
		err := cmd.Wait()
		sess.mu.Lock()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				sess.exitCode = exitErr.ExitCode()
			} else {
				sess.exitCode = 1
			}
		}
		sess.mu.Unlock()
		close(sess.done)

		zap.L().Debug("terminal: command completed",
			zap.String("id", id),
			zap.Int("exitCode", sess.exitCode))
	}()

	tm.mu.Lock()
	tm.sessions[id] = sess
	tm.mu.Unlock()

	return sess, nil
}

// getOutput returns the current output of a terminal session.
func (tm *terminalManager) getOutput(id string) (string, bool) {
	tm.mu.Lock()
	sess, ok := tm.sessions[id]
	tm.mu.Unlock()
	if !ok {
		return "", false
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()
	output := sess.output.String()

	// Truncate very large outputs to prevent context overflow
	const maxOutput = 256 * 1024 // 256KB
	truncated := false
	if len(output) > maxOutput {
		output = "[output truncated — showing last 256KB]\n" + output[len(output)-maxOutput:]
		truncated = true
	}
	return output, truncated
}

// waitForExit blocks until the terminal session completes and returns the exit code.
func (tm *terminalManager) waitForExit(ctx context.Context, id string) int {
	tm.mu.Lock()
	sess, ok := tm.sessions[id]
	tm.mu.Unlock()
	if !ok {
		return -1
	}

	select {
	case <-sess.done:
		sess.mu.Lock()
		code := sess.exitCode
		sess.mu.Unlock()
		return code
	case <-ctx.Done():
		return -1
	}
}

// killSession terminates a running terminal session.
func (tm *terminalManager) killSession(id string) {
	tm.mu.Lock()
	sess, ok := tm.sessions[id]
	tm.mu.Unlock()
	if !ok {
		return
	}

	if sess.cmd != nil && sess.cmd.Process != nil {
		killProcessGroup(sess.cmd.Process.Pid, "terminal-session")
	}
}

// releaseSession removes a terminal session from the manager.
func (tm *terminalManager) releaseSession(id string) {
	tm.mu.Lock()
	delete(tm.sessions, id)
	tm.mu.Unlock()
}

// killAll terminates and removes all active terminal sessions.
// Called during cleanup to prevent orphaned processes.
func (tm *terminalManager) killAll() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	for id, sess := range tm.sessions {
		if sess.cmd != nil && sess.cmd.Process != nil {
			killProcessGroup(sess.cmd.Process.Pid, "terminal-killall-"+id)
		}
		delete(tm.sessions, id)
	}
}
