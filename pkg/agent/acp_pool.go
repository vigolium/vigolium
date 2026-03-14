package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	acp "github.com/coder/acp-go-sdk"
	"github.com/vigolium/vigolium/internal/config"
	"go.uber.org/zap"
)

// stderrRingBuffer keeps the last N lines of stderr for diagnostics.
type stderrRingBuffer struct {
	mu    sync.Mutex
	lines []string
	max   int
}

func (b *stderrRingBuffer) add(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.max == 0 {
		b.max = 20
	}
	b.lines = append(b.lines, line)
	if len(b.lines) > b.max {
		// Copy to a new slice to allow GC of the old backing array.
		trimmed := make([]string, b.max)
		copy(trimmed, b.lines[len(b.lines)-b.max:])
		b.lines = trimmed
	}
}

func (b *stderrRingBuffer) last(n int) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n <= 0 || len(b.lines) == 0 {
		return nil
	}
	start := len(b.lines) - n
	if start < 0 {
		start = 0
	}
	out := make([]string, len(b.lines)-start)
	copy(out, b.lines[start:])
	return out
}

// killProcessGroup sends SIGKILL to a process group and logs errors instead of
// silently discarding them. ESRCH (no such process) is expected when the process
// has already exited and is logged at Debug level; other errors are logged as Warn.
func killProcessGroup(pid int, label string) {
	err := syscall.Kill(-pid, syscall.SIGKILL)
	if err == nil {
		return
	}
	if errors.Is(err, syscall.ESRCH) {
		zap.L().Debug("process group already exited",
			zap.String("label", label),
			zap.Int("pid", pid))
		return
	}
	zap.L().Warn("failed to kill process group",
		zap.String("label", label),
		zap.Int("pid", pid),
		zap.Error(err))
}

// acpSession holds a warm ACP subprocess and its connection state.
type acpSession struct {
	agentName string
	cmd       *exec.Cmd
	conn      *acp.ClientSideConnection
	sessionID acp.SessionId
	client    *acpClient
	cwd       string

	stdinPipe    io.WriteCloser
	stderrWriter *io.PipeWriter
	stderrReader *io.PipeReader
	stderrWg     sync.WaitGroup
	stderrBuf    stderrRingBuffer // last N stderr lines for diagnostics

	inUse       bool
	lastUsed    time.Time
	weight      int
	dead        bool
	authMethods []acp.AuthMethod // auth methods advertised by the agent
}

// kill terminates the subprocess and marks the session as dead.
func (s *acpSession) kill() {
	if s.dead {
		return
	}
	s.dead = true
	// Close stdin to signal EOF
	_ = s.stdinPipe.Close()
	// Close stderr pipe writer so the drain goroutine finishes
	_ = s.stderrWriter.Close()
	s.stderrWg.Wait()
	// Kill the entire process group
	if s.cmd.Process != nil {
		killProcessGroup(s.cmd.Process.Pid, "warm-session-"+s.agentName)
	}
	_ = s.cmd.Wait()
	zap.L().Debug("ACP warm session killed", zap.String("agent", s.agentName))
}

// alive checks if the subprocess is still running.
func (s *acpSession) alive() bool {
	if s.dead {
		return false
	}
	if s.cmd == nil || s.cmd.Process == nil {
		return false
	}
	// Check if the process has exited
	if s.cmd.ProcessState != nil {
		s.dead = true
		return false
	}
	return true
}

// ACPPool manages warm ACP subprocess sessions for reuse across prompts.
type ACPPool struct {
	mu          sync.Mutex
	sessions    map[string]*acpSession // keyed by agent name
	cfg         config.WarmSessionConfig
	agents      map[string]config.AgentDef
	reaperStop  chan struct{}
	reaperDone  chan struct{}
	closed      bool
}

// NewACPPool creates a new session pool and starts the idle reaper.
func NewACPPool(cfg config.WarmSessionConfig, agents map[string]config.AgentDef) *ACPPool {
	p := &ACPPool{
		sessions:   make(map[string]*acpSession),
		cfg:        cfg,
		agents:     agents,
		reaperStop: make(chan struct{}),
		reaperDone: make(chan struct{}),
	}
	runtime.SetFinalizer(p, func(pool *ACPPool) {
		if !pool.closed {
			zap.L().Warn("ACPPool garbage-collected without Close() — reaper goroutine was leaked")
		}
	})
	go p.reaper()
	return p
}

// Prompt sends a prompt to the named agent, reusing a warm session if available.
// When the pooled session is already in use (concurrent calls for the same agent),
// it falls back to a one-shot ACP session to avoid blocking or corrupting output.
// When a withSessionKey option is provided, the pool uses that key (instead of agentName)
// to look up and store sessions. This prevents context accumulation across different
// phases that share the same agent backend (e.g., source-analysis vs sast-review both
// using "claude"). The agentName is still used for agent config lookup when spawning.
func (p *ACPPool) Prompt(ctx context.Context, agentName string, prompt string, cwd string, opts ...acpClientOption) (result acpResult, err error) {
	// Normalize cwd to absolute path for consistent session matching
	if !filepath.IsAbs(cwd) {
		if abs, err := filepath.Abs(cwd); err == nil {
			cwd = abs
		}
	}

	// Apply all options once to extract session key, weight, and stream writer.
	clientOpts := newACPClient(opts...)
	poolKey := agentName
	if clientOpts.sessionKey != "" {
		poolKey = clientOpts.sessionKey
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return acpResult{}, fmt.Errorf("pool is closed")
	}

	sess, exists := p.sessions[poolKey]
	if exists {
		if !sess.alive() || sess.cwd != cwd {
			zap.L().Debug("ACP warm session stale, replacing",
				zap.String("agent", agentName),
				zap.String("poolKey", poolKey),
				zap.Bool("alive", sess.alive()),
				zap.String("oldCwd", sess.cwd),
				zap.String("newCwd", cwd))
			sess.kill()
			delete(p.sessions, poolKey)
			exists = false
		} else if sess.inUse {
			// Session is busy — fall back to a one-shot ACP session
			p.mu.Unlock()
			agentDef, ok := p.agents[agentName]
			if !ok {
				return acpResult{}, fmt.Errorf("agent %q not found in pool configuration", agentName)
			}
			zap.L().Debug("ACP warm session busy, falling back to one-shot session",
				zap.String("agent", agentName),
				zap.String("poolKey", poolKey))
			return RunAgenticACP(ctx, agentDef, prompt, opts...)
		}
	}

	if !exists {
		// Check capacity — evict LRU if at max
		if len(p.sessions) >= p.cfg.EffectiveMaxSessions() {
			p.evictLRU()
		}
	}
	p.mu.Unlock()

	if !exists {
		// Spawn new session (outside lock to avoid blocking).
		// Use agentName for config lookup, poolKey for map storage.
		newSess, spawnErr := p.spawnSession(ctx, agentName, cwd, opts...)
		if spawnErr != nil {
			return acpResult{}, spawnErr
		}
		p.mu.Lock()
		// Another goroutine may have inserted a session while we were spawning.
		if existing, raced := p.sessions[poolKey]; raced && existing.alive() {
			if existing.inUse {
				// The existing session is already in use by another goroutine.
				// Keep our freshly spawned session as a one-shot: use it for this
				// prompt and kill it afterwards, without storing it in the pool.
				p.mu.Unlock()
				zap.L().Debug("ACP warm session race: existing session busy, using spawned session as one-shot",
					zap.String("agent", agentName),
					zap.String("poolKey", poolKey))
				return p.promptOneShot(ctx, agentName, newSess, prompt, opts...)
			}
			sess = existing
			p.mu.Unlock()
			// Kill the duplicate outside the lock (kill() is safe to call independently)
			newSess.kill()
		} else {
			p.sessions[poolKey] = newSess
			sess = newSess
			p.mu.Unlock()
		}

		// Apply session weight from options
		if clientOpts.sessionWeight > 0 {
			sess.weight = clientOpts.sessionWeight
		}
	}

	// Mark in-use
	p.mu.Lock()
	sess.inUse = true
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		sess.inUse = false
		sess.lastUsed = time.Now()
		p.mu.Unlock()
	}()

	// Reset output and update stream writer
	sess.client.resetOutput()
	sess.client.setStreamWriter(clientOpts.streamWriter)

	zap.L().Debug("sending ACP prompt via warm session",
		zap.String("agent", agentName),
		zap.Int("promptLength", len(prompt)))

	sessionID := string(sess.sessionID)

	// Send prompt on the existing connection
	promptResp, promptErr := sess.conn.Prompt(ctx, acp.PromptRequest{
		SessionId: sess.sessionID,
		Prompt:    []acp.ContentBlock{acp.TextBlock(prompt)},
	})
	if promptErr != nil {
		// Session is likely dead
		p.mu.Lock()
		sess.dead = true
		delete(p.sessions, poolKey)
		p.mu.Unlock()
		sess.kill()

		r := acpResult{Stdout: sess.client.collectedOutput(), SessionID: sessionID}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return r, fmt.Errorf("ACP prompt timed out: %w", ctx.Err())
		}
		return r, fmt.Errorf("ACP prompt failed on warm session: %w", promptErr)
	}

	output := sess.client.collectedOutput()

	zap.L().Debug("ACP warm session prompt completed",
		zap.String("agent", agentName),
		zap.String("stopReason", string(promptResp.StopReason)),
		zap.Int("outputBytes", len(output)))

	if len(output) == 0 && promptResp.StopReason == "end_turn" {
		// Build a helpful error message based on the agent's auth methods
		var authHint string
		if len(sess.authMethods) > 0 {
			hints := make([]string, 0, len(sess.authMethods))
			for _, am := range sess.authMethods {
				desc := am.Name
				if am.Description != nil && *am.Description != "" {
					desc = *am.Description
				}
				hints = append(hints, desc)
			}
			authHint = fmt.Sprintf("; the agent advertises authentication methods — ensure you are authenticated: %s", strings.Join(hints, "; "))
		}

		// Capture recent stderr for diagnostics
		recentStderr := sess.stderrBuf.last(10)
		stderrSummary := ""
		if len(recentStderr) > 0 {
			stderrSummary = strings.Join(recentStderr, "\n")
		}

		warnFields := []zap.Field{
			zap.String("agent", agentName),
			zap.String("cwd", sess.cwd),
			zap.Int("promptLength", len(prompt)),
		}
		if stderrSummary != "" {
			warnFields = append(warnFields, zap.String("recent_stderr", stderrSummary))
		}
		zap.L().Warn("ACP agent returned empty output with zero tokens — the agent's LLM backend may not be processing prompts", warnFields...)

		return acpResult{
			Stdout:    output,
			Stderr:    stderrSummary,
			SessionID: sessionID,
		}, fmt.Errorf("agent %q returned empty output (0 tokens) — the LLM backend did not process the prompt%s", agentName, authHint)
	}

	return acpResult{
		Stdout:    output,
		SessionID: sessionID,
	}, nil
}

// promptOneShot uses a freshly spawned session for a single prompt and then kills it.
// This is used when the pooled session for an agent is busy (concurrent calls).
func (p *ACPPool) promptOneShot(ctx context.Context, agentName string, sess *acpSession, prompt string, opts ...acpClientOption) (acpResult, error) {
	defer sess.kill()

	// Update stream writer from options
	clientOpts := newACPClient(opts...)
	sess.client.setStreamWriter(clientOpts.streamWriter)

	sessionID := string(sess.sessionID)

	promptResp, promptErr := sess.conn.Prompt(ctx, acp.PromptRequest{
		SessionId: sess.sessionID,
		Prompt:    []acp.ContentBlock{acp.TextBlock(prompt)},
	})
	if promptErr != nil {
		r := acpResult{Stdout: sess.client.collectedOutput(), SessionID: sessionID}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return r, fmt.Errorf("ACP prompt timed out: %w", ctx.Err())
		}
		return r, fmt.Errorf("ACP prompt failed on one-shot session: %w", promptErr)
	}

	output := sess.client.collectedOutput()

	zap.L().Debug("ACP one-shot session prompt completed",
		zap.String("agent", agentName),
		zap.String("stopReason", string(promptResp.StopReason)),
		zap.Int("outputBytes", len(output)))

	if len(output) == 0 && promptResp.StopReason == "end_turn" {
		recentStderr := sess.stderrBuf.last(10)
		stderrSummary := ""
		if len(recentStderr) > 0 {
			stderrSummary = strings.Join(recentStderr, "\n")
		}
		warnFields := []zap.Field{
			zap.String("agent", agentName),
			zap.String("cwd", sess.cwd),
			zap.Int("promptLength", len(prompt)),
		}
		if stderrSummary != "" {
			warnFields = append(warnFields, zap.String("recent_stderr", stderrSummary))
		}
		zap.L().Warn("ACP agent returned empty output with zero tokens — the agent's LLM backend may not be processing prompts", warnFields...)
		return acpResult{
			Stdout:    output,
			Stderr:    stderrSummary,
			SessionID: sessionID,
		}, fmt.Errorf("agent %q returned empty output (0 tokens) — the LLM backend did not process the prompt", agentName)
	}

	return acpResult{
		Stdout:    output,
		SessionID: sessionID,
	}, nil
}

// Close kills all sessions and stops the reaper.
func (p *ACPPool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	for name, sess := range p.sessions {
		sess.kill()
		delete(p.sessions, name)
	}
	p.mu.Unlock()

	close(p.reaperStop)
	<-p.reaperDone
	zap.L().Debug("ACP pool closed")
}

// spawnSession creates a new warm ACP session for the given agent.
func (p *ACPPool) spawnSession(ctx context.Context, agentName string, cwd string, opts ...acpClientOption) (*acpSession, error) {
	agentDef, ok := p.agents[agentName]
	if !ok {
		return nil, fmt.Errorf("agent %q not found in pool configuration", agentName)
	}

	cmdPath, err := exec.LookPath(agentDef.Command)
	if err != nil {
		return nil, fmt.Errorf("agent command %q not found in PATH: %w", agentDef.Command, err)
	}

	// Resolve cwd to absolute path before spawning the process.
	// A relative "." is meaningless for a long-running server whose CWD may not exist.
	absCwd := cwd
	if !filepath.IsAbs(cwd) {
		if abs, absErr := filepath.Abs(cwd); absErr == nil {
			absCwd = abs
		} else {
			// Fallback: use os.TempDir() if we can't resolve the CWD (e.g., it was deleted)
			absCwd = os.TempDir()
		}
	}

	zap.L().Debug("spawning ACP warm session",
		zap.String("agent", agentName),
		zap.String("cmd", cmdPath+" "+strings.Join(agentDef.Args, " ")),
		zap.String("cwd", absCwd))

	cmd := exec.CommandContext(ctx, cmdPath, agentDef.Args...)
	cmd.Dir = absCwd
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if len(agentDef.Env) > 0 {
		cmd.Env = cmd.Environ()
		for k, v := range agentDef.Env {
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

	stderrReader, stderrWriter := io.Pipe()
	cmd.Stderr = stderrWriter

	if err := cmd.Start(); err != nil {
		_ = stderrWriter.Close()
		return nil, fmt.Errorf("failed to start agent process: %w", err)
	}

	sess := &acpSession{
		agentName:    agentName,
		cmd:          cmd,
		cwd:          absCwd,
		stdinPipe:    stdinPipe,
		stderrWriter: stderrWriter,
		stderrReader: stderrReader,
		lastUsed:     time.Now(),
	}

	// Drain stderr in background, keeping last lines for diagnostics
	sess.stderrWg.Add(1)
	go func() {
		defer sess.stderrWg.Done()
		scanner := bufio.NewScanner(stderrReader)
		for scanner.Scan() {
			line := scanner.Text()
			sess.stderrBuf.add(line)
			zap.L().Debug("agent stderr (warm)", zap.String("agent", agentName), zap.String("line", line))
		}
	}()

	client := newACPClient(opts...)
	sess.client = client

	conn := acp.NewClientSideConnection(client, stdinPipe, stdoutPipe)
	conn.SetLogger(slog.New(newZapSlogHandler()))
	sess.conn = conn

	// Initialize
	initResp, initErr := conn.Initialize(ctx, acp.InitializeRequest{
		ProtocolVersion: acp.ProtocolVersionNumber,
		ClientCapabilities: acp.ClientCapabilities{
			Fs: acp.FileSystemCapability{
				ReadTextFile:  true,
				WriteTextFile: false,
			},
			Terminal: false,
		},
	})
	if initErr != nil {
		sess.kill()
		return nil, fmt.Errorf("ACP initialize failed for warm session: %w", initErr)
	}
	sess.authMethods = initResp.AuthMethods

	// Create session
	sessReq := acp.NewSessionRequest{
		Cwd:        absCwd,
		McpServers: []acp.McpServer{},
	}
	if agentDef.SessionMeta != nil {
		sessReq.Meta = agentDef.SessionMeta
	}
	sessResp, sessErr := conn.NewSession(ctx, sessReq)
	if sessErr != nil {
		sess.kill()
		return nil, fmt.Errorf("ACP new session failed for warm session: %w", sessErr)
	}

	sess.sessionID = sessResp.SessionId
	zap.L().Debug("ACP warm session created",
		zap.String("agent", agentName),
		zap.String("sessionId", string(sessResp.SessionId)))

	return sess, nil
}

// evictLRU kills the lowest-weight (then least-recently-used) session that is not in use.
// Must be called with p.mu held.
func (p *ACPPool) evictLRU() {
	var victim *acpSession
	var victimName string
	for name, sess := range p.sessions {
		if sess.inUse {
			continue
		}
		if victim == nil {
			victim = sess
			victimName = name
			continue
		}
		// Prefer evicting lower-weight sessions; tie-break by LRU
		if sess.weight < victim.weight || (sess.weight == victim.weight && sess.lastUsed.Before(victim.lastUsed)) {
			victim = sess
			victimName = name
		}
	}
	if victim != nil {
		zap.L().Debug("ACP pool evicting session", zap.String("agent", victimName), zap.Int("weight", victim.weight))
		victim.kill()
		delete(p.sessions, victimName)
	}
}

// reaper periodically kills idle sessions.
func (p *ACPPool) reaper() {
	defer close(p.reaperDone)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.reaperStop:
			return
		case <-ticker.C:
			p.mu.Lock()
			idleTimeout := time.Duration(p.cfg.EffectiveIdleTimeout()) * time.Second
			now := time.Now()
			for name, sess := range p.sessions {
				if sess.inUse {
					continue
				}
				if !sess.alive() || now.Sub(sess.lastUsed) > idleTimeout {
					zap.L().Debug("ACP reaper killing idle session",
						zap.String("agent", name),
						zap.Duration("idle", now.Sub(sess.lastUsed)))
					sess.kill()
					delete(p.sessions, name)
				}
			}
			p.mu.Unlock()
		}
	}
}



