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

	inUse    bool
	lastUsed time.Time
	weight   int
	dead     bool
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
func (p *ACPPool) Prompt(ctx context.Context, agentName string, prompt string, cwd string, opts ...acpClientOption) (result acpResult, err error) {
	// Normalize cwd to absolute path for consistent session matching
	if !filepath.IsAbs(cwd) {
		if abs, err := filepath.Abs(cwd); err == nil {
			cwd = abs
		}
	}

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return acpResult{}, fmt.Errorf("pool is closed")
	}

	sess, exists := p.sessions[agentName]
	if exists {
		if !sess.alive() || sess.cwd != cwd {
			zap.L().Debug("ACP warm session stale, replacing",
				zap.String("agent", agentName),
				zap.Bool("alive", sess.alive()),
				zap.String("oldCwd", sess.cwd),
				zap.String("newCwd", cwd))
			sess.kill()
			delete(p.sessions, agentName)
			exists = false
		} else if sess.inUse {
			p.mu.Unlock()
			return acpResult{}, fmt.Errorf("ACP session for agent %q is already in use", agentName)
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
		// Spawn new session (outside lock to avoid blocking)
		newSess, spawnErr := p.spawnSession(ctx, agentName, cwd, opts...)
		if spawnErr != nil {
			return acpResult{}, spawnErr
		}
		p.mu.Lock()
		// Another goroutine may have inserted a session while we were spawning.
		if existing, raced := p.sessions[agentName]; raced && existing.alive() {
			sess = existing
			p.mu.Unlock()
			// Kill the duplicate outside the lock (kill() is safe to call independently)
			newSess.kill()
		} else {
			p.sessions[agentName] = newSess
			sess = newSess
			p.mu.Unlock()
		}

		// Apply session weight from options
		for _, opt := range opts {
			probe := &acpClient{}
			opt(probe)
			if probe.sessionWeight > 0 {
				sess.weight = probe.sessionWeight
			}
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
	var streamWriter io.Writer
	for _, opt := range opts {
		probe := &acpClient{}
		opt(probe)
		if probe.streamWriter != nil {
			streamWriter = probe.streamWriter
		}
	}
	sess.client.setStreamWriter(streamWriter)

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
		delete(p.sessions, agentName)
		p.mu.Unlock()
		sess.kill()

		r := acpResult{Stdout: sess.client.collectedOutput(), SessionID: sessionID}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return r, fmt.Errorf("ACP prompt timed out: %w", ctx.Err())
		}
		return r, fmt.Errorf("ACP prompt failed on warm session: %w", promptErr)
	}

	zap.L().Debug("ACP warm session prompt completed",
		zap.String("agent", agentName),
		zap.String("stopReason", string(promptResp.StopReason)),
		zap.Int("outputBytes", len(sess.client.collectedOutput())))

	return acpResult{
		Stdout:    sess.client.collectedOutput(),
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

	// Drain stderr in background
	sess.stderrWg.Add(1)
	go func() {
		defer sess.stderrWg.Done()
		scanner := bufio.NewScanner(stderrReader)
		for scanner.Scan() {
			zap.L().Debug("agent stderr (warm)", zap.String("agent", agentName), zap.String("line", scanner.Text()))
		}
	}()

	client := newACPClient(opts...)
	sess.client = client

	conn := acp.NewClientSideConnection(client, stdinPipe, stdoutPipe)
	conn.SetLogger(slog.New(newZapSlogHandler()))
	sess.conn = conn

	// Initialize
	_, initErr := conn.Initialize(ctx, acp.InitializeRequest{
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

