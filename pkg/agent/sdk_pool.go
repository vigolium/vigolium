package agent

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/agent/claudesdk"
	"github.com/vigolium/vigolium/internal/config"
	"go.uber.org/zap"
)

// sdkSession holds a warm SDK client for reuse across prompts.
type sdkSession struct {
	agentName string
	client    *claudesdk.Client
	inUse     bool
	lastUsed  time.Time
	weight    int  // higher = less likely to be evicted
	dead      bool // set true after close errors
}

func (s *sdkSession) alive() bool {
	return !s.dead
}

func (s *sdkSession) kill() {
	if s.client != nil {
		_ = s.client.Close()
	}
	s.dead = true
}

// SDKPool manages warm SDK client sessions for reuse across prompts.
// It mirrors ACPPool's interface but is much simpler since the SDK client
// handles subprocess management internally.
type SDKPool struct {
	mu         sync.Mutex
	sessions   map[string]*sdkSession // keyed by pool key
	cfg        config.WarmSessionConfig
	agents     map[string]config.AgentDef
	reaperStop chan struct{}
	reaperDone chan struct{}
	closed     bool
}

// NewSDKPool creates a new SDK session pool.
func NewSDKPool(cfg config.WarmSessionConfig, agents map[string]config.AgentDef) *SDKPool {
	p := &SDKPool{
		sessions:   make(map[string]*sdkSession),
		cfg:        cfg,
		agents:     agents,
		reaperStop: make(chan struct{}),
		reaperDone: make(chan struct{}),
	}
	go p.reaper()
	return p
}

// Prompt sends a prompt to the named agent, reusing a warm session if available.
// Falls back to one-shot RunAgenticSDK if the session is busy or dead.
func (p *SDKPool) Prompt(ctx context.Context, agentName string, prompt string, cfg sdkRunConfig, poolKey string, weight int) (acpResult, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return acpResult{}, fmt.Errorf("SDK pool is closed")
	}

	sess, exists := p.sessions[poolKey]

	// Check if existing session is usable
	if exists {
		if !sess.alive() {
			delete(p.sessions, poolKey)
			exists = false
		} else if sess.inUse {
			// Session busy — fall through to one-shot below
			p.mu.Unlock()
			zap.L().Debug("SDK warm session busy, falling back to one-shot",
				zap.String("agent", agentName),
				zap.String("poolKey", poolKey))
			agentDef := p.resolveAgent(agentName)
			return RunAgenticSDK(ctx, agentDef, prompt, cfg)
		}
	}

	// Evict LRU if at max capacity
	if !exists && len(p.sessions) >= p.cfg.EffectiveMaxSessions() {
		p.evictLRU()
	}
	p.mu.Unlock()

	// Create new session if needed
	if !exists {
		newSess, err := p.createSession(agentName, cfg)
		if err != nil {
			return acpResult{}, fmt.Errorf("failed to create SDK session: %w", err)
		}

		p.mu.Lock()
		// Check for race — another goroutine may have inserted one
		if existing, raced := p.sessions[poolKey]; raced && existing.alive() {
			if existing.inUse {
				p.mu.Unlock()
				// Use the new session as one-shot
				defer newSess.kill()
				return p.promptSession(ctx, newSess, prompt, cfg.StreamWriter)
			}
			sess = existing
			p.mu.Unlock()
			newSess.kill()
		} else {
			p.sessions[poolKey] = newSess
			sess = newSess
			p.mu.Unlock()
		}

		if weight > 0 {
			sess.weight = weight
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

	result, err := p.promptSession(ctx, sess, prompt, cfg.StreamWriter)
	if err != nil {
		// Session may be dead
		p.mu.Lock()
		sess.dead = true
		delete(p.sessions, poolKey)
		p.mu.Unlock()
		sess.kill()
		return result, err
	}

	return result, nil
}

// promptSession sends a prompt to an existing session and collects output.
func (p *SDKPool) promptSession(ctx context.Context, sess *sdkSession, prompt string, streamWriter io.Writer) (acpResult, error) {
	// Send prompt (first call creates query, subsequent calls are multi-turn)
	if err := sess.client.Query(ctx, prompt); err != nil {
		return acpResult{}, fmt.Errorf("SDK session query failed: %w", err)
	}

	output, sessionID, err := collectSDKOutput(ctx, sess.client, streamWriter)
	if err != nil {
		return acpResult{Stdout: output, SessionID: sessionID}, err
	}

	zap.L().Debug("SDK warm session prompt completed",
		zap.String("agent", sess.agentName),
		zap.Int("outputBytes", len(output)))

	return acpResult{
		Stdout:    output,
		SessionID: sessionID,
	}, nil
}

// createSession creates a new SDK client session.
func (p *SDKPool) createSession(agentName string, cfg sdkRunConfig) (*sdkSession, error) {
	agentDef := p.resolveAgent(agentName)
	opts := buildSDKOptions(agentDef, cfg)

	client := claudesdk.NewClient(opts)

	zap.L().Debug("created SDK warm session",
		zap.String("agent", agentName),
		zap.String("cwd", cfg.Cwd))

	return &sdkSession{
		agentName: agentName,
		client:    client,
		lastUsed:  time.Now(),
	}, nil
}

// resolveAgent looks up an agent definition by name, falling back to a minimal def.
func (p *SDKPool) resolveAgent(name string) config.AgentDef {
	if def, ok := p.agents[name]; ok {
		return def
	}
	return config.AgentDef{Command: "claude", Protocol: "sdk"}
}

// evictLRU removes the least-recently-used, lowest-weight, not-in-use session.
// Must be called with p.mu held.
func (p *SDKPool) evictLRU() {
	var evictKey string
	var evictTime time.Time
	evictWeight := int(^uint(0) >> 1) // max int

	for key, sess := range p.sessions {
		if sess.inUse {
			continue
		}
		if sess.weight < evictWeight || (sess.weight == evictWeight && (evictKey == "" || sess.lastUsed.Before(evictTime))) {
			evictKey = key
			evictTime = sess.lastUsed
			evictWeight = sess.weight
		}
	}

	if evictKey != "" {
		sess := p.sessions[evictKey]
		delete(p.sessions, evictKey)
		go sess.kill() // kill outside lock
		zap.L().Debug("evicted SDK warm session",
			zap.String("key", evictKey),
			zap.String("agent", sess.agentName))
	}
}

// reaper periodically kills idle sessions.
func (p *SDKPool) reaper() {
	defer close(p.reaperDone)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.reaperStop:
			return
		case <-ticker.C:
			p.reapIdle()
		}
	}
}

// reapIdle kills sessions that have been idle longer than the configured timeout.
func (p *SDKPool) reapIdle() {
	maxIdle := time.Duration(p.cfg.EffectiveIdleTimeout()) * time.Second
	now := time.Now()

	p.mu.Lock()
	var toKill []*sdkSession
	for key, sess := range p.sessions {
		if !sess.inUse && now.Sub(sess.lastUsed) > maxIdle {
			toKill = append(toKill, sess)
			delete(p.sessions, key)
			zap.L().Debug("reaping idle SDK session",
				zap.String("agent", sess.agentName),
				zap.Duration("idle", now.Sub(sess.lastUsed)))
		}
	}
	p.mu.Unlock()

	for _, sess := range toKill {
		sess.kill()
	}
}

// Close shuts down the pool and all sessions.
func (p *SDKPool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true

	sessions := make([]*sdkSession, 0, len(p.sessions))
	for _, sess := range p.sessions {
		sessions = append(sessions, sess)
	}
	p.sessions = nil
	p.mu.Unlock()

	close(p.reaperStop)
	<-p.reaperDone

	for _, sess := range sessions {
		sess.kill()
	}
}
