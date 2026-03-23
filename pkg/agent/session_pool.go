package agent

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"go.uber.org/zap"
)

// warmSession is the constraint for sessions managed by SessionPool.
type warmSession interface {
	alive() bool
	kill()
}

// poolEntry wraps a warm session with lifecycle metadata.
type poolEntry[S warmSession] struct {
	agentName string
	session   S
	inUse     bool
	lastUsed  time.Time
	weight    int
}

// SessionPool is a generic warm session pool with LRU eviction and idle reaping.
// It replaces the per-backend pool implementations (SDKPool, CodexPool, OpenCodePool)
// with a single parameterized type.
type SessionPool[S warmSession] struct {
	mu         sync.Mutex
	entries    map[string]*poolEntry[S]
	cfg        config.WarmSessionConfig
	agents     map[string]config.AgentDef
	reaperStop chan struct{}
	reaperDone chan struct{}
	closed     bool
	name       string // pool name for logging
}

// NewSessionPool creates a new generic session pool.
func NewSessionPool[S warmSession](name string, cfg config.WarmSessionConfig, agents map[string]config.AgentDef) *SessionPool[S] {
	p := &SessionPool[S]{
		entries:    make(map[string]*poolEntry[S]),
		cfg:        cfg,
		agents:     agents,
		reaperStop: make(chan struct{}),
		reaperDone: make(chan struct{}),
		name:       name,
	}
	go p.reaper()
	return p
}

// ResolveAgent looks up an agent definition by name, returning fallback if not found.
func (p *SessionPool[S]) ResolveAgent(name string, fallback config.AgentDef) config.AgentDef {
	if def, ok := p.agents[name]; ok {
		return def
	}
	return fallback
}

// Use acquires or creates a session, runs promptFn, and handles the full lifecycle.
// createFn creates a new session when none exists for the pool key.
// promptFn executes the prompt on an acquired session.
// fallbackFn is called when the existing session is busy.
func (p *SessionPool[S]) Use(
	ctx context.Context,
	agentName, poolKey string,
	weight int,
	createFn func(ctx context.Context) (S, error),
	promptFn func(ctx context.Context, sess S) (acpResult, error),
	fallbackFn func(ctx context.Context) (acpResult, error),
) (acpResult, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return acpResult{}, fmt.Errorf("%s pool is closed", p.name)
	}

	entry, exists := p.entries[poolKey]

	if exists {
		if !entry.session.alive() {
			delete(p.entries, poolKey)
			exists = false
		} else if entry.inUse {
			p.mu.Unlock()
			zap.L().Debug(p.name+" warm session busy, falling back to one-shot",
				zap.String("agent", agentName),
				zap.String("poolKey", poolKey))
			return fallbackFn(ctx)
		}
	}

	if !exists && len(p.entries) >= p.cfg.EffectiveMaxSessions() {
		p.evictLRU()
	}
	p.mu.Unlock()

	// Create new session if needed
	if !exists {
		sess, err := createFn(ctx)
		if err != nil {
			return acpResult{}, err
		}

		p.mu.Lock()
		if existing, raced := p.entries[poolKey]; raced && existing.session.alive() {
			if existing.inUse {
				p.mu.Unlock()
				defer sess.kill()
				return promptFn(ctx, sess)
			}
			entry = existing
			p.mu.Unlock()
			sess.kill()
		} else {
			newEntry := &poolEntry[S]{
				agentName: agentName,
				session:   sess,
				lastUsed:  time.Now(),
			}
			p.entries[poolKey] = newEntry
			entry = newEntry
			p.mu.Unlock()
		}

		if weight > 0 {
			entry.weight = weight
		}
	}

	p.mu.Lock()
	entry.inUse = true
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		entry.inUse = false
		entry.lastUsed = time.Now()
		p.mu.Unlock()
	}()

	result, err := promptFn(ctx, entry.session)
	if err != nil {
		p.mu.Lock()
		delete(p.entries, poolKey)
		p.mu.Unlock()
		entry.session.kill()
		return result, err
	}

	return result, nil
}

// evictLRU removes the least-recently-used, lowest-weight, not-in-use session.
// Must be called with p.mu held.
func (p *SessionPool[S]) evictLRU() {
	var evictKey string
	var evictTime time.Time
	evictWeight := int(^uint(0) >> 1) // max int

	for key, entry := range p.entries {
		if entry.inUse {
			continue
		}
		if entry.weight < evictWeight || (entry.weight == evictWeight && (evictKey == "" || entry.lastUsed.Before(evictTime))) {
			evictKey = key
			evictTime = entry.lastUsed
			evictWeight = entry.weight
		}
	}

	if evictKey != "" {
		entry := p.entries[evictKey]
		delete(p.entries, evictKey)
		go entry.session.kill()
		zap.L().Debug("evicted "+p.name+" warm session",
			zap.String("key", evictKey),
			zap.String("agent", entry.agentName))
	}
}

func (p *SessionPool[S]) reaper() {
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

func (p *SessionPool[S]) reapIdle() {
	maxIdle := time.Duration(p.cfg.EffectiveIdleTimeout()) * time.Second
	now := time.Now()

	p.mu.Lock()
	var toKill []S
	for key, entry := range p.entries {
		if !entry.inUse && now.Sub(entry.lastUsed) > maxIdle {
			toKill = append(toKill, entry.session)
			delete(p.entries, key)
			zap.L().Debug("reaping idle "+p.name+" session",
				zap.String("agent", entry.agentName),
				zap.Duration("idle", now.Sub(entry.lastUsed)))
		}
	}
	p.mu.Unlock()

	for _, sess := range toKill {
		sess.kill()
	}
}

// Close shuts down the pool and all sessions.
func (p *SessionPool[S]) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true

	sessions := make([]S, 0, len(p.entries))
	for _, entry := range p.entries {
		sessions = append(sessions, entry.session)
	}
	p.entries = nil
	p.mu.Unlock()

	close(p.reaperStop)
	<-p.reaperDone

	for _, sess := range sessions {
		sess.kill()
	}
}
