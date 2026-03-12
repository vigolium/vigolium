package agent

import (
	"testing"
	"time"

	"github.com/vigolium/vigolium/internal/config"
)

func boolPtr(b bool) *bool { return &b }

func TestNewACPPool(t *testing.T) {
	cfg := config.WarmSessionConfig{
		Enable:      boolPtr(true),
		IdleTimeout: 60,
		MaxSessions: 3,
	}
	agents := map[string]config.AgentDef{
		"test": {Command: "echo", Args: []string{"hello"}, Protocol: "acp"},
	}

	pool := NewACPPool(cfg, agents)
	if pool == nil {
		t.Fatal("expected pool to be non-nil")
	}
	defer pool.Close()

	if pool.closed {
		t.Error("pool should not be closed right after creation")
	}
	if len(pool.sessions) != 0 {
		t.Error("pool should start with no sessions")
	}
}

func TestACPPoolClose(t *testing.T) {
	cfg := config.WarmSessionConfig{Enable: boolPtr(true)}
	agents := map[string]config.AgentDef{}

	pool := NewACPPool(cfg, agents)
	pool.Close()

	if !pool.closed {
		t.Error("pool should be closed after Close()")
	}

	// Double close should not panic
	pool.Close()
}

func TestACPPoolPromptClosed(t *testing.T) {
	cfg := config.WarmSessionConfig{Enable: boolPtr(true)}
	agents := map[string]config.AgentDef{
		"test": {Command: "echo", Protocol: "acp"},
	}

	pool := NewACPPool(cfg, agents)
	pool.Close()

	_, err := pool.Prompt(t.Context(), "test", "hello", ".")
	if err == nil {
		t.Error("expected error when prompting a closed pool")
	}
}

func TestACPPoolPromptUnknownAgent(t *testing.T) {
	cfg := config.WarmSessionConfig{Enable: boolPtr(true)}
	agents := map[string]config.AgentDef{}

	pool := NewACPPool(cfg, agents)
	defer pool.Close()

	_, err := pool.Prompt(t.Context(), "nonexistent", "hello", ".")
	if err == nil {
		t.Error("expected error for unknown agent")
	}
}

func TestACPSessionKill(t *testing.T) {
	sess := &acpSession{
		agentName: "test",
		dead:      false,
	}
	// Killing a session with nil cmd/pipes should not panic
	sess.dead = true
	sess.kill() // should be a no-op
}

func TestACPSessionAlive(t *testing.T) {
	sess := &acpSession{dead: true}
	if sess.alive() {
		t.Error("dead session should not be alive")
	}

	sess2 := &acpSession{dead: false}
	if sess2.alive() {
		t.Error("session with nil process should not be alive")
	}
}

func TestACPPoolEvictLRU(t *testing.T) {
	cfg := config.WarmSessionConfig{
		Enable:      boolPtr(true),
		MaxSessions: 2,
	}
	agents := map[string]config.AgentDef{}

	pool := NewACPPool(cfg, agents)
	defer pool.Close()

	// Add two mock sessions (already dead so kill() is safe)
	pool.sessions["agent-a"] = &acpSession{
		agentName: "agent-a",
		lastUsed:  time.Now().Add(-10 * time.Minute),
		dead:      true,
	}
	pool.sessions["agent-b"] = &acpSession{
		agentName: "agent-b",
		lastUsed:  time.Now().Add(-1 * time.Minute),
		dead:      true,
	}

	pool.evictLRU()

	if _, exists := pool.sessions["agent-a"]; exists {
		t.Error("agent-a (oldest) should have been evicted")
	}
	if _, exists := pool.sessions["agent-b"]; !exists {
		t.Error("agent-b (newer) should still exist")
	}
}

func TestACPPoolEvictLRUSkipsInUse(t *testing.T) {
	cfg := config.WarmSessionConfig{Enable: boolPtr(true), MaxSessions: 1}
	agents := map[string]config.AgentDef{}

	pool := NewACPPool(cfg, agents)
	defer pool.Close()

	pool.sessions["busy"] = &acpSession{
		agentName: "busy",
		lastUsed:  time.Now().Add(-1 * time.Hour),
		inUse:     true,
		dead:      true,
	}
	pool.sessions["idle"] = &acpSession{
		agentName: "idle",
		lastUsed:  time.Now(),
		dead:      true,
	}

	pool.evictLRU()

	// busy is in use, so idle should be evicted instead
	if _, exists := pool.sessions["busy"]; !exists {
		t.Error("in-use session should not be evicted")
	}
	if _, exists := pool.sessions["idle"]; exists {
		t.Error("idle session should have been evicted")
	}
}

func TestWarmSessionConfigDefaults(t *testing.T) {
	cfg := config.WarmSessionConfig{}

	if cfg.IsEnabled() {
		t.Error("should default to disabled")
	}
	if cfg.EffectiveIdleTimeout() != 300 {
		t.Errorf("expected default idle timeout 300, got %d", cfg.EffectiveIdleTimeout())
	}
	if cfg.EffectiveMaxSessions() != 2 {
		t.Errorf("expected default max sessions 2, got %d", cfg.EffectiveMaxSessions())
	}
}

func TestWarmSessionConfigEnabled(t *testing.T) {
	cfg := config.WarmSessionConfig{
		Enable:      boolPtr(true),
		IdleTimeout: 120,
		MaxSessions: 5,
	}

	if !cfg.IsEnabled() {
		t.Error("should be enabled")
	}
	if cfg.EffectiveIdleTimeout() != 120 {
		t.Errorf("expected idle timeout 120, got %d", cfg.EffectiveIdleTimeout())
	}
	if cfg.EffectiveMaxSessions() != 5 {
		t.Errorf("expected max sessions 5, got %d", cfg.EffectiveMaxSessions())
	}
}

func TestAgentDefIsEnabled(t *testing.T) {
	// nil Enable → enabled by default
	d1 := config.AgentDef{Command: "test"}
	if !d1.IsEnabled() {
		t.Error("nil Enable should default to true")
	}

	// Explicitly enabled
	d2 := config.AgentDef{Command: "test", Enable: boolPtr(true)}
	if !d2.IsEnabled() {
		t.Error("Enable=true should be enabled")
	}

	// Explicitly disabled
	d3 := config.AgentDef{Command: "test", Enable: boolPtr(false)}
	if d3.IsEnabled() {
		t.Error("Enable=false should be disabled")
	}
}

func TestAgentConfigValidateDisabledDefault(t *testing.T) {
	cfg := config.AgentConfig{
		DefaultAgent: "test",
		Backends: map[string]config.AgentDef{
			"test": {Command: "echo", Enable: boolPtr(false)},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Error("expected error when default agent is disabled")
	}
}

func TestAgentConfigValidateWarmSession(t *testing.T) {
	cfg := config.AgentConfig{
		DefaultAgent: "test",
		Backends: map[string]config.AgentDef{
			"test": {Command: "echo"},
		},
		WarmSession: config.WarmSessionConfig{
			Enable:      boolPtr(true),
			IdleTimeout: -1,
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for negative idle timeout")
	}
}
