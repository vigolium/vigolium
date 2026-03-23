package agent

import (
	"context"
	"fmt"
	"io"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/opencodesdk"
	"go.uber.org/zap"
)

// opencodeSession holds a warm OpenCode daemon + session for reuse across prompts.
type opencodeSession struct {
	client    *opencodesdk.Client
	sessionID string // reused across prompts in the same session
	dead      bool
}

func (s *opencodeSession) alive() bool {
	return !s.dead && s.client != nil && s.client.Alive()
}

func (s *opencodeSession) kill() {
	if s.client != nil {
		_ = s.client.Close()
	}
	s.dead = true
}

var opencodeFallbackAgent = config.AgentDef{Command: "opencode", Protocol: "opencode-sdk"}

// OpenCodePool manages warm OpenCode daemon sessions for reuse across prompts.
// Like CodexPool, it reuses sessions — sending follow-up prompts to the same
// session for continued context.
type OpenCodePool struct {
	inner *SessionPool[*opencodeSession]
}

// NewOpenCodePool creates a new OpenCode session pool.
func NewOpenCodePool(cfg config.WarmSessionConfig, agents map[string]config.AgentDef) *OpenCodePool {
	return &OpenCodePool{
		inner: NewSessionPool[*opencodeSession]("OpenCode", cfg, agents),
	}
}

// Prompt sends a prompt to the named agent, reusing a warm session if available.
// Falls back to one-shot RunOpenCodeSDK if the session is busy or dead.
func (p *OpenCodePool) Prompt(ctx context.Context, agentName string, prompt string, cfg opencodeRunConfig, poolKey string, weight int) (acpResult, error) {
	return p.inner.Use(ctx, agentName, poolKey, weight,
		func(ctx context.Context) (*opencodeSession, error) {
			return createOpenCodeSession(ctx, p.inner, agentName, cfg)
		},
		func(ctx context.Context, sess *opencodeSession) (acpResult, error) {
			return promptOpenCodeSession(ctx, sess, prompt, cfg.StreamWriter)
		},
		func(ctx context.Context) (acpResult, error) {
			agentDef := p.inner.ResolveAgent(agentName, opencodeFallbackAgent)
			return RunOpenCodeSDK(ctx, agentDef, prompt, cfg)
		},
	)
}

// Close shuts down the pool and all sessions.
func (p *OpenCodePool) Close() {
	p.inner.Close()
}

func promptOpenCodeSession(ctx context.Context, sess *opencodeSession, prompt string, streamWriter io.Writer) (acpResult, error) {
	output, err := sess.client.Prompt(ctx, sess.sessionID, prompt, streamWriter)
	if err != nil {
		return acpResult{Stdout: output, SessionID: sess.sessionID}, err
	}
	return acpResult{Stdout: output, SessionID: sess.sessionID}, nil
}

func createOpenCodeSession(ctx context.Context, pool *SessionPool[*opencodeSession], agentName string, cfg opencodeRunConfig) (*opencodeSession, error) {
	agentDef := pool.ResolveAgent(agentName, opencodeFallbackAgent)
	opts := buildOpenCodeSDKOptions(agentDef, cfg)

	client := opencodesdk.NewClient(opts)

	if err := client.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start OpenCode client: %w", err)
	}

	sessionID, err := client.CreateSession(ctx)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("failed to create OpenCode session: %w", err)
	}

	zap.L().Debug("created OpenCode warm session",
		zap.String("agent", agentName),
		zap.String("sessionId", sessionID),
		zap.String("cwd", cfg.Cwd))

	return &opencodeSession{
		client:    client,
		sessionID: sessionID,
	}, nil
}
