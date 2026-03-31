package backend

import (
	"context"
	"fmt"
	"io"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/agent/claudesdk"
	"go.uber.org/zap"
)

// SDKSession holds a warm SDK client for reuse across prompts.
type SDKSession struct {
	client *claudesdk.Client
	dead   bool
}

func (s *SDKSession) Alive() bool {
	return !s.dead
}

func (s *SDKSession) Kill() {
	if s.client != nil {
		_ = s.client.Close()
	}
	s.dead = true
}

var sdkFallbackAgent = config.AgentDef{Command: "claude", Protocol: "sdk"}

// SDKPool manages warm SDK client sessions for reuse across prompts.
type SDKPool struct {
	inner *SessionPool[*SDKSession]
}

// NewSDKPool creates a new SDK session pool.
func NewSDKPool(cfg config.WarmSessionConfig, agents map[string]config.AgentDef) *SDKPool {
	return &SDKPool{
		inner: NewSessionPool[*SDKSession]("SDK", cfg, agents),
	}
}

// Prompt sends a prompt to the named agent, reusing a warm session if available.
// Falls back to one-shot RunAgenticSDK if the session is busy or dead.
func (p *SDKPool) Prompt(ctx context.Context, agentName string, prompt string, cfg SDKRunConfig, poolKey string, weight int) (agenttypes.RunResult, error) {
	return p.inner.Use(ctx, agentName, poolKey, weight,
		func(_ context.Context) (*SDKSession, error) {
			return createSDKSession(p.inner, agentName, cfg)
		},
		func(ctx context.Context, sess *SDKSession) (agenttypes.RunResult, error) {
			return promptSDKSession(ctx, sess, prompt, cfg.StreamWriter)
		},
		func(ctx context.Context) (agenttypes.RunResult, error) {
			agentDef := p.inner.ResolveAgent(agentName, sdkFallbackAgent)
			return RunAgenticSDK(ctx, agentDef, prompt, cfg)
		},
	)
}

// Close shuts down the pool and all sessions.
func (p *SDKPool) Close() {
	p.inner.Close()
}

func promptSDKSession(ctx context.Context, sess *SDKSession, prompt string, streamWriter io.Writer) (agenttypes.RunResult, error) {
	if err := sess.client.Query(ctx, prompt); err != nil {
		return agenttypes.RunResult{}, fmt.Errorf("SDK session query failed: %w", err)
	}

	output, sessionID, err := CollectSDKOutput(ctx, sess.client, streamWriter)
	if err != nil {
		return agenttypes.RunResult{Stdout: output, SessionID: sessionID}, err
	}

	return agenttypes.RunResult{Stdout: output, SessionID: sessionID}, nil
}

func createSDKSession(pool *SessionPool[*SDKSession], agentName string, cfg SDKRunConfig) (*SDKSession, error) {
	agentDef := pool.ResolveAgent(agentName, sdkFallbackAgent)
	opts := BuildSDKOptions(agentDef, cfg)

	client := claudesdk.NewClient(opts)

	zap.L().Debug("created SDK warm session",
		zap.String("agent", agentName),
		zap.String("cwd", cfg.Cwd))

	return &SDKSession{
		client: client,
	}, nil
}
