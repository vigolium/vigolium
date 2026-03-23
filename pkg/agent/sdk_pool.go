package agent

import (
	"context"
	"fmt"
	"io"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/claudesdk"
	"go.uber.org/zap"
)

// sdkSession holds a warm SDK client for reuse across prompts.
type sdkSession struct {
	client *claudesdk.Client
	dead   bool
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

var sdkFallbackAgent = config.AgentDef{Command: "claude", Protocol: "sdk"}

// SDKPool manages warm SDK client sessions for reuse across prompts.
type SDKPool struct {
	inner *SessionPool[*sdkSession]
}

// NewSDKPool creates a new SDK session pool.
func NewSDKPool(cfg config.WarmSessionConfig, agents map[string]config.AgentDef) *SDKPool {
	return &SDKPool{
		inner: NewSessionPool[*sdkSession]("SDK", cfg, agents),
	}
}

// Prompt sends a prompt to the named agent, reusing a warm session if available.
// Falls back to one-shot RunAgenticSDK if the session is busy or dead.
func (p *SDKPool) Prompt(ctx context.Context, agentName string, prompt string, cfg sdkRunConfig, poolKey string, weight int) (acpResult, error) {
	return p.inner.Use(ctx, agentName, poolKey, weight,
		func(_ context.Context) (*sdkSession, error) {
			return createSDKSession(p.inner, agentName, cfg)
		},
		func(ctx context.Context, sess *sdkSession) (acpResult, error) {
			return promptSDKSession(ctx, sess, prompt, cfg.StreamWriter)
		},
		func(ctx context.Context) (acpResult, error) {
			agentDef := p.inner.ResolveAgent(agentName, sdkFallbackAgent)
			return RunAgenticSDK(ctx, agentDef, prompt, cfg)
		},
	)
}

// Close shuts down the pool and all sessions.
func (p *SDKPool) Close() {
	p.inner.Close()
}

func promptSDKSession(ctx context.Context, sess *sdkSession, prompt string, streamWriter io.Writer) (acpResult, error) {
	if err := sess.client.Query(ctx, prompt); err != nil {
		return acpResult{}, fmt.Errorf("SDK session query failed: %w", err)
	}

	output, sessionID, err := collectSDKOutput(ctx, sess.client, streamWriter)
	if err != nil {
		return acpResult{Stdout: output, SessionID: sessionID}, err
	}

	return acpResult{Stdout: output, SessionID: sessionID}, nil
}

func createSDKSession(pool *SessionPool[*sdkSession], agentName string, cfg sdkRunConfig) (*sdkSession, error) {
	agentDef := pool.ResolveAgent(agentName, sdkFallbackAgent)
	opts := buildSDKOptions(agentDef, cfg)

	client := claudesdk.NewClient(opts)

	zap.L().Debug("created SDK warm session",
		zap.String("agent", agentName),
		zap.String("cwd", cfg.Cwd))

	return &sdkSession{
		client: client,
	}, nil
}
