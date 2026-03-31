package backend

import (
	"context"
	"fmt"
	"io"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/agent/codexsdk"
	"go.uber.org/zap"
)

// CodexSession holds a warm Codex client + thread for reuse across prompts.
type CodexSession struct {
	client   *codexsdk.Client
	threadID string // reused across prompts in the same session
	dead     bool
}

func (s *CodexSession) Alive() bool {
	return !s.dead && s.client != nil && s.client.Alive()
}

func (s *CodexSession) Kill() {
	if s.client != nil {
		_ = s.client.Close()
	}
	s.dead = true
}

var codexFallbackAgent = config.AgentDef{Command: "codex", Protocol: "codex-sdk"}

// CodexPool manages warm Codex app-server sessions for reuse across prompts.
// Unlike SDK pool which creates new conversations per client, CodexPool reuses
// threads — sending follow-up turns to the same thread for continued context.
type CodexPool struct {
	inner *SessionPool[*CodexSession]
}

// NewCodexPool creates a new Codex session pool.
func NewCodexPool(cfg config.WarmSessionConfig, agents map[string]config.AgentDef) *CodexPool {
	return &CodexPool{
		inner: NewSessionPool[*CodexSession]("Codex", cfg, agents),
	}
}

// Prompt sends a prompt to the named agent, reusing a warm session (and thread) if available.
// Falls back to one-shot RunCodexSDK if the session is busy or dead.
func (p *CodexPool) Prompt(ctx context.Context, agentName string, prompt string, cfg CodexRunConfig, poolKey string, weight int) (agenttypes.RunResult, error) {
	return p.inner.Use(ctx, agentName, poolKey, weight,
		func(ctx context.Context) (*CodexSession, error) {
			return createCodexSession(ctx, p.inner, agentName, cfg)
		},
		func(ctx context.Context, sess *CodexSession) (agenttypes.RunResult, error) {
			return promptCodexSession(ctx, sess, prompt, cfg.StreamWriter)
		},
		func(ctx context.Context) (agenttypes.RunResult, error) {
			agentDef := p.inner.ResolveAgent(agentName, codexFallbackAgent)
			return RunCodexSDK(ctx, agentDef, prompt, cfg)
		},
	)
}

// Close shuts down the pool and all sessions.
func (p *CodexPool) Close() {
	p.inner.Close()
}

func promptCodexSession(ctx context.Context, sess *CodexSession, prompt string, streamWriter io.Writer) (agenttypes.RunResult, error) {
	output, err := ExecuteCodexTurn(ctx, sess.client, sess.threadID, prompt, streamWriter)
	if err != nil {
		return agenttypes.RunResult{Stdout: output, SessionID: sess.threadID}, err
	}
	return agenttypes.RunResult{Stdout: output, SessionID: sess.threadID}, nil
}

func createCodexSession(ctx context.Context, pool *SessionPool[*CodexSession], agentName string, cfg CodexRunConfig) (*CodexSession, error) {
	agentDef := pool.ResolveAgent(agentName, codexFallbackAgent)
	opts := BuildCodexOptions(agentDef, cfg)

	client := codexsdk.NewClient(opts)

	if err := client.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start Codex client: %w", err)
	}

	if _, err := client.Initialize(ctx); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("failed to initialize Codex client: %w", err)
	}

	threadParams := BuildCodexThreadParams(opts, cfg)
	threadResp, err := client.ThreadStart(ctx, threadParams)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("failed to start Codex thread: %w", err)
	}

	zap.L().Debug("created Codex warm session",
		zap.String("agent", agentName),
		zap.String("threadId", threadResp.Thread.Id),
		zap.String("cwd", cfg.Cwd))

	return &CodexSession{
		client:   client,
		threadID: threadResp.Thread.Id,
	}, nil
}
