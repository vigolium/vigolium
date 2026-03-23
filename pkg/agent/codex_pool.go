package agent

import (
	"context"
	"fmt"
	"io"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/codexsdk"
	"go.uber.org/zap"
)

// codexSession holds a warm Codex client + thread for reuse across prompts.
type codexSession struct {
	client   *codexsdk.Client
	threadID string // reused across prompts in the same session
	dead     bool
}

func (s *codexSession) alive() bool {
	return !s.dead && s.client != nil && s.client.Alive()
}

func (s *codexSession) kill() {
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
	inner *SessionPool[*codexSession]
}

// NewCodexPool creates a new Codex session pool.
func NewCodexPool(cfg config.WarmSessionConfig, agents map[string]config.AgentDef) *CodexPool {
	return &CodexPool{
		inner: NewSessionPool[*codexSession]("Codex", cfg, agents),
	}
}

// Prompt sends a prompt to the named agent, reusing a warm session (and thread) if available.
// Falls back to one-shot RunCodexSDK if the session is busy or dead.
func (p *CodexPool) Prompt(ctx context.Context, agentName string, prompt string, cfg codexRunConfig, poolKey string, weight int) (acpResult, error) {
	return p.inner.Use(ctx, agentName, poolKey, weight,
		func(ctx context.Context) (*codexSession, error) {
			return createCodexSession(ctx, p.inner, agentName, cfg)
		},
		func(ctx context.Context, sess *codexSession) (acpResult, error) {
			return promptCodexSession(ctx, sess, prompt, cfg.StreamWriter)
		},
		func(ctx context.Context) (acpResult, error) {
			agentDef := p.inner.ResolveAgent(agentName, codexFallbackAgent)
			return RunCodexSDK(ctx, agentDef, prompt, cfg)
		},
	)
}

// Close shuts down the pool and all sessions.
func (p *CodexPool) Close() {
	p.inner.Close()
}

func promptCodexSession(ctx context.Context, sess *codexSession, prompt string, streamWriter io.Writer) (acpResult, error) {
	output, err := executeCodexTurn(ctx, sess.client, sess.threadID, prompt, streamWriter)
	if err != nil {
		return acpResult{Stdout: output, SessionID: sess.threadID}, err
	}
	return acpResult{Stdout: output, SessionID: sess.threadID}, nil
}

func createCodexSession(ctx context.Context, pool *SessionPool[*codexSession], agentName string, cfg codexRunConfig) (*codexSession, error) {
	agentDef := pool.ResolveAgent(agentName, codexFallbackAgent)
	opts := buildCodexOptions(agentDef, cfg)

	client := codexsdk.NewClient(opts)

	if err := client.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start Codex client: %w", err)
	}

	if _, err := client.Initialize(ctx); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("failed to initialize Codex client: %w", err)
	}

	threadParams := buildCodexThreadParams(opts, cfg)
	threadResp, err := client.ThreadStart(ctx, threadParams)
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("failed to start Codex thread: %w", err)
	}

	zap.L().Debug("created Codex warm session",
		zap.String("agent", agentName),
		zap.String("threadId", threadResp.Thread.Id),
		zap.String("cwd", cfg.Cwd))

	return &codexSession{
		client:   client,
		threadID: threadResp.Thread.Id,
	}, nil
}
