package agent

import (
	"context"
	"fmt"
	"io"

	"github.com/vigolium/vigolium/internal/config"
	oengine "github.com/vigolium/vigolium/pkg/olium/engine"
)

// AgentSession is an opaque, reusable agent conversation whose prefix (system
// prompt, tool definitions, prior turns) stays warm across prompts so the
// provider's prompt cache hits. Fork returns a child that shares the prefix but
// runs independently — used for parallel sub-runs such as the source-analysis
// fan-out.
type AgentSession interface {
	Fork() AgentSession
}

// SessionSpec configures a session built via AgentRuntime.NewSessionWithSpec for
// specialized one-off flows (the guardrail classifier, intent setup) that need a
// custom system prompt, turn cap, or tool set. The combination used by the
// default NewSession — {SourcePath: ..., IncludeTools: true} — reproduces the
// standard engine: builtin tools, the config's system prompt (or the package
// default), and the engine's default turn cap.
type SessionSpec struct {
	System            string // explicit system prompt; empty falls back to cfg/default
	SourcePath        string // appended to the system prompt when set
	MaxTurns          int    // 0 = engine default
	IncludeTools      bool   // register the builtin tool set
	EnablePromptCache bool
}

// defaultRuntime backs package-level helpers that don't carry an Engine (e.g.
// the guardrail classifier). It's a var so tests can substitute a fake.
var defaultRuntime AgentRuntime = oliumRuntime{}

// AgentRuntime abstracts AI dispatch so the agent engine depends on an interface
// rather than the concrete olium runtime. The default implementation
// (oliumRuntime) is backed by the in-process olium engine; tests can substitute
// a fake. This is the single seam between agent orchestration and the LLM
// runtime: concrete olium types live behind it (here and in olium_adapter.go),
// keeping the rest of pkg/agent free of a hard dependency on one runtime.
type AgentRuntime interface {
	// RunPrompt runs one prompt on a fresh session. When sourcePath is set it is
	// appended to the system prompt so the agent knows it has filesystem access
	// to local source. Text deltas mirror to streamWriter and reasoning deltas to
	// thinkingWriter when those are non-nil.
	RunPrompt(ctx context.Context, cfg *config.OliumConfig, prompt string, streamWriter, thinkingWriter io.Writer, sourcePath string, verbose bool) (oliumRunOutput, error)

	// RunOnSession runs one prompt reusing an existing session's warm prefix.
	RunOnSession(ctx context.Context, cfg *config.OliumConfig, sess AgentSession, prompt string, streamWriter, thinkingWriter io.Writer, verbose bool) (oliumRunOutput, error)

	// NewSession builds a reusable session without running anything. Equivalent
	// to NewSessionWithSpec with the standard tool-enabled spec.
	NewSession(cfg *config.OliumConfig, sourcePath string) (AgentSession, error)

	// NewSessionWithSpec builds a session from an explicit SessionSpec, for
	// specialized flows that need a custom system prompt, turn cap, or tool set.
	NewSessionWithSpec(cfg *config.OliumConfig, spec SessionSpec) (AgentSession, error)
}

// oliumRuntime is the olium-backed AgentRuntime. It is stateless — all config is
// passed per call — and delegates to the package's olium dispatch helpers in
// olium_adapter.go, keeping concrete olium engine types out of the rest of
// pkg/agent.
type oliumRuntime struct{}

// oliumSession wraps a concrete *oengine.Engine behind the AgentSession seam.
type oliumSession struct{ eng *oengine.Engine }

func (s *oliumSession) Fork() AgentSession { return &oliumSession{eng: s.eng.Fork()} }

func (oliumRuntime) RunPrompt(ctx context.Context, cfg *config.OliumConfig, prompt string, streamWriter, thinkingWriter io.Writer, sourcePath string, verbose bool) (oliumRunOutput, error) {
	return runOliumPromptWithThinking(ctx, cfg, prompt, streamWriter, thinkingWriter, sourcePath, verbose)
}

func (oliumRuntime) RunOnSession(ctx context.Context, cfg *config.OliumConfig, sess AgentSession, prompt string, streamWriter, thinkingWriter io.Writer, verbose bool) (oliumRunOutput, error) {
	os, ok := sess.(*oliumSession)
	if !ok || os == nil || os.eng == nil {
		return oliumRunOutput{}, fmt.Errorf("oliumRuntime: invalid agent session %T", sess)
	}
	return runOliumOnEngineWithThinking(ctx, cfg, os.eng, prompt, streamWriter, thinkingWriter, verbose)
}

func (r oliumRuntime) NewSession(cfg *config.OliumConfig, sourcePath string) (AgentSession, error) {
	return r.NewSessionWithSpec(cfg, SessionSpec{SourcePath: sourcePath, IncludeTools: true})
}

func (oliumRuntime) NewSessionWithSpec(cfg *config.OliumConfig, spec SessionSpec) (AgentSession, error) {
	eng, err := buildOliumEngineWithSpec(cfg, spec)
	if err != nil {
		return nil, err
	}
	return &oliumSession{eng: eng}, nil
}
