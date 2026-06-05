package agent

import (
	"context"
	"fmt"
	"io"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	oengine "github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/skill"
)

// VigToolSpec, when set on a SessionSpec built with IncludeTools, registers the
// vigolium read+replay tool subset — query_records, inspect_record,
// replay_request, attack_kit — so a skill-driven agent (swarm triage) can run
// an explore → inspect → craft → replay confirmation loop against prior scan
// records. Requires Repo. OAST tools are intentionally excluded: oast_mint owns
// an interactsh Service that needs an explicit Shutdown the per-call engine
// can't manage.
type VigToolSpec struct {
	Repo        *database.Repository
	ProjectUUID string
}

// AgentSession is an opaque, reusable agent conversation whose prefix (system
// prompt, tool definitions, prior turns) stays warm across prompts so the
// provider's prompt cache hits. Fork returns a child that shares the prefix but
// runs independently — used for parallel sub-runs such as the source-analysis
// fan-out.
//
// Close flushes and releases any per-session artifact (notably the Pi-style
// JSONL transcript recorder): the recorder buffers the final assistant turn
// until the run ends, so a session built with a RecordSpec must be Closed for
// that turn to land. Sessions without a recorder Close to a no-op. Forks carry
// no recorder (concurrent sub-runs would interleave one file), so closing a
// fork is always a no-op.
type AgentSession interface {
	Fork() AgentSession
	Close() error
}

// RecordSpec configures a per-run Pi-style JSONL transcript written under
// SessionDir. The zero value (empty SessionDir) disables recording. It is
// plain data on purpose so the AgentRuntime seam never leaks olium's
// EventRecorder type — the adapter builds the concrete sessionlog.Recorder
// from these fields inside buildOliumEngineWithSpec.
type RecordSpec struct {
	// SessionDir is the directory the transcript-*.jsonl file is written to.
	// Empty disables recording (the common one-off CLI case).
	SessionDir string
	// Template is the phase/template name; it seeds the per-phase filename
	// (transcript-<template>.jsonl) and the concurrency-dedup key so parallel
	// same-template calls (swarm plan batches) never share a file.
	Template string
	// SessionID is the transcript header's session id; empty falls back to the
	// SessionDir base name.
	SessionID string
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
	// Skills, when non-nil and non-empty, injects an <available_skills> block
	// into the system prompt and registers the load_skill tool (requires
	// IncludeTools). Used by swarm plan/triage phases for planner-driven skill
	// loading; nil for phases that don't surface skills.
	Skills *skill.Registry
	// VigTools, when non-nil with a Repo (and IncludeTools), registers the
	// vigolium read+replay tool subset so a skill can actually confirm/escalate
	// against scan records. nil for phases that only reason over prompt context.
	VigTools *VigToolSpec
	// Record, when its SessionDir is set, attaches a Pi-style JSONL transcript
	// recorder to the built engine so the session's turns (including model
	// reasoning) persist for debugging. Zero value = no transcript.
	Record RecordSpec
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
	// thinkingWriter when those are non-nil. When rec.SessionDir is set, the
	// fresh engine records a Pi-style JSONL transcript (flushed before return).
	RunPrompt(ctx context.Context, cfg *config.OliumConfig, prompt string, streamWriter, thinkingWriter io.Writer, sourcePath string, verbose bool, rec RecordSpec) (oliumRunOutput, error)

	// RunOnSession runs one prompt reusing an existing session's warm prefix.
	// Unlike RunPrompt it takes no RecordSpec: a reused session's transcript
	// recorder (if any) is attached once when the session is built
	// (NewSessionWithSpec with a RecordSpec) and spans all of its prompts, then
	// flushed by AgentSession.Close().
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

// Close flushes and closes the session's transcript recorder (if any). No-op
// for sessions built without a RecordSpec and for forks (which carry no
// recorder). Safe to call multiple times.
func (s *oliumSession) Close() error {
	if s == nil || s.eng == nil {
		return nil
	}
	return s.eng.CloseRecorder()
}

func (oliumRuntime) RunPrompt(ctx context.Context, cfg *config.OliumConfig, prompt string, streamWriter, thinkingWriter io.Writer, sourcePath string, verbose bool, rec RecordSpec) (oliumRunOutput, error) {
	return runOliumPromptWithThinking(ctx, cfg, prompt, streamWriter, thinkingWriter, sourcePath, verbose, rec)
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
