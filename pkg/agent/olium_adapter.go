package agent

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/olium"
	oengine "github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/sessionlog"
	"github.com/vigolium/vigolium/pkg/olium/skill"
	"github.com/vigolium/vigolium/pkg/olium/stream"
	"github.com/vigolium/vigolium/pkg/olium/tool"
	"github.com/vigolium/vigolium/pkg/olium/toollog"
	"github.com/vigolium/vigolium/pkg/olium/vigtool"
)

// oliumRunOutput is the structured return of runOliumPrompt — text plus the
// per-call token usage summed across all turns of the multi-turn loop.
type oliumRunOutput struct {
	Text  string
	Usage agenttypes.TokenUsage
}

// oliumProviderSem caps the number of in-flight olium provider calls
// across the entire process. Sized lazily on first acquire from
// cfg.EffectiveMaxConcurrent(); subsequent config changes are ignored to
// keep semantics simple (the swarm/autopilot session uses one config).
//
// Without this cap, source-analysis (3 parallel) + plan batches (3 parallel)
// + triage + repair calls can pile up and trigger 429s on tier-1 API plans.
var (
	oliumProviderSemOnce sync.Once
	oliumProviderSem     chan struct{}
)

// acquireProviderSlot blocks until a provider slot is available or ctx is
// cancelled. Returns a release func; safe to defer immediately after acquire.
func acquireProviderSlot(ctx context.Context, cfg *config.OliumConfig) (release func(), err error) {
	max := 4
	if cfg != nil {
		max = cfg.EffectiveMaxConcurrent()
	}
	if max <= 0 {
		// Unbounded — no semaphore.
		return func() {}, nil
	}
	oliumProviderSemOnce.Do(func() {
		oliumProviderSem = make(chan struct{}, max)
	})
	select {
	case oliumProviderSem <- struct{}{}:
		return func() { <-oliumProviderSem }, nil
	case <-ctx.Done():
		return func() {}, ctx.Err()
	}
}

// runOliumPromptWithThinking is the single dispatch path for all Engine.Run
// callers (query, swarm phases, source analysis) after the subprocess-backend
// removal. Streaming: if streamWriter is non-nil, text deltas are mirrored
// there in real time. It also forwards the model's thinking deltas
// (reasoning content from o1 / Claude thinking) to thinkingWriter — pass nil
// to discard. sourcePath, when set, is appended to the system prompt so the
// agent knows it has filesystem access to local source code.
func runOliumPromptWithThinking(ctx context.Context, cfg *config.OliumConfig, prompt string, streamWriter, thinkingWriter io.Writer, sourcePath string, verbose bool, rec RecordSpec) (oliumRunOutput, error) {
	eng, err := buildOliumEngineWithSpec(cfg, SessionSpec{SourcePath: sourcePath, IncludeTools: true, Record: rec})
	if err != nil {
		return oliumRunOutput{}, err
	}
	// Fresh-per-call path: this engine isn't reused, so flush + close its
	// transcript recorder here (no-op when rec.SessionDir was empty). The
	// recorder buffers the final assistant turn until close, so without this
	// the last turn never lands in the transcript.
	defer func() { _ = eng.CloseRecorder() }()
	return runOliumOnEngineWithThinking(ctx, cfg, eng, prompt, streamWriter, thinkingWriter, verbose)
}

// buildOliumEngineWithSpec is the general engine constructor behind the
// AgentRuntime seam. It resolves the provider from olium config, then applies
// the SessionSpec (system prompt, source-path suffix, turn cap, tool set,
// prompt cache). Concrete olium engine/provider/tool types are confined to this
// file so the rest of pkg/agent depends only on the AgentRuntime interface.
func buildOliumEngineWithSpec(cfg *config.OliumConfig, spec SessionSpec) (*oengine.Engine, error) {
	if cfg == nil {
		return nil, fmt.Errorf("olium config is nil")
	}
	prov, _, model, err := olium.ResolveProvider(olium.Options{
		Provider:            cfg.Provider,
		OAuthCredPath:       cfg.OAuthCredPath,
		OAuthToken:          cfg.OAuthToken,
		LLMAPIKey:           cfg.LLMAPIKey,
		GoogleCloudProject:  cfg.GoogleCloudProject,
		GoogleCloudLocation: cfg.GoogleCloudLocation,
		Model:               cfg.Model,
		ReasoningEffort:     cfg.ReasoningEffort,
		CustomBaseURL:       cfg.CustomProvider.BaseURL,
		CustomModelID:       cfg.CustomProvider.ModelID,
		CustomAPIKey:        firstNonEmpty(cfg.CustomProvider.APIKey, cfg.LLMAPIKey),
		CustomExtraHeaders:  cfg.CustomProvider.ExtraHeadersMap(),
	})
	if err != nil {
		return nil, fmt.Errorf("olium provider: %w", err)
	}

	system := spec.System
	if system == "" {
		system = cfg.SystemPrompt
		if system == "" {
			system = olium.DefaultSystemPrompt
		}
	}
	if spec.SourcePath != "" {
		system += "\n\nApplication source code is available at: " + spec.SourcePath
	}

	ecfg := oengine.Config{
		Provider:          prov,
		Model:             model,
		System:            system,
		MaxTurns:          spec.MaxTurns,
		EnablePromptCache: spec.EnablePromptCache,
		// Skills, when set, are rendered into the system prompt as an
		// <available_skills> block by engine.New. The load_skill tool that
		// serves their bodies is registered below (requires IncludeTools).
		Skills: spec.Skills,
	}
	if spec.IncludeTools {
		reg := tool.NewRegistry()
		tool.RegisterBuiltins(reg, nil)
		if spec.Skills != nil && spec.Skills.Len() > 0 {
			reg.Register(skill.NewLoadTool(spec.Skills))
		}
		// Read+replay subset: lets a skill-driven agent confirm/escalate against
		// prior scan records (explore → inspect → craft → replay). Stateless
		// tools only — no oast_mint (it owns an interactsh Service needing
		// Shutdown the per-call engine can't run).
		if spec.VigTools != nil && spec.VigTools.Repo != nil {
			sessCtx := &vigtool.SessionsContext{
				Repo:        spec.VigTools.Repo,
				ProjectUUID: spec.VigTools.ProjectUUID,
			}
			reg.Register(vigtool.NewQueryRecordsTool(sessCtx))
			reg.Register(vigtool.NewInspectRecordTool(sessCtx))
			reg.Register(vigtool.NewReplayRequestTool(sessCtx))
			reg.Register(vigtool.NewAttackKitTool())
		}
		ecfg.Tools = reg
	}

	// Attach a Pi-style JSONL transcript recorder when a session dir is wired.
	// Mirrors autopilot's transcript so swarm/query phases also persist their
	// turns — including model reasoning — for post-hoc debugging. A recorder
	// construction failure is non-fatal: the run proceeds without a transcript.
	if spec.Record.SessionDir != "" {
		name := uniqueTranscriptName(spec.Record.SessionDir, spec.Record.Template)
		sessID := spec.Record.SessionID
		if sessID == "" {
			sessID = filepath.Base(spec.Record.SessionDir)
		}
		cwd, _ := os.Getwd()
		if rec, rerr := sessionlog.New(filepath.Join(spec.Record.SessionDir, name), sessionlog.Meta{
			SessionID: sessID,
			Provider:  prov.Name(),
			Model:     model,
			Cwd:       cwd,
		}); rerr == nil {
			ecfg.Recorder = rec
		}
	}

	return oengine.New(ecfg), nil
}

// transcriptSeq tracks how many recorders have been opened per
// (sessionDir, template) within this process, so concurrent same-template
// calls (swarm plan batches run up to BatchConcurrency goroutines deep) get
// distinct files instead of interleaving large tool-result lines into one.
var (
	transcriptSeqMu sync.Mutex
	transcriptSeq   = map[string]int{}
)

// uniqueTranscriptName returns the per-phase transcript basename for a session
// dir + template. The first use of a (dir, template) pair in this process gets
// the clean name (transcript-<template>.jsonl); the 2nd, 3rd, … get
// transcript-<template>-2.jsonl etc. Keying on dir keeps separate runs (each
// its own session dir) clean — only true collisions within one run are
// suffixed. An empty template falls back to "inline", matching the thinking
// sink's naming.
func uniqueTranscriptName(sessionDir, template string) string {
	safe := sanitizeTemplateSegment(template)
	key := sessionDir + "\x00" + safe
	transcriptSeqMu.Lock()
	n := transcriptSeq[key]
	transcriptSeq[key]++
	transcriptSeqMu.Unlock()
	if n == 0 {
		return "transcript-" + safe + ".jsonl"
	}
	return fmt.Sprintf("transcript-%s-%d.jsonl", safe, n+1)
}

// runOliumOnEngineWithThinking is the full-fidelity version that also
// forwards thinking deltas (reasoning content) to a separate sink. Lets
// session-dir loggers preserve the model's reasoning artifact for later
// debugging without polluting the user-visible text stream.
func runOliumOnEngineWithThinking(ctx context.Context, cfg *config.OliumConfig, eng *oengine.Engine, prompt string, streamWriter, thinkingWriter io.Writer, verbose bool) (oliumRunOutput, error) {
	release, err := acquireProviderSlot(ctx, cfg)
	if err != nil {
		return oliumRunOutput{}, err
	}
	defer release()

	// Bound the per-call duration so a hung provider stream can't pin the
	// whole phase. context.DeadlineExceeded is already a retryable
	// sentinel — retryAgentCall will back off and retry.
	if cfg != nil {
		if to := cfg.EffectiveCallTimeout(); to > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, to)
			defer cancel()
		}
	}

	var captured strings.Builder
	var usage agenttypes.TokenUsage
	// Surface tool exec start/end on streamWriter so swarm phases match the
	// autopilot/headless format. Per-turn usage is *not* echoed here — swarm
	// drives many short phases and a [turn done ...] line per phase is too
	// noisy. Adapter still tallies usage from the same event below. The
	// reasoning lane is pinned to stderr (not streamWriter, which is stdout
	// for swarm/query) so piped stdout stays clean; it's gated on --verbose
	// inside the logger.
	tlog := toollog.NewWith(streamWriter, verbose).WithThinkingWriter(os.Stderr)
	ch := eng.Run(ctx, prompt)
	for ev := range ch {
		if tlog.HandleTool(ev) {
			continue
		}
		if tlog.HandleThinking(ev) {
			// Also persist raw reasoning to the per-template thinking file
			// (transcript artifact) when one is wired; the logger only renders
			// the live, compacted stderr lane.
			if thinkingWriter != nil {
				_, _ = io.WriteString(thinkingWriter, ev.Delta)
			}
			continue
		}
		switch ev.Type {
		case oengine.EventTextDelta:
			// Flush buffered reasoning before this turn's assistant text so the
			// operator reads think → answer (a text-only phase never hits a
			// tool card to trigger the flush).
			tlog.FlushThinking()
			captured.WriteString(ev.Delta)
			if streamWriter != nil {
				_, _ = io.WriteString(streamWriter, ev.Delta)
			}
		case oengine.EventTurnDone:
			if ev.Usage != nil {
				usage.InputTokens += ev.Usage.Input
				usage.OutputTokens += ev.Usage.Output
			}
		case oengine.EventError:
			tlog.FlushThinking()
			return oliumRunOutput{Text: captured.String(), Usage: usage}, fmt.Errorf("olium: %w", classifyOliumError(ev.Err))
		}
	}
	// Flush reasoning from a final turn that produced no assistant text and no
	// tool card (otherwise it'd be silently dropped at phase end).
	tlog.FlushThinking()
	return oliumRunOutput{Text: captured.String(), Usage: usage}, nil
}

// WrapProviderWithSemaphore returns a provider.Provider that gates each
// Stream call through the shared oliumProviderSem. Use this around the
// resolved provider before passing it into long-running loops (autopilot)
// so their per-turn LLM calls participate in the same process-wide cap as
// the swarm/source-analysis paths — without this, autopilot bypasses the
// limiter and N concurrent sessions can flood the provider with 429s.
//
// The slot is held only for the duration of one Stream (one model turn),
// not the whole run, so a multi-hour autopilot doesn't pin a slot.
func WrapProviderWithSemaphore(cfg *config.OliumConfig, p provider.Provider) provider.Provider {
	if p == nil {
		return nil
	}
	return &semaphoreProvider{inner: p, cfg: cfg}
}

type semaphoreProvider struct {
	inner provider.Provider
	cfg   *config.OliumConfig
}

func (s *semaphoreProvider) Name() string { return s.inner.Name() }

// CloseIdleConnections forwards to the wrapped provider when it implements
// provider.ConnectionResetter so the engine's retry path can drain idle
// conns through the wrapper without unwrapping first.
func (s *semaphoreProvider) CloseIdleConnections() {
	if r, ok := s.inner.(provider.ConnectionResetter); ok {
		r.CloseIdleConnections()
	}
}

func (s *semaphoreProvider) Stream(ctx context.Context, req provider.Request) (<-chan stream.Event, error) {
	release, err := acquireProviderSlot(ctx, s.cfg)
	if err != nil {
		return nil, err
	}
	innerCh, err := s.inner.Stream(ctx, req)
	if err != nil {
		release()
		return nil, err
	}
	// Re-emit events on a forwarded channel and release the slot only
	// after the inner stream drains. The engine drains the channel in
	// streamOnce, so cancelling ctx propagates to the inner provider and
	// the close arrives promptly.
	out := make(chan stream.Event, cap(innerCh))
	go func() {
		defer release()
		defer close(out)
		for ev := range innerCh {
			out <- ev
		}
	}()
	return out, nil
}
