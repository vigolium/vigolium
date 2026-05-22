package agent

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/agent/agenttypes"
	"github.com/vigolium/vigolium/pkg/olium"
	oengine "github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/stream"
	"github.com/vigolium/vigolium/pkg/olium/tool"
	"github.com/vigolium/vigolium/pkg/olium/toollog"
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
func runOliumPromptWithThinking(ctx context.Context, cfg *config.OliumConfig, prompt string, streamWriter, thinkingWriter io.Writer, sourcePath string, verbose bool) (oliumRunOutput, error) {
	eng, err := buildOliumEngine(cfg, sourcePath)
	if err != nil {
		return oliumRunOutput{}, err
	}
	return runOliumOnEngineWithThinking(ctx, cfg, eng, prompt, streamWriter, thinkingWriter, verbose)
}

// buildOliumEngine constructs an oengine.Engine from olium config without
// running anything. Useful when the same engine is reused for multiple
// prompts (e.g., source-analysis explore -> 3 forked format calls) so the
// conversation prefix stays warm in provider history.
func buildOliumEngine(cfg *config.OliumConfig, sourcePath string) (*oengine.Engine, error) {
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

	reg := tool.NewRegistry()
	tool.RegisterBuiltins(reg, nil)

	system := cfg.SystemPrompt
	if system == "" {
		system = olium.DefaultSystemPrompt
	}
	if sourcePath != "" {
		system += "\n\nApplication source code is available at: " + sourcePath
	}

	return oengine.New(oengine.Config{
		Provider: prov,
		Tools:    reg,
		Model:    model,
		System:   system,
	}), nil
}

// runOliumOnEngine executes a single prompt against an existing engine and
// drains its event stream into captured text + usage. Bounds provider
// concurrency via the global semaphore. Used both by runOliumPrompt
// (per-call fresh engine) and by SA's session-based reuse path.
func runOliumOnEngine(ctx context.Context, cfg *config.OliumConfig, eng *oengine.Engine, prompt string, streamWriter io.Writer) (oliumRunOutput, error) {
	return runOliumOnEngineWithThinking(ctx, cfg, eng, prompt, streamWriter, nil, false)
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
	// noisy. Adapter still tallies usage from the same event below.
	tlog := toollog.NewWith(streamWriter, verbose)
	ch := eng.Run(ctx, prompt)
	for ev := range ch {
		if tlog.HandleTool(ev) {
			continue
		}
		switch ev.Type {
		case oengine.EventTextDelta:
			captured.WriteString(ev.Delta)
			if streamWriter != nil {
				_, _ = io.WriteString(streamWriter, ev.Delta)
			}
		case oengine.EventThinkingDelta:
			if thinkingWriter != nil {
				_, _ = io.WriteString(thinkingWriter, ev.Delta)
			}
		case oengine.EventTurnDone:
			if ev.Usage != nil {
				usage.InputTokens += ev.Usage.Input
				usage.OutputTokens += ev.Usage.Output
			}
		case oengine.EventError:
			return oliumRunOutput{Text: captured.String(), Usage: usage}, fmt.Errorf("olium: %w", classifyOliumError(ev.Err))
		}
	}
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
