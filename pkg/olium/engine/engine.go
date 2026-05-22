package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/skill"
	"github.com/vigolium/vigolium/pkg/olium/stream"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// DefaultToolTimeout bounds each individual tool invocation. A runaway
// bash/web_fetch call shouldn't be able to hang the whole autopilot
// session; five minutes is generous for legitimate work (curl against a
// slow target, grep across a large repo) while still bounded.
const DefaultToolTimeout = 5 * time.Minute

// Config configures an Engine.
type Config struct {
	Provider provider.Provider
	Tools    *tool.Registry
	Model    string
	System   string
	// Skills, when non-nil, are injected into the system prompt as an
	// <available_skills> block. The model decides when to read them via
	// read_file. Does not constrain or replace Tools.
	Skills *skill.Registry
	// MaxTurns caps how many LLM→tool cycles a single Run may do. 0 = default 32.
	MaxTurns int
	// ToolTimeout bounds each tool invocation. 0 = DefaultToolTimeout.
	// Negative = disabled (tools run without an imposed deadline, honoring
	// only the parent ctx).
	ToolTimeout time.Duration
	// EnablePromptCache opts the provider into cache_control breakpoints
	// on the system prompt and tool list. Ignored by providers that don't
	// support caching. Recommended for long-running multi-turn loops
	// (autopilot) where the system prompt + tools dominate the prefix.
	EnablePromptCache bool
	// MaxToolResultBytes truncates large tool outputs (e.g. `bash ls -R`
	// on a big repo) before appending to history, preventing context
	// overflow across long multi-turn runs. 0 = DefaultMaxToolResultBytes
	// (16 KiB). Negative = disabled (no truncation).
	MaxToolResultBytes int

	// SpillDir, when non-empty, changes oversized-tool-result handling
	// from in-place head+tail truncation to spill-to-disk: the full
	// payload is written to a file under SpillDir/tool-results/ and the
	// in-history content becomes a head excerpt plus a clear pointer
	// (with the on-disk path), so the model can `read_file` the rest if
	// it needs more. Caller is responsible for the directory's lifecycle.
	SpillDir string

	// OnToolResult, when non-nil, is invoked with each tool's content
	// after shrink/spill but before the result is appended to history.
	// The returned string replaces the history-side content; the event
	// stream still emits the raw tool output so operator logs stay clean.
	// Autopilot uses this to pin a scratchpad digest at the tail of every
	// non-scratchpad tool result so plan state stays at the conversation
	// tail across long stretches between update_plan / remember calls.
	OnToolResult func(toolName string, content string, isErr bool) string

	// RetryInitialBackoff sets the first sleep between transient-stream-error
	// retries inside streamOnceWithRetry; each subsequent retry doubles up
	// to maxBackoff (10s). 0 = DefaultRetryInitialBackoff (1s). Tests set
	// this to ms-scale so they don't spend seconds on backoff sleeps.
	RetryInitialBackoff time.Duration

	// NudgeOnEmptyToolCalls caps how many consecutive text-only turns
	// (no tool_calls) the engine tolerates before exiting. After each empty
	// turn within the cap, NudgeOnEmptyMessage is appended as a user-role
	// message and the loop continues so the model gets one more chance to
	// either resume work or call the agent's halt tool. 0 = disabled
	// (legacy behavior: first empty turn ends the run). Use for agentic
	// loops where a capable model is expected to keep calling tools and a
	// silent text-only turn means the model has lost the loop — typical
	// with small open-weight models that don't reliably emit tool_calls.
	NudgeOnEmptyToolCalls int

	// NudgeOnEmptyMessage is the user-role text injected after an empty
	// turn when NudgeOnEmptyToolCalls > 0. Empty = a generic default that
	// asks for either a tool call or a halt. Callers that wire a specific
	// halt tool (autopilot's halt_scan) should override with a message
	// that names it explicitly.
	NudgeOnEmptyMessage string
}

// DefaultRetryInitialBackoff is the first sleep between transient stream
// retries when Config.RetryInitialBackoff is unset.
const DefaultRetryInitialBackoff = time.Second

// DefaultMaxToolResultBytes is the cap applied to each tool result when
// the engine appends it to conversation history. Tools that legitimately
// return more than this (e.g. very large code search results) get
// head + tail truncation with a clear elision marker so the model still
// sees the start and the most recent context.
const DefaultMaxToolResultBytes = 16 * 1024

// defaultNudgeOnEmptyMessage is used when NudgeOnEmptyToolCalls > 0 but
// NudgeOnEmptyMessage is empty. Generic enough not to assume any specific
// halt-tool name; callers with a custom halt tool should override.
const defaultNudgeOnEmptyMessage = "No tool was called and no halt was requested. Either pick the next concrete step and invoke a tool now, or call a halt tool with a one-line reason. Do not respond with text alone."

// Engine is the multi-turn agent runtime. One Engine handles one
// conversation; call Run per user prompt.
type Engine struct {
	cfg              Config
	maxT             int
	toolTimeout      time.Duration
	maxToolResultLen int    // 0 disables truncation
	nudgeOnEmpty     int    // 0 = disabled
	nudgeMessage     string // resolved at construction; empty only when nudgeOnEmpty == 0
	mu               sync.Mutex
	history          []provider.Message
}

// New constructs an Engine. Skills (if any) are baked into the system
// prompt at construction time — the registry itself is stable for the
// session, so there's no reason to re-render on every turn.
func New(cfg Config) *Engine {
	max := cfg.MaxTurns
	if max <= 0 {
		max = 32
	}
	toolTO := cfg.ToolTimeout
	if toolTO == 0 {
		toolTO = DefaultToolTimeout
	}
	maxResLen := cfg.MaxToolResultBytes
	switch {
	case maxResLen < 0:
		maxResLen = 0 // disabled
	case maxResLen == 0:
		maxResLen = DefaultMaxToolResultBytes
	}
	if cfg.Skills != nil && cfg.Skills.Len() > 0 {
		cfg.System = skill.InjectIntoSystemPrompt(cfg.System, cfg.Skills)
	}
	nudgeMsg := ""
	if cfg.NudgeOnEmptyToolCalls > 0 {
		nudgeMsg = strings.TrimSpace(cfg.NudgeOnEmptyMessage)
		if nudgeMsg == "" {
			nudgeMsg = defaultNudgeOnEmptyMessage
		}
	}
	return &Engine{
		cfg:              cfg,
		maxT:             max,
		toolTimeout:      toolTO,
		maxToolResultLen: maxResLen,
		nudgeOnEmpty:     cfg.NudgeOnEmptyToolCalls,
		nudgeMessage:     nudgeMsg,
	}
}

// Fork returns a new Engine that shares this engine's provider, tools,
// system prompt, and configuration but starts with an independent copy of
// the current conversation history. Use this to branch a multi-turn run:
// the parent's prefix (system + tool defs + earlier messages) remains in
// the new engine's prompt, so providers with prompt caching can serve the
// repeated prefix from cache, but writes to the fork's history don't echo
// back to the parent.
//
// Typical use: source-analysis explore phase runs once on a parent engine,
// then 3 format/extension sub-calls Fork() and Run() in parallel — they
// each see the explore output in history without paying to re-append it
// in user prompts.
func (e *Engine) Fork() *Engine {
	e.mu.Lock()
	snapshot := make([]provider.Message, len(e.history))
	copy(snapshot, e.history)
	e.mu.Unlock()
	return &Engine{
		cfg:              e.cfg,
		maxT:             e.maxT,
		toolTimeout:      e.toolTimeout,
		maxToolResultLen: e.maxToolResultLen,
		nudgeOnEmpty:     e.nudgeOnEmpty,
		nudgeMessage:     e.nudgeMessage,
		history:          snapshot,
	}
}

// History returns a snapshot of the conversation. Safe to call from the UI thread.
func (e *Engine) History() []provider.Message {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]provider.Message, len(e.history))
	copy(out, e.history)
	return out
}

// Reset clears the conversation history.
func (e *Engine) Reset() {
	e.mu.Lock()
	e.history = nil
	e.mu.Unlock()
}

// Run executes one user prompt through the multi-turn tool loop. The
// returned channel emits Events in order and closes when the run ends
// (success or error). All events must be drained.
func (e *Engine) Run(ctx context.Context, userPrompt string) <-chan Event {
	out := make(chan Event, 64)
	go e.run(ctx, userPrompt, out)
	return out
}

func (e *Engine) run(ctx context.Context, userPrompt string, out chan<- Event) {
	defer close(out)

	e.mu.Lock()
	e.history = append(e.history, provider.Message{
		Role: provider.RoleUser,
		Text: userPrompt,
	})
	e.mu.Unlock()

	tools := e.toolDefs()

	emptyStreak := 0
	for turn := 0; turn < e.maxT; turn++ {
		select {
		case <-ctx.Done():
			out <- Event{Type: EventError, Err: ctx.Err().Error()}
			return
		default:
		}

		req := provider.Request{
			Model:        e.cfg.Model,
			System:       e.cfg.System,
			Messages:     e.snapshotHistory(),
			Tools:        tools,
			CacheControl: e.cfg.EnablePromptCache,
		}
		stopReason, usage, toolCalls, assistantText, err := e.streamOnceWithRetry(ctx, req, out)
		if err != nil {
			out <- Event{Type: EventError, Err: err.Error()}
			return
		}

		// Record the assistant message before we dispatch tools — the
		// follow-up request needs it in history.
		assistantMsg := provider.Message{
			Role:      provider.RoleAssistant,
			Text:      assistantText,
			ToolCalls: toolCalls,
		}
		e.mu.Lock()
		e.history = append(e.history, assistantMsg)
		e.mu.Unlock()

		out <- Event{Type: EventTurnDone, StopReason: stopReason, Usage: usage}

		if len(toolCalls) == 0 {
			// Text-only turn. Small open-weight models routinely lose the
			// tool-calling loop here and silently wrap up after 0-record
			// queries; legacy behavior was to treat the first empty turn as
			// natural completion and exit. With NudgeOnEmptyToolCalls > 0,
			// we instead append a user-role reminder and re-stream — up to
			// the cap — so the model gets a concrete chance to either resume
			// work or call the agent's halt tool explicitly. A capable model
			// that's truly done responds to the nudge by halting (one extra
			// round); a weak one usually gets prodded back into the loop.
			if emptyStreak < e.nudgeOnEmpty {
				emptyStreak++
				e.mu.Lock()
				e.history = append(e.history, provider.Message{
					Role: provider.RoleUser,
					Text: e.nudgeMessage,
				})
				e.mu.Unlock()
				out <- Event{
					Type:  EventInfo,
					Delta: fmt.Sprintf("empty tool-call turn; nudging model to act or halt (%d/%d)", emptyStreak, e.nudgeOnEmpty),
				}
				continue
			}
			out <- Event{Type: EventRunDone, Usage: usage}
			return
		}
		// Productive turn — clear the empty streak so the next stall is
		// counted from zero, not the cumulative run total.
		emptyStreak = 0

		// Execute tool calls. When every call in the batch is read-only
		// (read_file, ls, grep, glob, web_fetch), run them concurrently
		// to cut latency on file-heavy turns. Otherwise fall back to
		// strict serial order so side-effect-bearing tools (bash,
		// write_file, edit_file) can't race with each other or with reads
		// of state they're about to mutate.
		//
		// Either way, history append + EventToolExecEnd are emitted in
		// the model's original tool-call order so the LLM sees a stable,
		// deterministic transcript.
		if len(toolCalls) > 1 && e.allParallelizable(toolCalls) {
			e.dispatchToolsParallel(ctx, toolCalls, out)
		} else {
			for _, tc := range toolCalls {
				select {
				case <-ctx.Done():
					out <- Event{Type: EventError, Err: ctx.Err().Error()}
					return
				default:
				}
				e.dispatchAndRecord(ctx, tc, out)
			}
		}
		// Loop back for the model's response to tool outputs.
	}

	out <- Event{Type: EventError, Err: fmt.Sprintf("exceeded max turns (%d)", e.maxT)}
}

// streamOnce runs a single provider stream and forwards its events.
// toolStarted=true means a tool-call-start was emitted without a matching
// end — the retry guard uses this to avoid producing a phantom
// announcement on a fresh attempt.
func (e *Engine) streamOnce(
	ctx context.Context,
	req provider.Request,
	out chan<- Event,
) (stopReason stream.StopReason, usage *stream.Usage, toolCalls []provider.ToolCall, text string, toolStarted bool, err error) {
	ch, err := e.cfg.Provider.Stream(ctx, req)
	if err != nil {
		return "", nil, nil, "", false, err
	}

	var (
		currentTC    *provider.ToolCall
		currentTCBuf string
	)

	for ev := range ch {
		switch ev.Type {
		case stream.EventTextDelta:
			text += ev.Delta
			out <- Event{Type: EventTextDelta, Delta: ev.Delta}

		case stream.EventTextEnd:
			if ev.Content != "" {
				// Prefer the final content from the provider (authoritative)
				text = ev.Content
			}

		case stream.EventThinkingDelta:
			out <- Event{Type: EventThinkingDelta, Delta: ev.Delta}

		case stream.EventToolCallStart:
			if ev.ToolCall != nil {
				currentTC = &provider.ToolCall{
					ID:   ev.ToolCall.ID,
					Name: ev.ToolCall.Name,
					Args: map[string]any{},
				}
				currentTCBuf = ""
				out <- Event{
					Type:       EventToolCallStart,
					ToolCallID: ev.ToolCall.ID,
					ToolName:   ev.ToolCall.Name,
				}
				toolStarted = true
			}

		case stream.EventToolCallDelta:
			currentTCBuf += ev.Delta

		case stream.EventToolCallEnd:
			if ev.ToolCall != nil && currentTC != nil {
				if ev.ToolCall.Arguments != nil {
					currentTC.Args = ev.ToolCall.Arguments
				}
				toolCalls = append(toolCalls, *currentTC)
				currentTC = nil
				currentTCBuf = ""
				// Matching end clears the in-flight start so a later
				// failure on the same stream (after one fully resolved
				// tool call) doesn't gate retry on a stale start.
				toolStarted = false
			}

		case stream.EventDone:
			stopReason = ev.StopReason
			usage = ev.Usage

		case stream.EventError:
			return stopReason, usage, toolCalls, text, toolStarted, fmt.Errorf("%s", ev.Err)
		}
	}

	return stopReason, usage, toolCalls, text, toolStarted, nil
}

// streamOnceWithRetry wraps streamOnce so a transient upstream stream
// failure (HTTP/2 INTERNAL_ERROR, REFUSED_STREAM, GOAWAY, idle reset)
// retries instead of tearing down the whole multi-turn loop. Text and
// thinking deltas are safe to dup on retry (cosmetic only — the operator
// sees a notice line followed by the fresh attempt's output). The one
// terminal case is an in-flight tool-call-start without a matching end:
// retrying then would leave a phantom announcement with no exec.
func (e *Engine) streamOnceWithRetry(
	ctx context.Context,
	req provider.Request,
	out chan<- Event,
) (stream.StopReason, *stream.Usage, []provider.ToolCall, string, error) {
	const (
		maxAttempts = 3
		maxBackoff  = 10 * time.Second
	)
	backoff := e.cfg.RetryInitialBackoff
	if backoff <= 0 {
		backoff = DefaultRetryInitialBackoff
	}
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		stopReason, usage, toolCalls, text, toolStarted, err := e.streamOnce(ctx, req, out)
		if err == nil {
			return stopReason, usage, toolCalls, text, nil
		}
		lastErr = err
		if !stream.IsTransientErr(err) || toolStarted || ctx.Err() != nil {
			return stopReason, usage, toolCalls, text, err
		}
		if attempt == maxAttempts-1 {
			break
		}
		out <- Event{
			Type:  EventInfo,
			Delta: fmt.Sprintf("transient upstream stream error (attempt %d/%d): %s; retrying in %s — assistant text above may be partial, retry will reproduce it in full", attempt+1, maxAttempts, err.Error(), backoff),
		}
		// Force a fresh TCP+TLS conn for the retry — riding the same conn
		// that just got RST'd often hits the same upstream poisoning.
		if r, ok := e.cfg.Provider.(provider.ConnectionResetter); ok {
			r.CloseIdleConnections()
		}
		select {
		case <-ctx.Done():
			return stopReason, usage, toolCalls, text, ctx.Err()
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
	return "", nil, nil, "", lastErr
}

// dispatchTool runs one tool call and returns its result. Emits progress
// events along the way. A per-tool timeout (engine.Config.ToolTimeout) is
// layered on top of the parent ctx so a runaway bash/web_fetch can't hang
// the whole run. Deadline exceeded surfaces as an IsError result — the
// engine loop continues so the model can recover or halt.
func (e *Engine) dispatchTool(ctx context.Context, tc provider.ToolCall, out chan<- Event) tool.Result {
	// A tools-less engine (e.g. a single-turn classifier built with no Tools
	// registry) advertises no tools, but a model can still hallucinate a tool
	// call. Return a recoverable error result instead of dereferencing a nil
	// registry — mirrors the nil guards in categoryFor / allParallelizable.
	if e.cfg.Tools == nil {
		return tool.Result{
			Content: fmt.Sprintf("error: tool %q is not available (no tools registered)", tc.Name),
			IsError: true,
		}
	}
	t, err := e.cfg.Tools.Get(tc.Name)
	if err != nil {
		return tool.Result{
			Content: fmt.Sprintf("error: %v", err),
			IsError: true,
		}
	}
	toolCtx := ctx
	var cancel context.CancelFunc
	if e.toolTimeout > 0 {
		toolCtx, cancel = context.WithTimeout(ctx, e.toolTimeout)
		defer cancel()
	}
	onUpdate := func(partial tool.Result) {
		out <- Event{
			Type:       EventToolExecProgress,
			ToolCallID: tc.ID,
			ToolName:   tc.Name,
			ToolResult: partial.Content,
		}
	}
	res, runErr := t.Execute(toolCtx, tc.Args, onUpdate)
	if runErr != nil {
		return tool.Result{
			Content: fmt.Sprintf("tool panic: %v", runErr),
			IsError: true,
		}
	}
	// If the tool returned without erroring but the per-tool deadline expired
	// (e.g., a well-behaved tool noticed ctx.Done and returned a partial
	// result without surfacing an error), still flag it so the model knows
	// the run was truncated.
	if e.toolTimeout > 0 && toolCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
		suffix := fmt.Sprintf("\n\n[tool timed out after %s]", e.toolTimeout)
		res.Content += suffix
		res.IsError = true
	}
	return res
}

// categoryFor resolves a tool's category for event tagging. Defaults to
// CategoryBuiltin when the tool isn't found in the registry — keeps the
// renderer color neutral for unrecognized names instead of flashing
// magenta on something that isn't a vigolium tool.
func (e *Engine) categoryFor(toolName string) string {
	if e.cfg.Tools == nil {
		return tool.CategoryBuiltin
	}
	t, err := e.cfg.Tools.Get(toolName)
	if err != nil || t == nil {
		return tool.CategoryBuiltin
	}
	return t.Category()
}

// allParallelizable reports whether every call in this batch resolves to a
// tool that declares itself read-only. Any miss (unknown tool, mutating
// tool) forces serial dispatch — false positives just lose concurrency,
// false negatives can corrupt shared state.
func (e *Engine) allParallelizable(calls []provider.ToolCall) bool {
	if e.cfg.Tools == nil {
		return false
	}
	for _, tc := range calls {
		t, err := e.cfg.Tools.Get(tc.Name)
		if err != nil || t == nil || !t.IsReadOnly() {
			return false
		}
	}
	return true
}

// dispatchToolsParallel executes every call concurrently but writes results
// to history and the event stream in the original call order. Bounded
// fan-out (8) keeps file-handle / socket usage sane on huge batches.
func (e *Engine) dispatchToolsParallel(ctx context.Context, calls []provider.ToolCall, out chan<- Event) {
	const maxFanOut = 8

	// Emit ExecStart in order before kicking off goroutines so the UI
	// sees the agent "thinking about all of them" up front.
	for _, tc := range calls {
		out <- Event{
			Type:         EventToolExecStart,
			ToolCallID:   tc.ID,
			ToolName:     tc.Name,
			ToolCategory: e.categoryFor(tc.Name),
			ToolArgs:     tc.Args,
		}
	}

	results := make([]tool.Result, len(calls))
	sem := make(chan struct{}, maxFanOut)
	var wg sync.WaitGroup
	for i, tc := range calls {
		i, tc := i, tc
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i] = tool.Result{Content: ctx.Err().Error(), IsError: true}
				return
			}
			// Pass nil onUpdate to avoid interleaved progress events from
			// different tools muddying the stream; final result still
			// appears via EventToolExecEnd in deterministic order below.
			t, err := e.cfg.Tools.Get(tc.Name)
			if err != nil {
				results[i] = tool.Result{Content: fmt.Sprintf("error: %v", err), IsError: true}
				return
			}
			toolCtx := ctx
			if e.toolTimeout > 0 {
				var cancel context.CancelFunc
				toolCtx, cancel = context.WithTimeout(ctx, e.toolTimeout)
				defer cancel()
			}
			res, runErr := t.Execute(toolCtx, tc.Args, nil)
			if runErr != nil {
				res = tool.Result{Content: fmt.Sprintf("tool panic: %v", runErr), IsError: true}
			}
			if e.toolTimeout > 0 && toolCtx.Err() == context.DeadlineExceeded && ctx.Err() == nil {
				res.Content += fmt.Sprintf("\n\n[tool timed out after %s]", e.toolTimeout)
				res.IsError = true
			}
			results[i] = res
		}()
	}
	wg.Wait()

	// Append history + emit ExecEnd in original order.
	for i, tc := range calls {
		res := results[i]
		historyContent := e.prepareHistoryContent(tc, res)
		e.mu.Lock()
		e.history = append(e.history, provider.Message{
			Role:       provider.RoleTool,
			ToolCallID: tc.ID,
			Content:    historyContent,
			IsError:    res.IsError,
		})
		e.mu.Unlock()
		out <- Event{
			Type:         EventToolExecEnd,
			ToolCallID:   tc.ID,
			ToolName:     tc.Name,
			ToolCategory: e.categoryFor(tc.Name),
			ToolResult:   res.Content,
			ToolIsErr:    res.IsError,
		}
	}
}

// dispatchAndRecord runs a single tool call serially (the existing
// codepath), emitting start/end events and appending to history.
func (e *Engine) dispatchAndRecord(ctx context.Context, tc provider.ToolCall, out chan<- Event) {
	category := e.categoryFor(tc.Name)
	out <- Event{
		Type:         EventToolExecStart,
		ToolCallID:   tc.ID,
		ToolName:     tc.Name,
		ToolCategory: category,
		ToolArgs:     tc.Args,
	}
	result := e.dispatchTool(ctx, tc, out)
	historyContent := e.prepareHistoryContent(tc, result)
	e.mu.Lock()
	e.history = append(e.history, provider.Message{
		Role:       provider.RoleTool,
		ToolCallID: tc.ID,
		Content:    historyContent,
		IsError:    result.IsError,
	})
	e.mu.Unlock()
	out <- Event{
		Type:         EventToolExecEnd,
		ToolCallID:   tc.ID,
		ToolName:     tc.Name,
		ToolCategory: category,
		ToolResult:   result.Content,
		ToolIsErr:    result.IsError,
	}
}

// prepareHistoryContent shrinks/spills the tool output and then runs the
// OnToolResult hook so callers (autopilot's scratchpad pin) can append
// state that must outlive the per-tool budget. Both dispatch paths use it
// to keep the shrink→hook ordering identical.
func (e *Engine) prepareHistoryContent(tc provider.ToolCall, res tool.Result) string {
	content := e.shrinkToolResult(tc, res.Content)
	if e.cfg.OnToolResult != nil {
		content = e.cfg.OnToolResult(tc.Name, content, res.IsError)
	}
	return content
}

// shrinkToolResult is the engine-aware wrapper around result clamping.
// When SpillDir is set on the Config and the result is oversized, the
// full payload is written to disk and the in-history content becomes a
// head excerpt + a clear pointer (path, byte count, suggested action).
// Otherwise it falls back to truncateToolResult's head+tail strategy.
func (e *Engine) shrinkToolResult(tc provider.ToolCall, content string) string {
	if e.maxToolResultLen <= 0 || len(content) <= e.maxToolResultLen {
		return content
	}
	if e.cfg.SpillDir != "" {
		if shrunk, ok := spillToolResult(e.cfg.SpillDir, tc, content, e.maxToolResultLen); ok {
			return shrunk
		}
		// Fall through to truncation if the spill failed (disk full,
		// permission denied, etc.) — better to lose detail than stall
		// the loop on an I/O error.
	}
	return truncateToolResult(content, e.maxToolResultLen)
}

// spillToolResult writes the full payload to <dir>/tool-results/<id>.txt
// and returns a short excerpt + pointer the model can act on. ok=false
// means we couldn't write — caller should fall back to truncation.
func spillToolResult(dir string, tc provider.ToolCall, content string, max int) (string, bool) {
	spillBase := filepath.Join(dir, "tool-results")
	if err := os.MkdirAll(spillBase, 0o755); err != nil {
		return "", false
	}
	// Filename: <toolName>-<callID>.txt. Sanitize the call ID since some
	// providers emit slashes / special chars.
	id := tc.ID
	if id == "" {
		id = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	id = sanitizeSpillSegment(id)
	name := sanitizeSpillSegment(tc.Name)
	filename := fmt.Sprintf("%s-%s.txt", name, id)
	path := filepath.Join(spillBase, filename)

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return "", false
	}

	// Reserve a chunk of the budget for the pointer text. Head excerpt
	// gets whatever remains. We pick a head excerpt (not head+tail) here
	// because the model will read the spill file directly if it needs the
	// rest — no point doubling up.
	const pointerTpl = "\n\n[%d bytes total; this is the first %d. Full output saved to `%s` — read with `read_file path=%q` if you need more.]"
	approxPointer := len(fmt.Sprintf(pointerTpl, len(content), 0, path, path))
	headLen := max - approxPointer
	if headLen < 256 {
		// Budget too tight for a useful excerpt — just point at the file.
		return fmt.Sprintf("Tool output spilled to disk (%d bytes). Read with `read_file path=%q`.",
			len(content), path), true
	}
	return content[:headLen] + fmt.Sprintf(pointerTpl, len(content), headLen, path, path), true
}

// sanitizeSpillSegment strips characters that aren't safe in filesystem
// names. Keeps the result short.
func sanitizeSpillSegment(s string) string {
	if s == "" {
		return "x"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
		if b.Len() >= 64 {
			break
		}
	}
	if b.Len() == 0 {
		return "x"
	}
	return b.String()
}

// truncateToolResult clamps oversized tool output so the conversation
// history doesn't grow unbounded. Strategy: keep the head (first 60%) and
// the tail (last 40%) with an elision marker in between — the model still
// sees the start (often a header / table of contents) and the most recent
// content (often what it actually needs to act on next), but stops paying
// for the middle of a 5MB ls output every turn.
//
// max = 0 disables truncation.
func truncateToolResult(content string, max int) string {
	if max <= 0 || len(content) <= max {
		return content
	}
	// Reserve room for the elision marker. If the remaining budget is
	// trivial (max < 256), just hard-truncate.
	const marker = "\n\n... [%d bytes truncated; %d kept (head + tail)] ...\n\n"
	approxMarker := len(fmt.Sprintf(marker, 0, 0))
	budget := max - approxMarker
	if budget < 256 {
		return content[:max]
	}
	headLen := budget * 6 / 10
	tailLen := budget - headLen
	return content[:headLen] +
		fmt.Sprintf(marker, len(content)-headLen-tailLen, headLen+tailLen) +
		content[len(content)-tailLen:]
}

func (e *Engine) snapshotHistory() []provider.Message {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]provider.Message, len(e.history))
	copy(out, e.history)
	return out
}

func (e *Engine) toolDefs() []provider.ToolDef {
	if e.cfg.Tools == nil {
		return nil
	}
	tools := e.cfg.Tools.List()
	defs := make([]provider.ToolDef, 0, len(tools))
	for _, t := range tools {
		defs = append(defs, provider.ToolDef{
			Name:        t.Name(),
			Description: t.Description(),
			Schema:      t.Schema(),
		})
	}
	return defs
}
