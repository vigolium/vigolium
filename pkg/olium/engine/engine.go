package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/skill"
	"github.com/vigolium/vigolium/pkg/olium/stream"
	"github.com/vigolium/vigolium/pkg/olium/tool"
)

// toStreamToolCalls converts the engine's internal provider.ToolCall slice
// into the stream.ToolCall shape carried on EventTurnDone for recorders.
// Returns nil for an empty input so the field stays omitted on text-only
// turns (and so event-equality assertions in tests don't see a spurious
// empty slice).
func toStreamToolCalls(calls []provider.ToolCall) []stream.ToolCall {
	if len(calls) == 0 {
		return nil
	}
	out := make([]stream.ToolCall, len(calls))
	for i, c := range calls {
		out[i] = stream.ToolCall{ID: c.ID, Name: c.Name, Arguments: c.Args, ArgsError: c.ArgsError}
	}
	return out
}

// maxStreamAttempts and maxStreamBackoff bound the in-flight retry around a
// single provider stream. A multi-hour agent run meets far more transient
// upstream trouble than a single chat turn: the previous 3 attempts inside
// ~3s let one 429, or one Anthropic 529 overload, end a run that had already
// been working for hours.
const (
	maxStreamAttempts = 5
	maxStreamBackoff  = 30 * time.Second
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
	// MaxToolCalls caps how many tool calls the engine will dispatch for the
	// life of this Engine. 0 = unlimited.
	//
	// Distinct from MaxTurns on purpose: one turn can carry any number of
	// parallel calls, so a turn ceiling does not bound the work done or the
	// money spent. The count deliberately survives Reset, so rotating a
	// section does not refill the budget.
	MaxToolCalls int

	// MaxHistoryBytes bounds the conversation carried into each request.
	// Past it, the oldest tool results are elided (see compactHistory).
	// 0 = DefaultMaxHistoryBytes, negative disables compaction.
	MaxHistoryBytes int

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

	// SessionID is forwarded on every provider request as a stable cache key
	// for backends that take one (OpenAI Responses' prompt_cache_key). Unset
	// means the backend falls back to routing by prefix alone.
	SessionID string

	// ReasoningEffort is the thinking/effort level forwarded on every
	// provider request (low|medium|high|xhigh|max; "" = provider default).
	// Until this was wired, the configured reasoning_effort reached the TUI
	// banner and the session transcript but never the API, so every request
	// ran at the provider's default.
	ReasoningEffort string

	// MaxTokens caps each response's output tokens (0 = provider default).
	// On adaptive-thinking models reasoning counts against this, so a
	// ceiling sized for visible text alone truncates long turns.
	MaxTokens int

	// Recorder, when non-nil, receives a copy of every emitted Event plus
	// the initiating user prompt (see EventRecorder). Engine.Run tees
	// through it at a single chokepoint so no emit site or consumer drain
	// loop needs to know about it. Used to persist a Pi-style JSONL session
	// transcript (pkg/olium/sessionlog). Forks do NOT inherit the recorder
	// — concurrent sub-runs would interleave one file. A recorder that
	// implements io.Closer is closed by Engine.CloseRecorder.
	Recorder EventRecorder
}

// SessionCacheKey derives a provider-side prompt-cache key from a run
// directory. filepath.Base("") is ".", which every keyless run would share,
// so an unset directory yields no key rather than a colliding one. Callers
// that own a real run id should pass that instead - this is the fallback.
func SessionCacheKey(sessionDir string) string {
	if strings.TrimSpace(sessionDir) == "" {
		return ""
	}
	return filepath.Base(sessionDir)
}

// DefaultRetryInitialBackoff is the first sleep between transient stream
// retries when Config.RetryInitialBackoff is unset.
const DefaultRetryInitialBackoff = time.Second

// DefaultMaxHistoryBytes bounds the conversation sent on each request.
//
// History is otherwise append-only for the life of a run: at up to 16 KiB
// per tool result (per result, not per turn - a parallel turn appends one
// each), an agent with a 750-turn budget reaches a 200K-token window's limit
// somewhere around turn 40-150 and then dies on a provider 400. The turn
// budget never binds; the context window does.
//
// 400 KiB is roughly 100K tokens, which leaves headroom under the smallest
// window in common use while keeping far more history than any run needs
// verbatim. Compaction elides the OLDEST tool results first, so the recent
// working set is untouched.
const DefaultMaxHistoryBytes = 400 << 10

// compactionKeepRecentTurns is how many trailing assistant turns are never
// elided. The model needs its recent tool output verbatim to keep working;
// older output has usually been distilled into the scratchpad already.
const compactionKeepRecentTurns = 6

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
	maxHistoryBytes  int    // 0 disables compaction
	maxToolCalls     int    // 0 disables the tool-call budget
	toolCalls        int    // dispatched so far; survives Reset by design
	nudgeOnEmpty     int    // 0 = disabled
	nudgeMessage     string // resolved at construction; empty only when nudgeOnEmpty == 0
	mu               sync.Mutex
	history          []provider.Message
	// failedCalls counts how many times each (tool, arguments) signature has
	// failed in a row. See noteToolOutcome.
	failedCalls map[string]int
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
	maxHist := cfg.MaxHistoryBytes
	switch {
	case maxHist < 0:
		maxHist = 0 // disabled
	case maxHist == 0:
		maxHist = DefaultMaxHistoryBytes
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
		maxHistoryBytes:  maxHist,
		maxToolCalls:     cfg.MaxToolCalls,
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
	// Share config by value, but drop the session recorder: forks run
	// concurrently (parallel sub-calls fan out from one parent), and a
	// shared recorder would interleave or double-write the parent's single
	// transcript file. Derivative sub-runs simply aren't recorded.
	forkCfg := e.cfg
	forkCfg.Recorder = nil
	return &Engine{
		cfg:              forkCfg,
		maxT:             e.maxT,
		toolTimeout:      e.toolTimeout,
		maxToolResultLen: e.maxToolResultLen,
		maxHistoryBytes:  e.maxHistoryBytes,
		maxToolCalls:     e.maxToolCalls,
		nudgeOnEmpty:     e.nudgeOnEmpty,
		nudgeMessage:     e.nudgeMessage,
		history:          snapshot,
	}
}

// CloseRecorder closes the configured session recorder if one is set and it
// implements io.Closer. Safe to call on an engine with no recorder (no-op)
// and on a fork (forks carry no recorder). Callers with a clear run
// lifecycle should defer this so the transcript file is flushed and closed.
func (e *Engine) CloseRecorder() error {
	if c, ok := e.cfg.Recorder.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// History returns a snapshot of the conversation. Safe to call from the UI thread.
func (e *Engine) History() []provider.Message {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.answerDanglingToolCallsLocked()
	out := make([]provider.Message, len(e.history))
	copy(out, e.history)
	return out
}

// Reset clears the conversation history and the per-call failure streaks
// that go with it - a fresh section starts from a clean slate, so a call
// that failed twice before the reset must not inherit an escalation banner.
func (e *Engine) Reset() {
	e.mu.Lock()
	e.history = nil
	e.failedCalls = nil
	e.mu.Unlock()
}

// Run executes one user prompt through the multi-turn tool loop. The
// returned channel emits Events in order and closes when the run ends
// (success or error). All events must be drained.
func (e *Engine) Run(ctx context.Context, userPrompt string) <-chan Event {
	out := make(chan Event, 64)
	rec := e.cfg.Recorder
	if rec == nil {
		go e.run(ctx, userPrompt, out)
		return out
	}
	// Tee every event through the recorder before forwarding it to the
	// caller. This single chokepoint means no emit site inside run() and no
	// consumer drain loop (headless, TUI, autopilot, agent adapter) needs to
	// know recording exists, and the recorder also sees the initiating
	// prompt — which is never an emitted event.
	raw := make(chan Event, 64)
	go e.run(ctx, userPrompt, raw)
	go func() {
		rec.UserPrompt(userPrompt)
		for ev := range raw {
			rec.Record(ev)
			out <- ev
		}
		close(out)
	}()
	return out
}

func (e *Engine) run(ctx context.Context, userPrompt string, out chan<- Event) {
	defer close(out)

	e.mu.Lock()
	// Close out a previous run's unanswered tool calls BEFORE this turn's
	// user message goes in. The repair appends at the tail, so doing it on
	// the first history read (after the user message) would leave a tool
	// result behind a user turn — an order providers reject, and one that
	// never heals because it is stored.
	e.answerDanglingToolCallsLocked()
	e.history = appendUserTurn(e.history, userPrompt)
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

		// Keep the conversation inside the context window. Without this,
		// history only grows and a long run ends on a provider 400 that no
		// retry can help.
		if e.compactHistory() {
			out <- Event{
				Type:  EventInfo,
				Delta: "context compaction: elided older tool output to stay inside the model's window",
			}
		}

		req := provider.Request{
			Model:        e.cfg.Model,
			System:       e.cfg.System,
			Messages:     e.snapshotHistory(),
			Tools:        tools,
			CacheControl: e.cfg.EnablePromptCache,
			ReasoningEff: e.cfg.ReasoningEffort,
			MaxTokens:    e.cfg.MaxTokens,
			SessionID:    e.cfg.SessionID,
		}
		stopReason, usage, toolCalls, assistantText, err := e.streamOnceWithRetry(ctx, req, out)
		if err != nil {
			out <- Event{Type: EventError, Err: err.Error()}
			return
		}

		// Record the assistant message before we dispatch tools — the
		// follow-up request needs it in history.
		if stopReason == stream.StopReasonLength {
			for i := range toolCalls {
				if toolCalls[i].ArgsError != "" {
					toolCalls[i].ArgsError += " - the response hit the output token limit mid-call; send shorter arguments or split the work"
				}
			}
		}
		assistantMsg := provider.Message{
			Role:      provider.RoleAssistant,
			Text:      assistantTurnText(assistantText, toolCalls),
			ToolCalls: toolCalls,
		}
		e.mu.Lock()
		e.history = append(e.history, assistantMsg)
		e.mu.Unlock()

		out <- Event{Type: EventTurnDone, StopReason: stopReason, Usage: usage, ToolCalls: toStreamToolCalls(toolCalls)}

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
			out <- Event{Type: EventRunDone, Usage: usage, Stalled: e.nudgeOnEmpty > 0}
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
		// Spend the tool-call budget before dispatching. Checked here, after
		// the turn is committed to history, so the model's calls are all
		// answered and the conversation stays valid for a resume.
		budgetSpent := e.spendToolCalls(len(toolCalls))

		if len(toolCalls) > 1 && e.allParallelizable(toolCalls) {
			e.dispatchToolsParallel(ctx, toolCalls, out)
		} else {
			for _, tc := range toolCalls {
				select {
				case <-ctx.Done():
					// The calls we are about to skip stay unanswered here;
					// answerDanglingToolCallsLocked closes the turn out the
					// next time history is read.
					out <- Event{Type: EventError, Err: ctx.Err().Error()}
					return
				default:
				}
				e.dispatchAndRecord(ctx, tc, out)
			}
		}
		if budgetSpent {
			out <- Event{
				Type:            EventError,
				Err:             fmt.Sprintf("%s (%d)", maxToolCallsErrPrefix, e.maxToolCalls),
				BudgetExhausted: true,
			}
			return
		}
		// Loop back for the model's response to tool outputs.
	}

	out <- Event{
		Type:            EventError,
		Err:             fmt.Sprintf("%s (%d)", maxTurnsErrPrefix, e.maxT),
		BudgetExhausted: true,
	}
}

// maxTurnsErrPrefix opens the EventError the run loop emits when it hits the
// turn ceiling. Callers distinguish it from a genuine failure with
// IsMaxTurnsError.
const maxTurnsErrPrefix = "exceeded max turns"

// maxToolCallsErrPrefix opens the EventError emitted when the tool-call
// budget is spent.
const maxToolCallsErrPrefix = "exceeded max tool calls"

// spendToolCalls reserves budget for the n calls a turn is about to
// dispatch, reporting whether the budget is now spent.
func (e *Engine) spendToolCalls(n int) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.toolCalls += n
	return e.maxToolCalls > 0 && e.toolCalls >= e.maxToolCalls
}

// ToolCallCount reports how many tool calls this engine has dispatched.
func (e *Engine) ToolCallCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.toolCalls
}

// matchInflight locates the started-but-not-yet-ended tool call that an end
// event belongs to. Ids are the reliable key; the name fallback covers
// gateways that send neither an id nor an index (see resolveToolBuf, which
// separates those calls in the first place). Returns -1 when nothing
// matches - including an end for a call already completed, so a provider
// that re-emits one cannot append a duplicate.
func matchInflight(inflight []*provider.ToolCall, end *stream.ToolCall) int {
	if end.ID != "" {
		for i, tc := range inflight {
			if tc.ID == end.ID {
				return i
			}
		}
		// An id matching nothing in flight is a mismatch, not a
		// free-for-all: fall through to name matching only.
	}
	if end.Name != "" {
		for i, tc := range inflight {
			if tc.Name == end.Name {
				return i
			}
		}
	}
	// One call in flight and no conflicting ids: the end is that call, even
	// though its name changed after the start fired (a placeholder or a name
	// streamed late). Dropping it lost the only call of the turn.
	if len(inflight) == 1 && (end.ID == "" || inflight[0].ID == "") {
		return 0
	}
	return -1
}

// streamOnce runs a single provider stream and forwards its events.
func (e *Engine) streamOnce(
	ctx context.Context,
	req provider.Request,
	out chan<- Event,
) (stopReason stream.StopReason, usage *stream.Usage, toolCalls []provider.ToolCall, assistantText string, err error) {
	// streamCtx lets the repetition guard abandon a looping response without
	// cancelling the run.
	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()
	ch, err := e.cfg.Provider.Stream(streamCtx, req)
	if err != nil {
		return "", nil, nil, "", err
	}
	var guard, thinkingGuard repetitionGuard
	// abandon ends a looping turn early: drop the stream, drained in the
	// background so the provider goroutine can exit, tell the operator, and
	// commit `committed` as a length-stopped, text-only turn.
	abandon := func(notice, committed string) (stream.StopReason, *stream.Usage, []provider.ToolCall, string, error) {
		cancelStream()
		go func() {
			for range ch {
			}
		}()
		out <- Event{Type: EventInfo, Delta: notice}
		return stream.StopReasonLength, usage, toolCalls, committed, nil
	}

	// In-flight tool calls, in start order. A single "current" pointer is NOT
	// enough: the OpenAI chat-completions wire format streams parallel tool
	// calls interleaved by index and only flushes every tool_call_end at the
	// close of the stream (start A, start B, end A, end B). With one pointer,
	// end A lands on call B - the turn executes one call carrying the wrong
	// tool's arguments and silently drops the other. Match ends to starts by
	// call id instead.
	var inflight []*provider.ToolCall

	// block accumulates the text block currently open; text holds every
	// block already closed. See EventTextEnd below. Builders rather than
	// string concatenation: a long turn streams thousands of deltas, and
	// `s += delta` recopies the whole accumulation each time.
	var text, block strings.Builder

	// sawDone records the stream's terminal event. Without it, a connection
	// cut mid-stream looks exactly like a finished turn: the SSE reader
	// returns a partial frame, the provider skips the unparseable JSON, the
	// channel closes, and we would commit a truncated assistant message with
	// err == nil. On Anthropic that means the in-flight tool call vanishes,
	// the turn reads as text-only, and a 750-turn run "completes naturally"
	// at turn 50 with no error anywhere.
	var sawDone bool

	for ev := range ch {
		switch ev.Type {
		case stream.EventTextDelta:
			block.WriteString(ev.Delta)
			out <- Event{Type: EventTextDelta, Delta: ev.Delta}
			if period, looping := guard.feed(ev.Delta); looping {
				// Commit the text with the loop cut down to one copy. No tool
				// call can be pending behind a text loop, so the turn reads
				// as text-only and the empty-turn nudge takes over.
				return abandon("model output is repeating itself; cut the response and moving on",
					text.String()+trimRepetition(block.String(), period))
			}

		case stream.EventTextEnd:
			// Commit the block that just closed. The provider's own final
			// content wins over the accumulated deltas for THAT block only -
			// a turn can carry several text blocks (the Responses API emits
			// one `message` item per block, e.g. a preamble, a tool call,
			// then the answer), and overwriting `text` on each end kept just
			// the last one. The rest was shown to the operator and then lost
			// from history, so the next turn saw a turn it never took.
			if ev.Content != "" {
				text.WriteString(ev.Content)
			} else {
				text.WriteString(block.String())
			}
			block.Reset()

		case stream.EventThinkingDelta:
			out <- Event{Type: EventThinkingDelta, Delta: ev.Delta}
			if _, looping := thinkingGuard.feed(ev.Delta); looping {
				return abandon("model reasoning is repeating itself; cut the response and moving on",
					text.String()+block.String())
			}

		case stream.EventToolCallStart:
			if ev.ToolCall != nil {
				inflight = append(inflight, &provider.ToolCall{
					ID:   ev.ToolCall.ID,
					Name: ev.ToolCall.Name,
					Args: map[string]any{},
				})
				out <- Event{
					Type:       EventToolCallStart,
					ToolCallID: ev.ToolCall.ID,
					ToolName:   ev.ToolCall.Name,
				}
			}

		case stream.EventToolCallDelta:
			// Argument deltas carry no call id, so they can't be attributed
			// when calls interleave. The end event carries the fully parsed
			// arguments; these deltas are forwarded by the provider for
			// progress rendering only.

		case stream.EventToolCallEnd:
			if ev.ToolCall == nil {
				break
			}
			idx := matchInflight(inflight, ev.ToolCall)
			if idx < 0 {
				// Every provider here emits a start before an end, so this
				// is a duplicate or stray end. Dropping it keeps the
				// assistant message self-consistent; appending would give
				// two tool_use blocks the same id.
				break
			}
			tc := inflight[idx]
			if ev.ToolCall.Arguments != nil {
				tc.Args = ev.ToolCall.Arguments
			}
			// The end carries the provider's final view of the call; the
			// start fired on the first name fragment, which can be a
			// placeholder or incomplete.
			if ev.ToolCall.Name != "" {
				tc.Name = ev.ToolCall.Name
			}
			if tc.ID == "" {
				tc.ID = ev.ToolCall.ID
			}
			tc.ArgsError = ev.ToolCall.ArgsError
			toolCalls = append(toolCalls, *tc)
			inflight = append(inflight[:idx], inflight[idx+1:]...)

		case stream.EventDone:
			sawDone = true
			stopReason = ev.StopReason
			usage = ev.Usage

		case stream.EventError:
			return stopReason, usage, toolCalls, text.String() + block.String(), fmt.Errorf("%s", ev.Err)
		}
	}

	if !sawDone {
		return stopReason, usage, toolCalls, text.String() + block.String(), stream.ErrStreamIncomplete
	}

	// A provider that ends its stream without closing the text block (or
	// never emits text_end at all) still gets its text committed.
	return stopReason, usage, toolCalls, text.String() + block.String(), nil
}

// streamOnceWithRetry wraps streamOnce so a transient upstream stream
// failure (HTTP/2 INTERNAL_ERROR, REFUSED_STREAM, GOAWAY, idle reset, or a
// content-less codex `error` frame) retries instead of tearing down the
// whole multi-turn loop. Text, thinking, AND tool-call-start deltas are all
// safe to dup on retry: they're cosmetic only (the operator sees a notice
// line followed by the fresh attempt's output), the assistant message is
// only committed to history from the successful attempt (see run loop), and
// no consumer commits a tool card until EventToolExecEnd — which a failed
// attempt never reaches. We deliberately retry even when a tool-call-start
// was already forwarded: in agentic mode a turn almost always ends in a
// tool call, so gating retry on an in-flight start (the previous behavior)
// defeated recovery in exactly the workload that needs it — a transient
// blip mid-tool-call would tear down the entire run.
func (e *Engine) streamOnceWithRetry(
	ctx context.Context,
	req provider.Request,
	out chan<- Event,
) (stream.StopReason, *stream.Usage, []provider.ToolCall, string, error) {
	backoff := e.cfg.RetryInitialBackoff
	if backoff <= 0 {
		backoff = DefaultRetryInitialBackoff
	}
	var lastErr error
	for attempt := 0; attempt < maxStreamAttempts; attempt++ {
		stopReason, usage, toolCalls, text, err := e.streamOnce(ctx, req, out)
		if err == nil {
			return stopReason, usage, toolCalls, text, nil
		}
		lastErr = err
		if !stream.IsTransientErr(err) || ctx.Err() != nil {
			return stopReason, usage, toolCalls, text, err
		}
		if attempt == maxStreamAttempts-1 {
			break
		}
		out <- Event{
			Type:  EventInfo,
			Delta: fmt.Sprintf("transient upstream stream error (attempt %d/%d): %s; retrying in %s - assistant text above may be partial, retry will reproduce it in full", attempt+1, maxStreamAttempts, err.Error(), backoff),
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
		if backoff *= 2; backoff > maxStreamBackoff {
			backoff = maxStreamBackoff
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
	return e.runTool(ctx, tc, func(partial tool.Result) {
		out <- Event{
			Type:       EventToolExecProgress,
			ToolCallID: tc.ID,
			ToolName:   tc.Name,
			ToolResult: partial.Content,
		}
	})
}

// runTool resolves, bounds and executes one tool call, then annotates the
// result. Shared by the serial and parallel dispatch paths so the two can't
// drift on lookup, timeout, cancellation marking or failure tracking - they
// already had: the parallel copy was missing the nil-registry guard.
// onUpdate may be nil (the parallel path passes nil so concurrent tools
// don't interleave progress events).
func (e *Engine) runTool(ctx context.Context, tc provider.ToolCall, onUpdate tool.UpdateFn) tool.Result {
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
	// Arguments that did not parse: running the tool with {} fails on a
	// missing field and hides the real problem from the model.
	if tc.ArgsError != "" {
		return e.noteToolOutcome(t, tc, tool.Result{
			Content: fmt.Sprintf("error: %s was not run - its %s. Re-issue the call with one complete JSON object.", tc.Name, tc.ArgsError),
			IsError: true,
		})
	}
	timeout := e.timeoutFor(t)
	toolCtx := ctx
	var cancel context.CancelFunc
	if timeout > 0 {
		toolCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	res, runErr := t.Execute(toolCtx, tc.Args, onUpdate)
	if runErr != nil {
		return tool.Result{
			Content: fmt.Sprintf("tool panic: %v", runErr),
			IsError: true,
		}
	}
	return e.noteToolOutcome(t, tc, annotateCutShort(res, ctx, toolCtx, timeout))
}

// annotateCutShort marks a tool result that was cut short by a deadline or a
// cancellation, so the model can tell a truncated run from a complete one.
//
// The marker goes at the HEAD of the content, not the tail: oversized results
// are shrunk to a head excerpt plus a spill pointer (see spillToolResult), so
// a tail marker is exactly what gets thrown away - a tool that timed out
// after producing a lot of output would reach the model looking like an
// ordinary short answer, and the model would reasonably retry it.
func annotateCutShort(res tool.Result, parent, toolCtx context.Context, timeout time.Duration) tool.Result {
	switch {
	case parent.Err() != nil:
		res.Content = "[run cancelled before this tool finished - output below is partial]\n\n" + res.Content
		res.IsError = true
	case toolCtx.Err() == context.DeadlineExceeded:
		res.Content = fmt.Sprintf(
			"[tool timed out after %s - output below is partial. Do not re-run it unchanged; narrow the scope or use a more targeted tool.]\n\n",
			timeout) + res.Content
		res.IsError = true
	}
	return res
}

// timeoutFor resolves the deadline for one tool invocation: the tool's own
// MaxDuration when it declares one (see tool.LongRunning), else the engine
// default. A tool-declared budget wins even when it is shorter.
func (e *Engine) timeoutFor(t tool.Tool) time.Duration {
	if lr, ok := t.(tool.LongRunning); ok {
		if d := lr.MaxDuration(); d > 0 {
			return d
		}
	}
	return e.toolTimeout
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
			// nil onUpdate: concurrent tools would interleave progress
			// events; the final result still appears via EventToolExecEnd in
			// deterministic order below.
			results[i] = e.runTool(ctx, tc, nil)
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
	const pointerTpl = "\n\n[%d bytes total; this is the first %d. Full output saved to `%s` — read with `" + spillPointerMarker + "%q` if you need more.]"
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
	e.answerDanglingToolCallsLocked()
	out := make([]provider.Message, len(e.history))
	copy(out, e.history)
	return out
}

// answerDanglingToolCallsLocked appends a placeholder result for any tool
// call in the trailing assistant turn that never got one.
//
// Every provider rejects a turn whose tool calls aren't all answered
// ("tool_use ids were found without tool_result blocks"), and history is
// re-sent on more paths than it is written: a stream retry, a TUI follow-up
// after Esc, a Fork, a post-halt re-entry. Enforcing it here - wherever
// history is read - covers all of them, including cancel sites that don't
// exist yet. Only the trailing turn can dangle; earlier ones were completed
// before the next assistant message was appended.
func (e *Engine) answerDanglingToolCallsLocked() {
	last := -1
	for i := len(e.history) - 1; i >= 0; i-- {
		if e.history[i].Role == provider.RoleAssistant {
			last = i
			break
		}
	}
	if last < 0 || len(e.history[last].ToolCalls) == 0 {
		return
	}
	answered := make(map[string]struct{}, len(e.history)-last)
	for _, m := range e.history[last+1:] {
		if m.Role == provider.RoleTool {
			answered[m.ToolCallID] = struct{}{}
		}
	}
	for _, tc := range e.history[last].ToolCalls {
		if _, ok := answered[tc.ID]; ok {
			continue
		}
		e.history = append(e.history, provider.Message{
			Role:       provider.RoleTool,
			ToolCallID: tc.ID,
			Content:    "[not run: the run ended before this tool was dispatched]",
			IsError:    true,
		})
	}
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

// maxTrackedFailedCalls bounds the repeat-failure map so a long run with
// many distinct failing calls can't grow it without limit.
const maxTrackedFailedCalls = 256

// noteToolOutcome tracks repeated identical failures and escalates the error
// text when it sees one.
//
// A model that re-issues a call verbatim after it failed is not being
// irrational: a bare "X is required" reads like a transient problem, and
// nothing in the result says "you already tried exactly this". Without a
// signal, the loop only ends at the turn ceiling or the wall clock - an
// observed run burned four turns re-sending the same two calls. The
// escalation names the tool's required arguments and tells the model the
// repeat is the problem, which is the information it needs to move on.
func (e *Engine) noteToolOutcome(t tool.Tool, tc provider.ToolCall, res tool.Result) tool.Result {
	e.mu.Lock()
	tracking := len(e.failedCalls)
	e.mu.Unlock()
	if !res.IsError && tracking == 0 {
		// The overwhelming common case: a call succeeded and no streak is
		// open. Skip hashing the arguments, which on write_file/bash means
		// serializing the whole payload just to build a key we'd discard.
		return res
	}

	sig := callSignature(tc)

	e.mu.Lock()
	if !res.IsError {
		delete(e.failedCalls, sig)
		e.mu.Unlock()
		return res
	}
	n := e.failedCalls[sig] + 1
	if e.failedCalls == nil {
		e.failedCalls = map[string]int{}
	}
	// Bound the map by declining NEW signatures rather than wiping the
	// existing ones, which would silently drop live streaks.
	if n > 1 || len(e.failedCalls) < maxTrackedFailedCalls {
		e.failedCalls[sig] = n
	}
	e.mu.Unlock()

	if n < 2 {
		return res
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[attempt %d of this exact %s call with these exact arguments - every one has failed. "+
		"Re-sending it will fail again.", n, tc.Name)
	if req := requiredArgs(t); len(req) > 0 {
		fmt.Fprintf(&b, " %s requires: %s.", tc.Name, strings.Join(req, ", "))
	}
	b.WriteString(" Change the arguments, use a different tool, or record what you learned and move on.]\n\n")
	res.Content = b.String() + res.Content
	return res
}

// requiredArgs pulls the `required` list out of a tool's JSON schema, or nil
// when the schema doesn't declare one.
func requiredArgs(t tool.Tool) []string {
	if t == nil {
		return nil
	}
	schema := t.Schema()
	if schema == nil {
		return nil
	}
	raw, ok := schema["required"]
	if !ok {
		return nil
	}
	req, _ := raw.([]string)
	return req
}

// callSignature identifies a (tool, arguments) pair. Hashed rather than
// keyed on the arguments themselves so the map holds a fixed-width key
// instead of a tool payload that can run to hundreds of KB.
func callSignature(tc provider.ToolCall) string {
	h := fnv.New64a()
	_, _ = io.WriteString(h, tc.Name)
	// Map keys marshal in sorted order, so this is stable across calls.
	_ = json.NewEncoder(h).Encode(tc.Args)
	return strconv.FormatUint(h.Sum64(), 16)
}

// compactHistory elides the oldest tool results until the conversation fits
// maxHistoryBytes, and reports how many bytes it reclaimed (0 when nothing
// was needed).
//
// Message SHAPE is preserved exactly - no message is dropped, only the text
// inside old tool results is replaced. That keeps the invariant every
// provider enforces (each tool call answered by exactly one result, in
// order) true by construction, which dropping whole messages would not.
//
// Tool results are the right target: they are the bulk of a long run, they
// are the part the model has usually already distilled into the scratchpad,
// and the recent ones - the working set - are left verbatim.
//
// That working set is a floor, so the budget is best-effort: a conversation
// whose last compactionKeepRecentTurns turns alone exceed it stays over.
// Bounded by the per-result cap, that is at most a few hundred KiB - far
// better than blinding the model to what it is currently reasoning about.
func (e *Engine) compactHistory() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.maxHistoryBytes <= 0 {
		return false
	}
	total := 0
	for _, m := range e.history {
		total += len(m.Text) + len(m.Content)
	}
	if total <= e.maxHistoryBytes {
		return false
	}

	// Everything from this index on is the recent working set, kept verbatim:
	// the last compactionKeepRecentTurns assistant messages and the tool
	// results that answer them.
	keepFrom := len(e.history)
	turns := 0
	for i := len(e.history) - 1; i >= 0; i-- {
		if e.history[i].Role != provider.RoleAssistant {
			continue
		}
		turns++
		keepFrom = i
		if turns == compactionKeepRecentTurns {
			break
		}
	}

	elided := false
	for i := 0; i < keepFrom && total > e.maxHistoryBytes; i++ {
		m := &e.history[i]
		if m.Role != provider.RoleTool || len(m.Content) <= compactionStubMaxLen {
			continue
		}
		stub := elideToolResult(m.Content)
		total -= len(m.Content) - len(stub)
		m.Content = stub
		elided = true
	}
	return elided
}

// compactionStubMaxLen is the size below which eliding a result reclaims
// less than the stub costs.
const compactionStubMaxLen = 512

// spillPointerMarker opens the "read it back with this" instruction that
// spillToolResult appends. Shared so elideToolResult recognizes the real
// pointer rather than a literal copied from it - rewording the template
// would otherwise silently drop the only route back to spilled output.
const spillPointerMarker = "read_file path="

// elideToolResult replaces a tool result with a note of what was there,
// preserving a spill pointer when the result had one - that line is how the
// model can still read the full output back.
func elideToolResult(content string) string {
	stub := fmt.Sprintf("[%d bytes of earlier tool output elided to fit the context window; re-run the tool if you need it]", len(content))
	// spillToolResult always appends its pointer as the trailing line.
	if last := content[strings.LastIndexByte(content, '\n')+1:]; strings.Contains(last, spillPointerMarker) {
		return stub + "\n" + last
	}
	return stub
}
