package autopilot

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium"
	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/skill"
	"github.com/vigolium/vigolium/pkg/olium/tool"
	"github.com/vigolium/vigolium/pkg/olium/toollog"
	"github.com/vigolium/vigolium/pkg/olium/vigtool"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// quotedLineWriter wraps an io.Writer and prepends prefix to every line
// it sees, tracking line state across calls so a delta that splits a
// line mid-word still produces one prefixed row. Used to render the
// agent's planning narration as a blockquote (`│ <text>`) so it reads
// as a sidebar alongside the `▶ tool` lines instead of inline text.
//
// Not safe for concurrent use; the autopilot loop drives it from a
// single goroutine.
type quotedLineWriter struct {
	w         io.Writer
	prefix    []byte
	atNewline bool
}

func newQuotedLineWriter(w io.Writer, prefix string) *quotedLineWriter {
	return &quotedLineWriter{w: w, prefix: []byte(prefix), atNewline: true}
}

// Write splits b on '\n' and emits the prefix at every line start. The
// trailing newline of any line is preserved so caller-side formatting
// (assistant text already containing `\n`) survives unchanged.
func (q *quotedLineWriter) Write(b []byte) (int, error) {
	written := 0
	for len(b) > 0 {
		if q.atNewline {
			if _, err := q.w.Write(q.prefix); err != nil {
				return written, err
			}
			q.atNewline = false
		}
		idx := bytes.IndexByte(b, '\n')
		if idx < 0 {
			n, err := q.w.Write(b)
			written += n
			return written, err
		}
		n, err := q.w.Write(b[:idx+1])
		written += n
		if err != nil {
			return written, err
		}
		q.atNewline = true
		b = b[idx+1:]
	}
	return written, nil
}

// Reset puts the writer back into "next byte starts a new line" mode.
// Called at the top of each turn so the planning header (printed
// directly to opts.Out, not through the wrapper) gets a fresh `│ ` on
// the first delta that follows.
func (q *quotedLineWriter) Reset() { q.atNewline = true }

// DefaultAutopilotMaxTurns is the fallback ceiling on engine turns when
// callers leave Options.MaxTurns at zero. It is deliberately much larger
// than the engine's own default (32 in pkg/olium/engine) and the
// OliumConfig.MaxTurns default (32, applied to non-autopilot uses like
// swarm phases and source analysis) — an autonomous audit chains many
// reconnaissance, validation, and reporting turns, so the patient ceiling
// is the right baseline. CLI --max-commands and the API MaxCommands field
// both override this on a per-run basis.
const DefaultAutopilotMaxTurns = 200

// Options configures an autopilot run.
type Options struct {
	// Provider and model for the underlying olium engine.
	Provider provider.Provider
	Model    string

	// What to audit. Target is the primary URL/hostname. SourcePath (if
	// non-empty) enables whitebox mode — the agent knows it has
	// filesystem access to local source code.
	Target     string
	SourcePath string

	// Scope optionally narrows the agent's attention (URL patterns,
	// paths, subsystems). Joined into the system prompt verbatim.
	Scope []string

	// Focus is a short operator-supplied directive, e.g. "prioritize
	// the authentication and payments flows". Empty = agent decides.
	Focus string

	// Instruction is extra text appended to the initial user prompt.
	Instruction string

	// Identifiers for DB persistence.
	ProjectUUID     string
	ScanUUID        string
	AgenticScanUUID string

	// Repo is the database handle used for finding persistence and the
	// run_scan / list_sessions / list_findings tools. *database.Repository
	// satisfies the FindingSink interface report_finding wants, plus
	// exposes the wider query surface vigtool needs.
	Repo *database.Repository

	// ConfigPath, when non-empty, is forwarded to runner.LaunchScan so
	// run_scan / run_extension load the same vigolium-configs.yaml the
	// outer CLI / server resolved. Empty falls back to default search.
	ConfigPath string

	// SessionDir is the on-disk directory for this run's artifacts
	// (~/.vigolium/agent-sessions/<run-uuid>/). When set, oversized tool
	// results spill into <SessionDir>/tool-results/ instead of being
	// head+tail truncated, and the model can read them back via
	// read_file. Empty disables spill — engine truncates in place.
	SessionDir string

	// MaxTurns caps the internal engine loop. 0 = DefaultAutopilotMaxTurns
	// (autopilot is intentionally patient; it decides when to halt). Note
	// this is independent of OliumConfig.MaxTurns in vigolium-configs.yaml,
	// which governs short non-autopilot engine uses (swarm phases, source
	// analysis). Autopilot's ceiling is deliberately higher because a real
	// audit needs many more tool turns than a single phase call.
	MaxTurns int

	// MaxWallTime is the hard ceiling on total run duration. When > 0,
	// the loop trips a halt with reason "wall-time budget exhausted" once
	// the wall clock crosses this threshold (checked between turns).
	// Zero means no wall-time cap — only MaxTurns and the model's own
	// halt_scan call bound the run.
	MaxWallTime time.Duration

	// TokenBudget is the hard ceiling on cumulative input+output tokens
	// (cache reads/writes are excluded since they don't bill the same
	// way). When > 0, the loop trips a halt once total tokens cross this
	// threshold. Zero means no token cap.
	TokenBudget int64

	// Out is where streaming assistant text is written. Default: stdout.
	Out io.Writer

	// ToolLog is where one-liner tool activity is written for operator
	// visibility. Default: stderr. Set to io.Discard to silence.
	ToolLog io.Writer

	// Verbose enables the per-tool result preview in the tool log. Off
	// by default to keep autopilot output concise; turn on for debug runs.
	Verbose bool

	// SystemPrompt, when non-empty, fully replaces the built-in autopilot
	// system prompt (persona + browser section). Use this for custom
	// agent personas where the caller wants total control over the
	// system message. Empty falls back to the embedded persona prompt
	// and conditional browser addendum.
	SystemPrompt string

	// BrowserAvailable signals that the agent-browser binary is on PATH
	// and `agent.browser.enable` is true. When set, the system prompt
	// gets a short addendum telling the model how to use the browser
	// surface (web_fetch mode=browser, browser_probe, agent-browser
	// SKILL.md). Off by default so blackbox HTTP-only runs stay terse.
	BrowserAvailable bool

	// InitialPrompt, when non-empty, replaces the auto-generated initial
	// user message entirely. Callers that have pre-assembled a richer
	// brief (e.g. the agent pipeline runner with audit findings + attack
	// plan + auth context) supply it here instead of relying on the
	// terse default framing.
	InitialPrompt string
}

// Result summarizes an autopilot run.
type Result struct {
	Halted       bool
	HaltReason   string
	FindingCount int64
	Elapsed      time.Duration

	// Cumulative token usage across every turn the engine emitted. Sourced
	// from the provider's per-turn Usage events; zero on providers that
	// don't report usage. Caller is responsible for pricing — Result stays
	// provider-neutral.
	InputTokens       int64
	OutputTokens      int64
	CacheReadTokens   int64
	CacheCreateTokens int64
}

// Run executes one autopilot session. It returns when the underlying
// engine's multi-turn loop completes — either because the model stopped
// calling tools, because halt_scan fired, or because MaxTurns was hit.
//
// Blocking. Honors ctx cancellation (engine teardown propagates).
func Run(ctx context.Context, opts Options) (*Result, error) {
	if opts.Provider == nil {
		return nil, fmt.Errorf("autopilot: Provider is required")
	}
	if opts.Target == "" && opts.SourcePath == "" {
		return nil, fmt.Errorf("autopilot: Target or SourcePath is required")
	}
	if opts.MaxTurns == 0 {
		opts.MaxTurns = DefaultAutopilotMaxTurns
	}
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	if opts.ToolLog == nil {
		opts.ToolLog = os.Stderr
	}

	// Skills: include ~/.vigolium/skills/ for autopilot (scan-specific
	// security workflows belong here). Warnings are surfaced to the
	// tool log but don't abort the run.
	skills, warnings := olium.LoadSkillsFor(true)
	for _, w := range warnings {
		_, _ = fmt.Fprintf(opts.ToolLog, "[autopilot] %s\n", w)
	}

	// Autopilot-specific tool wiring.
	halt := &HaltSignal{}
	reportCtx := &ReportFindingContext{
		Repo:            opts.Repo,
		ProjectUUID:     opts.ProjectUUID,
		ScanUUID:        opts.ScanUUID,
		AgenticScanUUID: opts.AgenticScanUUID,
		Target:          opts.Target,
	}

	// Working memory: a plan + note scratchpad that survives context
	// eviction (the engine never summarises — history grows until it hits
	// the provider ceiling). Seeds from the pipeline's frozen plan.json
	// when present, else starts blank for the agent to fill. Needs only the
	// session dir, so it's registered unconditionally — even target-only
	// CLI runs benefit.
	scratch := NewScratchpadContext(opts.SessionDir)

	tools := tool.NewRegistry()
	tool.RegisterBuiltins(tools, nil)
	tools.Register(NewHaltTool(halt))
	tools.Register(NewUpdatePlanTool(scratch))
	tools.Register(NewRememberTool(scratch))
	// Upgrade browser_probe and web_fetch to the capture-enabled variants
	// when a Repo + ProjectUUID are available. Without these, fetches are
	// invisible to query_records / inspect_record / replay_request — the
	// agent loads a page, walks away, and the next turn has nothing to scan.
	// With capture wired, every fetch produces an http_record the rest of
	// the toolchain can act on. browser_probe captures XHR/fetch traffic
	// via CDP under source="browser-probe"; web_fetch captures the
	// request/response itself under source="web-fetch" /
	// "web-fetch-browser".
	if opts.Repo != nil && opts.ProjectUUID != "" {
		tools.Register(tool.NewBrowserProbeWithCapture(opts.Repo, opts.ProjectUUID))
		tools.Register(tool.NewWebFetchWithCapture(opts.Repo, opts.ProjectUUID))
	}
	if opts.Repo != nil {
		tools.Register(NewReportFindingTool(reportCtx))

		// Vigolium-aware tools: scan launching, extension execution, and
		// session/finding queries. All require a real *database.Repository
		// (not just a FindingSink), so they're registered together under
		// the same opts.Repo guard.
		scanCtx := &vigtool.ScanContext{
			Repo:            opts.Repo,
			ProjectUUID:     opts.ProjectUUID,
			ConfigPath:      opts.ConfigPath,
			AgenticScanUUID: opts.AgenticScanUUID,
			Target:          opts.Target,
			Scope:           opts.Scope,
		}
		sessCtx := &vigtool.SessionsContext{
			Repo:        opts.Repo,
			ProjectUUID: opts.ProjectUUID,
		}
		tools.Register(vigtool.NewRunScanTool(scanCtx))
		tools.Register(vigtool.NewRunExtensionTool(scanCtx))
		tools.Register(vigtool.NewRunModuleTool(scanCtx))
		tools.Register(vigtool.NewListSessionsTool(sessCtx))
		tools.Register(vigtool.NewGetSessionTool(sessCtx))
		tools.Register(vigtool.NewListFindingsTool(sessCtx))
		tools.Register(vigtool.NewUpdateFindingTool(sessCtx))
		tools.Register(vigtool.NewListAuthSessionsTool(sessCtx))
		tools.Register(vigtool.NewAuthSessionLookupTool(sessCtx))
		// Record-driven attack surface: explore HTTP records, inspect
		// insertion points, fetch starter payloads, replay mutated requests,
		// and poll for OAST callbacks. Together these let the agent run a
		// targeted explore → inspect → craft → send → confirm loop without
		// having to fire a full run_scan every time.
		tools.Register(vigtool.NewQueryRecordsTool(sessCtx))
		tools.Register(vigtool.NewInspectRecordTool(sessCtx))
		tools.Register(vigtool.NewReplayRequestTool(sessCtx))
		tools.Register(vigtool.NewOASTPollTool(sessCtx))
		// send_raw_http: exact-bytes socket primitive for smuggling/desync/
		// CRLF that net/http normalises away. Hard-blocks out-of-scope
		// destinations via scanCtx.Target/Scope.
		tools.Register(vigtool.NewSendRawHTTPTool(scanCtx))
		// oast_mint: lazy-owns an interactsh Service so the agent can mint
		// its own canary for hand-crafted blind payloads (oast_poll only
		// reads). Deferred Shutdown gives late callbacks a grace window
		// before the client deregisters.
		mintTool := vigtool.NewOASTMintTool(scanCtx)
		tools.Register(mintTool)
		defer mintTool.Shutdown()
		tools.Register(vigtool.NewAttackKitTool())
		// browser_auth wraps agent-browser to drive interactive login flows
		// and persist the resulting cookies as an auth_session row. Only
		// registers when agent-browser is on PATH; otherwise the constructor
		// returns nil and the agent doesn't see the tool.
		if t := vigtool.NewBrowserAuthTool(opts.Repo, opts.ProjectUUID); t != nil {
			tools.Register(t)
		}
		tools.Register(vigtool.NewListModulesTool())
	}
	if skills != nil && skills.Len() > 0 {
		tools.Register(skill.NewLoadTool(skills))
	}

	eng := engine.New(engine.Config{
		Provider: opts.Provider,
		Tools:    tools,
		Skills:   skills,
		Model:    opts.Model,
		System:   buildSystemPrompt(opts),
		MaxTurns: opts.MaxTurns,
		// Autopilot runs many turns against a stable system prompt and
		// tool list; prompt caching cuts the repeated prefix tokens by
		// roughly 90% on Anthropic. No-op on providers that don't
		// implement it.
		EnablePromptCache: true,
		// Spill big tool outputs into the session dir so context stays
		// bounded but the full payload is recoverable on demand.
		SpillDir: opts.SessionDir,
		// Pin a scratchpad digest at the tail of every other tool result so
		// plan state survives long stretches of query/inspect/replay between
		// update_plan/remember calls (which already echo the full render).
		OnToolResult: func(toolName string, content string, isErr bool) string {
			if toolName == updatePlanToolName || toolName == rememberToolName {
				return content
			}
			digest := scratch.Digest()
			if digest == "" {
				return content
			}
			return content + digest
		},
	})

	initial := buildInitialPrompt(opts)

	// Derive a child context so MaxWallTime / TokenBudget enforcement can
	// trip cancellation independently of the caller. Cancelling the engine
	// ctx tears down the streaming provider and closes the events channel,
	// which is how we exit the run loop on budget exhaustion.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	started := time.Now()
	var deadline time.Time
	if opts.MaxWallTime > 0 {
		deadline = started.Add(opts.MaxWallTime)
	}

	events := eng.Run(runCtx, initial)

	// Split streams: tool lifecycle lines go to ToolLog (stderr by default)
	// while the per-turn `[turn done …]` usage line goes to Out (the
	// assistant text stream) so it always lands AFTER the model's message
	// — stdout/stderr can buffer independently and reorder otherwise.
	tlog := toollog.NewWithStreams(opts.ToolLog, opts.Out, opts.Verbose)

	// When running over Claude Code's CLI, engine-level tools never wire
	// in (the provider treats the CLI as a black-box LLM with its own
	// internal toolset). Install a stream parser that extracts inline
	// FINDING/HALT sentinel blocks from the model's text output and
	// dispatches them as if the report_finding / halt_scan tools had
	// fired. nil for every other provider — they get the normal tool path.
	var ccParser *claudeCodeBlockParser
	if isClaudeCodeProvider(opts.Provider) {
		ccParser = &claudeCodeBlockParser{
			onFinding: func(args map[string]any) {
				res := reportCtx.PersistFromArgs(runCtx, args)
				if res.IsError {
					_, _ = fmt.Fprintf(opts.ToolLog, "[claudecode] report_finding: %s\n", res.Message)
				} else {
					_, _ = fmt.Fprintf(opts.ToolLog, "[claudecode] %s\n", res.Message)
				}
			},
			onHalt: func(reason string) {
				if reason == "" {
					reason = "(no reason provided)"
				}
				halt.Set(reason)
			},
		}
	}

	var usage struct {
		in, out, cacheRead, cacheCreate int64
	}
	// hadTextThisTurn flips true on any non-empty EventTextDelta and
	// resets on EventTurnDone. Used to suppress the `[turn done ...]`
	// accounting line on silent tool-only turns — a lonely usage line
	// with no preceding narration just confuses the operator.
	hadTextThisTurn := false
	// Narration goes through a quoted-block writer so each line of the
	// planning text is rendered `│ <text>`, while the planning header,
	// tool calls, and [turn done] line keep writing directly to opts.Out
	// (no bar prefix). Reset on each new turn's first delta so a fresh
	// `│ ` lands after the header newline.
	quotedOut := newQuotedLineWriter(opts.Out, terminal.Muted("│ "))

	for ev := range events {
		// Tool exec lifecycle is always echoed on the tool log; the
		// per-turn usage line is gated on hadTextThisTurn below so we
		// don't print accounting lines out of nowhere. The text-delta
		// flag is flipped inside the switch (post-parser) rather than
		// here, so claude-code's FINDING/HALT blocks that the parser
		// consumes don't count as visible narration.
		tlog.HandleTool(ev)
		if ev.Type == engine.EventTurnDone {
			if ev.Usage != nil {
				usage.in += int64(ev.Usage.Input)
				usage.out += int64(ev.Usage.Output)
				usage.cacheRead += int64(ev.Usage.CacheRead)
				usage.cacheCreate += int64(ev.Usage.CacheWrite)
			}
			if hadTextThisTurn {
				tlog.HandleTurn(ev)
			}
			hadTextThisTurn = false
		}

		// Drain-time halt check. The halt_scan tool flips the signal during
		// tool dispatch (between EventTurnDone of turn N and the next
		// streamOnce); cancelling here makes the engine's next iteration
		// observe ctx.Done() and emit EventError, which the EventError arm
		// below converts into a clean Result with HaltReason. Without this,
		// the engine would pay for another LLM round-trip before noticing
		// the model wanted to stop. Idempotent: budget enforcement (below)
		// already cancel()s on its own.
		if halted, _ := halt.Halted(); halted && runCtx.Err() == nil {
			cancel()
		}

		switch ev.Type {
		case engine.EventTextDelta:
			delta := ev.Delta
			if ccParser != nil {
				delta = ccParser.Feed(delta)
			}
			if delta != "" {
				if !hadTextThisTurn {
					// First visible text in this turn — frame the
					// narration with a header so it reads like the
					// `▶ tool` lines (planning is just another step).
					// Header writes directly to opts.Out (no `│ `);
					// the quote writer's reset puts the first byte of
					// the body on a fresh line so the bar lands cleanly.
					_, _ = fmt.Fprintf(opts.Out, "\n%s %s\n",
						terminal.BoldGreen(terminal.SymbolRunning),
						terminal.BoldGreen("planning"))
					quotedOut.Reset()
					hadTextThisTurn = true
				}
				_, _ = quotedOut.Write([]byte(delta))
			}

		case engine.EventTurnDone:
			// Budget enforcement runs after each turn. Tripping the halt
			// signal AND cancelling runCtx covers both paths: the engine
			// teardown drains, and Result reflects why we stopped.
			if !deadline.IsZero() && time.Now().After(deadline) {
				reason := fmt.Sprintf("wall-time budget exhausted after %s (cap=%s)",
					time.Since(started).Round(time.Second), opts.MaxWallTime)
				halt.Set(reason)
				_, _ = fmt.Fprintf(opts.ToolLog, "[%s]\n", reason)
				cancel()
			}
			if opts.TokenBudget > 0 && usage.in+usage.out > opts.TokenBudget {
				reason := fmt.Sprintf("token budget exhausted (used=%d, cap=%d)",
					usage.in+usage.out, opts.TokenBudget)
				halt.Set(reason)
				_, _ = fmt.Fprintf(opts.ToolLog, "[%s]\n", reason)
				cancel()
			}

		case engine.EventRunDone:
			// natural completion — handled by loop exit

		case engine.EventError:
			// Drain any pending sentinel tail to stdout so the operator
			// isn't left missing model output. Errors short-circuit the
			// loop, so do it here as well as after the loop exits.
			if ccParser != nil {
				if tail := ccParser.Flush(); tail != "" {
					_, _ = io.WriteString(opts.Out, tail)
				}
			}
			// If we already tripped the halt signal (budget enforcement,
			// halt_scan tool, caller cancellation observed earlier), the
			// resulting "context canceled" engine event is expected — treat
			// it as a clean run termination so Result reflects the real
			// reason, not a spurious error.
			if halted, reason := halt.Halted(); halted {
				return &Result{
					Halted:            true,
					HaltReason:        reason,
					FindingCount:      reportCtx.Count.Load(),
					Elapsed:           time.Since(started),
					InputTokens:       usage.in,
					OutputTokens:      usage.out,
					CacheReadTokens:   usage.cacheRead,
					CacheCreateTokens: usage.cacheCreate,
				}, nil
			}
			return &Result{
				FindingCount:      reportCtx.Count.Load(),
				Elapsed:           time.Since(started),
				InputTokens:       usage.in,
				OutputTokens:      usage.out,
				CacheReadTokens:   usage.cacheRead,
				CacheCreateTokens: usage.cacheCreate,
			}, fmt.Errorf("autopilot engine: %s", ev.Err)
		}
	}

	// Flush any held sentinel tail. Normally Feed consumes everything but
	// a model that ends mid-block (no <<<VIG:END>>>) would leave bytes
	// buffered; surfacing them helps debug prompt drift.
	if ccParser != nil {
		if tail := ccParser.Flush(); tail != "" {
			_, _ = io.WriteString(opts.Out, tail)
		}
	}
	_, _ = fmt.Fprintln(opts.Out) // terminating newline after streamed text

	halted, reason := halt.Halted()
	return &Result{
		Halted:            halted,
		HaltReason:        reason,
		FindingCount:      reportCtx.Count.Load(),
		Elapsed:           time.Since(started),
		InputTokens:       usage.in,
		OutputTokens:      usage.out,
		CacheReadTokens:   usage.cacheRead,
		CacheCreateTokens: usage.cacheCreate,
	}, nil
}
