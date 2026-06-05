package autopilot

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vigolium/vigolium/internal/config"
	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/olium"
	"github.com/vigolium/vigolium/pkg/olium/engine"
	"github.com/vigolium/vigolium/pkg/olium/provider"
	"github.com/vigolium/vigolium/pkg/olium/sessionlog"
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

// autopilotEmptyTurnNudge is the user-role reminder appended after a
// text-only turn (no tool_calls). Names halt_scan explicitly so the model
// has both a "resume work" and a "stop cleanly" path described in one
// sentence — the generic engine default doesn't know about autopilot's
// halt tool by name.
const autopilotEmptyTurnNudge = "You produced text but did not call any tool. The autopilot loop only progresses when you invoke a tool. If you are genuinely done, call halt_scan with a one-line reason. Otherwise pick the next concrete step (run_scan to scan natively, browser_probe or web_fetch to populate http_records, query_records to re-inspect what's already there, report_finding if you have evidence) and invoke it now. Do not respond with prose alone."

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

	// Skill selection (planner-driven loading). When SkillNames/SkillTags are
	// set, they force-include those skills and bypass the pre-flight selection.
	// NoSkillFilter loads the full set. AlwaysOnSkills are kept regardless of
	// selection (empty falls back to config.DefaultAlwaysOnSkills).
	SkillNames     []string
	SkillTags      []string
	NoSkillFilter  bool
	AlwaysOnSkills []string

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

	// PostHaltVerify enables the post-halt coverage verification loop. When
	// true AND CoverageProbe is set, after the model calls halt_scan the
	// loop runs CoverageProbe.Run(ctx), diffs the discovered route set
	// against a snapshot taken at run start, and re-enters the engine with
	// a follow-up user prompt when the gap meets PostHaltGapThreshold.
	// Off by default — callers (typically the pipeline runner) opt in.
	PostHaltVerify bool

	// PostHaltGapThreshold is the minimum number of new (method, URL)
	// signatures the coverage probe must turn up before a re-entry fires.
	// 0 falls back to defaultPostHaltGapThreshold (5).
	PostHaltGapThreshold int

	// CoverageProbe is the probe used to verify coverage after halt. The
	// pipeline runner builds one from the autopilot's Repo + ProjectUUID +
	// Target; direct CLI callers can leave it nil to disable post-halt
	// verification regardless of PostHaltVerify. Must be safe to call
	// multiple times — Run snapshots its own before/after each invocation.
	CoverageProbe interface {
		Run(ctx context.Context) (*CoverageProbeResultLite, error)
		SnapshotSignatures(ctx context.Context) ([]string, error)
	}
}

// CoverageProbeResultLite is the slice of CoverageProbeResult autopilot.Run
// cares about. Defined here so the autopilot package doesn't have to import
// pkg/agent (which would create a cycle — pkg/agent already imports this
// package). The pipeline runner injects an adapter.
type CoverageProbeResultLite struct {
	NewSignatures []string
}

const (
	defaultPostHaltGapThreshold = 5
	// maxPostHaltReentries caps how many post-halt re-entries a single run
	// can fire. One re-entry is enough to surface the gap to the model; a
	// second pass rarely turns up novel routes and just burns LLM turns
	// against the wall-time / token budget.
	maxPostHaltReentries = 1
)

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

	// Reentries counts how many times the post-halt coverage verification
	// loop re-prompted the agent. 0 = no verification re-entry fired (most
	// runs); ≥1 = the coverage probe surfaced enough new endpoints that
	// the loop nudged the model to continue. Capped at maxPostHaltReentries.
	Reentries int
}

// skillTag is the muted "❯ autopilot │" phase prefix shared by the skill log
// lines — matches the native-scan phase output style (terminal.PhasePrefix).
// Colors auto-disable when the tool log is not a TTY (or NO_COLOR is set).
func skillTag() string { return terminal.PhasePrefix("autopilot") }

// logSkillsLoaded prints a one-line, color-highlighted summary of the skills
// available to the agent: the total plus a per-source *count* breakdown. Skill
// names are deliberately not enumerated here — they show up only on the
// "selected" line (logSkillsSelected) so the operator sees exactly what was
// loaded for the target instead of a wall of names up front. A source missing
// from the breakdown (count 0) makes a mis-placed or empty skill folder
// obvious at a glance.
func logSkillsLoaded(w io.Writer, skills *skill.Registry) {
	if skills == nil || skills.Len() == 0 {
		_, _ = fmt.Fprintf(w, "%s loaded %s skills\n", skillTag(), terminal.BoldYellow("0"))
		return
	}
	bySource := map[skill.Source]int{}
	for _, s := range skills.List() {
		bySource[s.Source]++
	}
	parts := make([]string, 0, 4)
	for _, src := range []skill.Source{
		skill.SourceProjectAgents,
		skill.SourceProjectClaude,
		skill.SourceUserVigolium,
		skill.SourceEmbedded,
	} {
		if n := bySource[src]; n > 0 {
			// source name muted, count highlighted — the count is the point.
			parts = append(parts, fmt.Sprintf("%s: %s", terminal.Muted(string(src)), terminal.Cyan(fmt.Sprintf("%d", n))))
		}
	}
	_, _ = fmt.Fprintf(w, "%s loaded %s skills (%s)\n",
		skillTag(), terminal.BoldCyan(fmt.Sprintf("%d", skills.Len())), strings.Join(parts, ", "))
}

// skillsPerLine caps how many skill names print on one continuation line so a
// large selected set wraps instead of running off the right edge of the
// terminal.
const skillsPerLine = 4

// logSkillsSelected prints which skills survived planner-driven filtering,
// color-highlighted, and is the only place skill *names* are listed. The names
// wrap at skillsPerLine per line (each line re-stamped with the phase prefix)
// so a dozen-skill set stays readable. A no-op when filtering didn't reduce the
// set (selected == all) so unfiltered runs stay quiet.
func logSkillsSelected(w io.Writer, all, selected *skill.Registry) {
	if selected == nil || all == nil || selected.Len() == 0 || selected.Len() == all.Len() {
		return
	}
	// Header line carries the counts; names follow on wrapped continuation
	// lines below it.
	_, _ = fmt.Fprintf(w, "%s selected %s of %s skills for this target:\n",
		skillTag(),
		terminal.BoldGreen(fmt.Sprintf("%d", selected.Len())),
		terminal.BoldCyan(fmt.Sprintf("%d", all.Len())))

	names := selected.Names()
	for i := 0; i < len(names); i += skillsPerLine {
		end := min(i+skillsPerLine, len(names))
		chunk := names[i:end]
		colored := make([]string, len(chunk))
		for j, n := range chunk {
			colored[j] = terminal.Cyan(n)
		}
		line := strings.Join(colored, ", ")
		if end < len(names) {
			line += "," // trailing comma signals the list continues on the next line
		}
		_, _ = fmt.Fprintf(w, "%s   %s\n", skillTag(), line)
	}
}

// logSkillsTip nudges the operator toward the skill-selection knobs. Shown
// only when no explicit override is in play — a run that already passed
// --skill / --skill-tag / --no-skill-filter doesn't need the hint. A no-op
// when no skills are loaded at all.
func logSkillsTip(w io.Writer, opts Options, skills *skill.Registry) {
	if skills == nil || skills.Len() == 0 {
		return
	}
	if opts.NoSkillFilter || len(opts.SkillNames) > 0 || len(opts.SkillTags) > 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "%s %s pick exact skills with %s, by tag with %s, or skip filtering (load all) with %s\n",
		skillTag(),
		terminal.TipPrefix(),
		terminal.Yellow("--skill <name>"),
		terminal.Yellow("--skill-tag <tag>"),
		terminal.Yellow("--no-skill-filter"))
}

// selectAutopilotSkills returns the skill subset to surface to the operator
// agent. Resolution order: --no-skill-filter → full set; --skill/--skill-tag →
// operator override (∪ always-on); otherwise a best-effort pre-flight LLM pick
// (∪ always-on). Any failure or empty result falls back to the full set so a
// long autonomous run never loses access to a skill it might need.
func selectAutopilotSkills(ctx context.Context, opts Options, all *skill.Registry) *skill.Registry {
	if all == nil || all.Len() == 0 || opts.NoSkillFilter {
		return all
	}
	alwaysOn := opts.AlwaysOnSkills
	if len(alwaysOn) == 0 {
		alwaysOn = config.DefaultAlwaysOnSkills
	}

	logWarn := func(warnings []string) {
		for _, w := range warnings {
			_, _ = fmt.Fprintf(opts.ToolLog, "%s %s\n", skillTag(), w)
		}
	}

	// Operator hard override bypasses the LLM pre-flight entirely.
	if len(opts.SkillNames) > 0 || len(opts.SkillTags) > 0 {
		sel, warnings := all.Select(skill.SelectOptions{
			Forced:     opts.SkillNames,
			ForcedTags: opts.SkillTags,
			AlwaysOn:   alwaysOn,
		})
		logWarn(warnings)
		if sel == nil || sel.Len() == 0 {
			return all
		}
		return sel
	}

	picks := preflightSkillPicks(ctx, opts, all)
	if len(picks) == 0 {
		return all // pre-flight unavailable/empty — keep everything
	}
	sel, warnings := all.Select(skill.SelectOptions{Picks: picks, AlwaysOn: alwaysOn})
	logWarn(warnings)
	if sel == nil || sel.Len() == 0 {
		return all
	}
	return sel
}

// preflightSkillPicks runs one cheap, tool-less model call that maps the target
// to matching skill names from the menu. Returns only names that resolve to a
// registered skill; returns nil on any error (the caller then keeps the full
// set). Bounded by a 60s timeout so a hung provider can't stall startup.
func preflightSkillPicks(ctx context.Context, opts Options, all *skill.Registry) []string {
	if opts.Provider == nil {
		return nil
	}
	var menu strings.Builder
	for _, s := range all.List() {
		fmt.Fprintf(&menu, "- %s", s.Name)
		if len(s.Tags) > 0 {
			fmt.Fprintf(&menu, " [tags: %s]", strings.Join(s.Tags, ", "))
		}
		fmt.Fprintf(&menu, ": %s\n", s.Description)
	}

	sys := "You are a security-scan planner. You are given a target and a menu of skills " +
		"(confirmation/escalation playbooks). Output ONLY the names of the skills whose description " +
		"or tags match this target's likely attack surface — comma-separated, names only, no prose. " +
		"When unsure, include a skill rather than omit it. Output nothing if none clearly apply."

	var user strings.Builder
	fmt.Fprintf(&user, "Target: %s\n", opts.Target)
	if opts.SourcePath != "" {
		user.WriteString("Application source code is available locally (whitebox).\n")
	}
	if opts.Focus != "" {
		fmt.Fprintf(&user, "Operator focus: %s\n", opts.Focus)
	}
	if len(opts.Scope) > 0 {
		fmt.Fprintf(&user, "Scope: %s\n", strings.Join(opts.Scope, ", "))
	}
	fmt.Fprintf(&user, "\nAvailable skills:\n%s\nReturn the matching skill names, comma-separated.", menu.String())

	eng := engine.New(engine.Config{Provider: opts.Provider, Model: opts.Model, System: sys, MaxTurns: 1})
	selCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	var text strings.Builder
	for ev := range eng.Run(selCtx, user.String()) {
		switch ev.Type {
		case engine.EventTextDelta:
			text.WriteString(ev.Delta)
		case engine.EventError:
			return nil
		}
	}

	// Extract name-like tokens ([a-z0-9-]) and keep those that resolve to a
	// registered skill — robust to the model wrapping names in backticks,
	// bullets, or trailing prose.
	lower := strings.ToLower(text.String())
	seen := map[string]bool{}
	var picks []string
	isNameRune := func(r rune) bool {
		return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-'
	}
	for _, tok := range strings.FieldsFunc(lower, func(r rune) bool { return !isNameRune(r) }) {
		if !seen[tok] && all.Get(tok) != nil {
			seen[tok] = true
			picks = append(picks, tok)
		}
	}
	return picks
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
	allSkills, warnings := olium.LoadSkillsFor(true)
	for _, w := range warnings {
		_, _ = fmt.Fprintf(opts.ToolLog, "%s %s\n", skillTag(), w)
	}
	logSkillsLoaded(opts.ToolLog, allSkills)

	// Planner-driven filtering: pick the subset relevant to this target (or
	// honor operator overrides). Best-effort — any failure falls back to the
	// full set, so a long autonomous run is never starved of a skill.
	skills := selectAutopilotSkills(ctx, opts, allSkills)
	logSkillsSelected(opts.ToolLog, allSkills, skills)
	logSkillsTip(opts.ToolLog, opts, allSkills)

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

	ecfg := engine.Config{
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
		// Small open-weight models (gemma, llama-3-instruct, etc.) routinely
		// produce a text-only turn after the first empty query response and
		// the engine would otherwise exit on the spot ("natural stop"). Two
		// consecutive nudges give the model a chance to either kick off
		// run_scan/browser_probe to populate records or admit it's done by
		// calling halt_scan. Capable models that genuinely have nothing left
		// to do almost always halt on the first nudge — one round of waste.
		NudgeOnEmptyToolCalls: 2,
		NudgeOnEmptyMessage:   autopilotEmptyTurnNudge,
	}

	// Persist a Pi-style JSONL transcript beside the other session artifacts
	// (runtime.log, scratchpad, tool-results/) for post-hoc debugging. Only
	// attach when we have a session dir; a recorder construction failure is
	// non-fatal — the scan proceeds without a transcript.
	if opts.SessionDir != "" {
		provName := ""
		if opts.Provider != nil {
			provName = opts.Provider.Name()
		}
		cwd, _ := os.Getwd()
		if rec, rerr := sessionlog.New(filepath.Join(opts.SessionDir, sessionlog.Filename), sessionlog.Meta{
			SessionID: filepath.Base(opts.SessionDir),
			Provider:  provName,
			Model:     opts.Model,
			Cwd:       cwd,
		}); rerr == nil {
			ecfg.Recorder = rec
		}
	}

	eng := engine.New(ecfg)
	// Flush + close the transcript when the run ends. No-op when no recorder
	// was attached.
	defer func() { _ = eng.CloseRecorder() }()

	initial := buildInitialPrompt(opts)

	// Each engine iteration derives its own child context inside
	// runIteration so MaxWallTime / TokenBudget enforcement can cancel
	// the current iteration without aborting a future re-entry that
	// should inherit the operator's outer ctx. runCtx is updated per
	// iteration and read by the ccParser closure — captured by pointer
	// so the closure sees the current iteration's context.
	var runCtx context.Context

	started := time.Now()
	var deadline time.Time
	if opts.MaxWallTime > 0 {
		deadline = started.Add(opts.MaxWallTime)
	}

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
				// runCtx is reassigned across re-entries; capturing it by
				// closure is fine because PersistFromArgs only reads ctx
				// during the call (no goroutine retains it).
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
				halt.SetByModel(reason)
			},
		}
	}

	var usage struct {
		in, out, cacheRead, cacheCreate int64
	}
	// Narration goes through a quoted-block writer so each line of the
	// planning text is rendered `│ <text>`, while the planning header,
	// tool calls, and [turn done] line keep writing directly to opts.Out
	// (no bar prefix). Reset on each new turn's first delta so a fresh
	// `│ ` lands after the header newline.
	quotedOut := newQuotedLineWriter(opts.Out, terminal.Muted("│ "))

	// Coverage-verify settings. CoverageProbe nil = verification disabled
	// regardless of PostHaltVerify, so the rest of the loop can ignore
	// nil-checks below.
	gapThreshold := opts.PostHaltGapThreshold
	if gapThreshold == 0 {
		gapThreshold = defaultPostHaltGapThreshold
	}
	verifyEnabled := opts.PostHaltVerify && opts.CoverageProbe != nil

	// Original halt reason from the first time the model called halt_scan.
	// Preserved across re-entries so the final Result reports the canonical
	// "why we initially stopped" rather than the re-entry's halt reason.
	firstHaltReason := ""
	reentries := 0
	nextPrompt := initial

	// runIteration drains one full engine.Run cycle and returns (fatalErr,
	// fatalResult). Each call owns its own cancellable context via defer
	// iterCancel, so go vet's lostcancel check is satisfied even when the
	// outer loop re-enters. runCtx is reassigned per iteration so the
	// ccParser closure (built outside this loop) sees the current ctx.
	runIteration := func(prompt string) (*Result, error) {
		iterCtx, iterCancel := context.WithCancel(ctx)
		defer iterCancel()
		runCtx = iterCtx

		events := eng.Run(iterCtx, prompt)

		// hadTextThisTurn flips true on any non-empty EventTextDelta and
		// resets on EventTurnDone. Local to each iteration so a re-entry
		// starts with no narration carry-over.
		hadTextThisTurn := false

		var runLoopErr error
		var fatalResult *Result

		for ev := range events {
			// Tool exec lifecycle is always echoed on the tool log; the
			// per-turn usage line is gated on hadTextThisTurn below so we
			// don't print accounting lines out of nowhere. The text-delta
			// flag is flipped inside the switch (post-parser) rather than
			// here, so claude-code's FINDING/HALT blocks that the parser
			// consumes don't count as visible narration.
			tlog.HandleTool(ev)
			// Reasoning deltas accumulate in the logger and flush as one muted
			// `⋈ thinking` block on the tool log (stderr) — before the turn's
			// first tool card (via start()) or, for a pure planning turn,
			// before the assistant narration prints below. Gated on --verbose
			// inside the logger; a no-op otherwise.
			tlog.HandleThinking(ev)
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
			// below converts into a clean run termination. Without this,
			// the engine would pay for another LLM round-trip before noticing
			// the model wanted to stop. Idempotent: budget enforcement (below)
			// already cancel()s on its own.
			if halted, _ := halt.Halted(); halted && iterCtx.Err() == nil {
				iterCancel()
			}

			switch ev.Type {
			case engine.EventTextDelta:
				delta := ev.Delta
				if ccParser != nil {
					delta = ccParser.Feed(delta)
				}
				if delta != "" {
					if !hadTextThisTurn {
						// Flush any buffered reasoning before the narration so
						// the operator reads think → answer (this turn had no
						// tool card to trigger the flush via start()).
						tlog.FlushThinking()
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
				// signal AND cancelling iterCtx covers both paths: the engine
				// teardown drains, and Result reflects why we stopped.
				if !deadline.IsZero() && time.Now().After(deadline) {
					reason := fmt.Sprintf("wall-time budget exhausted after %s (cap=%s)",
						time.Since(started).Round(time.Second), opts.MaxWallTime)
					halt.SetByBudget(reason)
					_, _ = fmt.Fprintf(opts.ToolLog, "[%s]\n", reason)
					iterCancel()
				}
				if opts.TokenBudget > 0 && usage.in+usage.out > opts.TokenBudget {
					reason := fmt.Sprintf("token budget exhausted (used=%d, cap=%d)",
						usage.in+usage.out, opts.TokenBudget)
					halt.SetByBudget(reason)
					_, _ = fmt.Fprintf(opts.ToolLog, "[%s]\n", reason)
					iterCancel()
				}

			case engine.EventInfo:
				// Non-fatal engine notice (e.g. transient stream-error retry).
				// Surface on the tool log so the operator sees what happened
				// without polluting the assistant narration stream.
				if ev.Delta != "" {
					_, _ = fmt.Fprintf(opts.ToolLog, "[%s]\n", ev.Delta)
				}

			case engine.EventRunDone:
				// natural completion — handled by loop exit

			case engine.EventError:
				// Drain any pending sentinel tail to stdout so the operator
				// isn't left missing model output. Errors short-circuit the
				// inner loop; flush here as well as after the outer loop
				// since some error paths return without re-entering.
				if ccParser != nil {
					if tail := ccParser.Flush(); tail != "" {
						_, _ = io.WriteString(opts.Out, tail)
					}
				}
				// If we already tripped the halt signal (budget enforcement,
				// halt_scan tool, caller cancellation observed earlier), the
				// resulting "context canceled" engine event is expected — let
				// the outer loop's post-halt logic decide what to do next.
				if halted, _ := halt.Halted(); !halted {
					fatalResult = &Result{
						FindingCount:      reportCtx.Count.Load(),
						Elapsed:           time.Since(started),
						InputTokens:       usage.in,
						OutputTokens:      usage.out,
						CacheReadTokens:   usage.cacheRead,
						CacheCreateTokens: usage.cacheCreate,
					}
					runLoopErr = fmt.Errorf("autopilot engine: %s", ev.Err)
				}
				// Drain any remaining events so the channel close cleanly;
				// engine close is the inner loop's natural exit signal.
			}
		}

		return fatalResult, runLoopErr
	}

	for {
		fatalResult, runLoopErr := runIteration(nextPrompt)
		if runLoopErr != nil {
			return fatalResult, runLoopErr
		}

		// Inner loop exited cleanly — decide whether to re-enter.
		halted, reason := halt.Halted()
		if !halted {
			// Engine stopped on its own (e.g. NudgeOnEmptyToolCalls exhausted)
			// without a halt signal. Treat as natural completion; no
			// verification re-entry because there's no model-driven halt to
			// double-check.
			break
		}
		haltSrc := halt.Source()
		if !verifyEnabled || haltSrc != HaltSourceModel || reentries >= maxPostHaltReentries {
			break
		}

		// Run the coverage probe; on any error or below-threshold gap we
		// accept the halt as final. The probe is allowed to be slow (it
		// runs a discovery scan), so use the outer ctx — not the cancelled
		// runCtx — so the operator can still abort.
		_, _ = fmt.Fprintf(opts.ToolLog, "[autopilot] halt observed — running coverage verification probe\n")
		probeRes, probeErr := opts.CoverageProbe.Run(ctx)
		if probeErr != nil {
			_, _ = fmt.Fprintf(opts.ToolLog, "[autopilot] coverage probe failed: %v (accepting halt)\n", probeErr)
			break
		}
		if probeRes == nil || len(probeRes.NewSignatures) < gapThreshold {
			gapCount := 0
			if probeRes != nil {
				gapCount = len(probeRes.NewSignatures)
			}
			_, _ = fmt.Fprintf(opts.ToolLog, "[autopilot] coverage gap below threshold (%d < %d) — accepting halt\n", gapCount, gapThreshold)
			break
		}

		// Re-entry: preserve the original halt reason, reset the signal,
		// build a follow-up prompt that names the gap, and loop. The
		// previous iteration's context is already cancelled by
		// runIteration's deferred iterCancel — no cleanup needed here.
		if firstHaltReason == "" {
			firstHaltReason = reason
		}
		_, _ = fmt.Fprintf(opts.ToolLog, "[autopilot] coverage probe found %d new endpoint(s) — re-entering agent (%d/%d)\n",
			len(probeRes.NewSignatures), reentries+1, maxPostHaltReentries)
		halt.Reset()
		nextPrompt = formatCoverageGapPrompt(probeRes.NewSignatures)
		reentries++
	}

	// Flush any reasoning buffered by a final turn that produced neither a
	// tool card nor narration (rare, but otherwise it would be silently
	// dropped at run end).
	tlog.FlushThinking()

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
	// When a verification re-entry fired, surface BOTH the original halt
	// reason and the post-verification reason so the operator can see what
	// the model thought before and after the probe.
	finalReason := reason
	if firstHaltReason != "" && firstHaltReason != reason {
		finalReason = fmt.Sprintf("%s (post-verify: %s)", firstHaltReason, reason)
	}
	return &Result{
		Halted:            halted,
		HaltReason:        finalReason,
		FindingCount:      reportCtx.Count.Load(),
		Elapsed:           time.Since(started),
		InputTokens:       usage.in,
		OutputTokens:      usage.out,
		CacheReadTokens:   usage.cacheRead,
		CacheCreateTokens: usage.cacheCreate,
		Reentries:         reentries,
	}, nil
}

// formatCoverageGapPrompt builds the user-role message the engine sees on a
// post-halt re-entry. Kept in-package so we don't depend on pkg/agent (which
// imports us). The pkg/agent FormatGapForPrompt helper has the same shape
// but lives there for callers building prompts outside the engine loop.
func formatCoverageGapPrompt(gap []string) string {
	if len(gap) == 0 {
		return ""
	}
	const capItems = 30
	shown := gap
	truncated := false
	if len(shown) > capItems {
		shown = shown[:capItems]
		truncated = true
	}
	var b strings.Builder
	fmt.Fprintf(&b, "You called halt_scan, but a verification discovery pass found %d endpoint(s) ", len(gap))
	b.WriteString("that were not in the project when you halted. ")
	b.WriteString("These are routes you either never investigated or that only became visible after the verification pass:\n\n")
	for _, sig := range shown {
		fmt.Fprintf(&b, "- `%s`\n", sig)
	}
	if truncated {
		fmt.Fprintf(&b, "\n(showing first %d of %d — call `query_records` for the full list)\n", capItems, len(gap))
	}
	b.WriteString("\nDecide for each: investigate (run_native_scan / replay_request / inspect_record) ")
	b.WriteString("or skip with justification (out of scope, duplicate surface, static asset). ")
	b.WriteString("When you've handled them all, call halt_scan again with an updated reason.")
	return b.String()
}
