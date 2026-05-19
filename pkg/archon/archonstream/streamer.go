// Package archonstream decodes archon-ts's NDJSON output format (emitted
// when the binary is invoked with `--json`) and renders it as a compact,
// colored activity feed suitable for a terminal. The stream also carries
// the totalUsd / totalTokens / findings summary in a final `result`
// event, which Stream returns to the caller for cost reporting.
package archonstream

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const (
	colorReset   = "\033[0m"
	colorDim     = "\033[2m"
	colorBold    = "\033[1m"
	colorCyan    = "\033[36m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorMagenta = "\033[35m"
	colorBlue    = "\033[34m"
	colorGray    = "\033[90m"
	colorRed     = "\033[31m"
)

// maxToolArgsLen caps the inline JSON rendering of tool arguments.
const maxToolArgsLen = 180

// maxTextLen caps individual text lines so one verbose block doesn't flood the terminal.
const maxTextLen = 400

// Options controls how Stream renders output.
type Options struct {
	// ShowThinking renders thinking blocks (dim). Off by default — they are very noisy.
	ShowThinking bool
	// RawLog, if non-nil, receives every raw JSON line (with trailing newline) for replay.
	RawLog io.Writer
}

// Tokens mirrors the {input, output} pair archon emits in `result` and
// `phaseEnd` events.
type Tokens struct {
	Input  int64 `json:"input"`
	Output int64 `json:"output"`
}

// Findings mirrors the {total, bySeverity} aggregate archon emits in
// `auditEnd` and `result`. Severity keys follow archon's own casing
// (Critical/High/Medium/Low/Info) — callers normalize when persisting.
type Findings struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"bySeverity"`
}

// Result captures the final `result` NDJSON event archon emits at the
// end of a run. Empty when the stream ended before the result arrived
// (e.g. process killed mid-run).
type Result struct {
	AuditID       string   `json:"auditId"`
	Status        string   `json:"status"`
	TotalUSD      float64  `json:"totalUsd"`
	TotalTokens   Tokens   `json:"totalTokens"`
	Findings      Findings `json:"findings"`
	FailedPhases  []string `json:"failedPhases"`
	SkippedPhases []string `json:"skippedPhases"`
}

// IsZero reports whether the Result was never populated (no `result`
// event observed). Used by callers to decide whether to fall back to
// the audit-state.json file for a phase summary.
func (r Result) IsZero() bool {
	return r.AuditID == "" && r.Status == "" && r.TotalUSD == 0 &&
		r.TotalTokens.Input == 0 && r.TotalTokens.Output == 0 &&
		r.Findings.Total == 0
}

// accumulate folds a later `result` event into the running total. A
// chained `archon run --modes a,b,c` emits one `result` per mode; the
// caller wants the aggregate, not just the last leg. Cost and token
// counts are additive across modes. AuditID / Status / FailedPhases /
// SkippedPhases reflect the most recent (final) mode. Findings.Total is
// taken as the max seen — archon's findings/ dir is cumulative across
// chained modes, so the last/most-complete snapshot wins and we never
// double-count by summing per-mode cumulative totals.
func (r Result) accumulate(next Result) Result {
	if r.IsZero() {
		return next
	}
	merged := next // AuditID/Status/Failed/Skipped = latest leg
	merged.TotalUSD = r.TotalUSD + next.TotalUSD
	merged.TotalTokens.Input = r.TotalTokens.Input + next.TotalTokens.Input
	merged.TotalTokens.Output = r.TotalTokens.Output + next.TotalTokens.Output
	merged.Findings = next.Findings
	if r.Findings.Total > merged.Findings.Total {
		merged.Findings = r.Findings
	}
	return merged
}

// Stream reads newline-delimited JSON events from r, renders a
// human-readable feed to w, and mirrors every raw line to opts.RawLog
// when set. Returns the final `result` event observed (or zero value
// when the stream ended before one arrived) along with any read error.
// Individual malformed lines are surfaced as dim warnings and skipped.
func Stream(r io.Reader, w io.Writer, opts Options) (Result, error) {
	scanner := bufio.NewScanner(r)
	// archon NDJSON lines can be large — toolResult events embed file
	// excerpts, knowledge-base prompts, etc. Match claudestream's budget.
	buf := make([]byte, 0, 1<<20)
	scanner.Buffer(buf, 16<<20) // up to 16 MiB per line

	var result Result

	for scanner.Scan() {
		line := scanner.Bytes()
		if opts.RawLog != nil {
			_, _ = opts.RawLog.Write(line)
			_, _ = opts.RawLog.Write([]byte("\n"))
		}

		trimmed := trimLeftSpace(line)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			continue
		}

		var env envelope
		if err := json.Unmarshal(line, &env); err != nil {
			_, _ = fmt.Fprintf(w, "%s[?] unparseable event: %s%s\n", colorGray, truncate(string(line), 160), colorReset)
			continue
		}

		switch env.Kind {
		case "auditStart":
			renderAuditStart(w, env)
		case "phaseStart":
			renderPhaseStart(w, env)
		case "phaseEnd":
			renderPhaseEnd(w, env)
		case "phaseAdapterEvent":
			renderAdapterEvent(w, env, opts)
		case "findingDiscovered":
			renderFindingDiscovered(w, env)
		case "auditEnd":
			renderAuditEnd(w, env)
		case "result":
			renderResult(w, env)
			// Re-decode into the typed Result — the envelope drops the
			// bySeverity nesting. accumulate (not assign) so a chained
			// --modes run aggregates across legs.
			var parsed Result
			if err := json.Unmarshal(line, &parsed); err == nil {
				result = result.accumulate(parsed)
			}
		case "error":
			renderError(w, env)
		default:
			// Unknown top-level kind — keep silent unless raw log is
			// also off, in which case a dim hint helps debugging.
			if opts.RawLog == nil {
				_, _ = fmt.Fprintf(w, "%s[?] unknown event: kind=%s%s\n", colorGray, env.Kind, colorReset)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return result, fmt.Errorf("read archon stream: %w", err)
	}
	return result, nil
}

// envelope captures the top-level fields archon emits across all event
// kinds. Sub-fields (phase, event, etc.) are decoded as raw JSON and
// re-parsed by the per-kind renderers.
type envelope struct {
	Kind     string          `json:"kind"`
	AuditID  string          `json:"auditId,omitempty"`
	PhaseID  string          `json:"phaseId,omitempty"`
	Phase    json.RawMessage `json:"phase,omitempty"`
	Event    json.RawMessage `json:"event,omitempty"`
	Index    int             `json:"index,omitempty"`
	Total    int             `json:"total,omitempty"`
	OK       *bool           `json:"ok,omitempty"`
	USD      float64         `json:"usd,omitempty"`
	Tokens   Tokens          `json:"tokens,omitempty"`
	Duration int64           `json:"durationMs,omitempty"`

	// auditStart fields
	Mode           string `json:"mode,omitempty"`
	TotalPhases    int    `json:"totalPhases,omitempty"`
	RunnablePhases int    `json:"runnablePhases,omitempty"`

	// auditEnd / result fields
	Status      string   `json:"status,omitempty"`
	TotalUSD    float64  `json:"totalUsd,omitempty"`
	TotalTokens Tokens   `json:"totalTokens,omitempty"`
	Findings    Findings `json:"findings,omitempty"`

	// findingDiscovered fields
	Path    string `json:"path,omitempty"`
	RelPath string `json:"relPath,omitempty"`

	// error fields
	Message string `json:"message,omitempty"`
}

type phaseInfo struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Agent string `json:"agent"`
}

type adapterEvent struct {
	Kind      string          `json:"kind"`
	SessionID string          `json:"sessionId,omitempty"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Tool      string          `json:"tool,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	Output    json.RawMessage `json:"output,omitempty"`
	IsError   bool            `json:"isError,omitempty"`
	Result    string          `json:"result,omitempty"`
	OK        *bool           `json:"ok,omitempty"`
	USD       float64         `json:"usd,omitempty"`
	Tokens    Tokens          `json:"tokens,omitempty"`
	Duration  int64           `json:"durationMs,omitempty"`
	Message   string          `json:"message,omitempty"`
	Thinking  string          `json:"thinking,omitempty"`
}

func renderAuditStart(w io.Writer, env envelope) {
	_, _ = fmt.Fprintf(w, "\n%s%s[audit %s]%s mode=%s phases=%d/%d\n",
		colorBold, colorBlue, env.AuditID, colorReset,
		env.Mode, env.RunnablePhases, env.TotalPhases)
}

func renderPhaseStart(w io.Writer, env envelope) {
	var p phaseInfo
	_ = json.Unmarshal(env.Phase, &p)
	agent := p.Agent
	if agent == "" {
		agent = "(inline)"
	}
	_, _ = fmt.Fprintf(w, "\n%s[phase %s]%s %s (%d/%d) agent=%s\n",
		colorBold+colorMagenta, p.ID, colorReset,
		p.Title, env.Index, env.Total, agent)
}

func renderPhaseEnd(w io.Writer, env envelope) {
	var p phaseInfo
	_ = json.Unmarshal(env.Phase, &p)
	ok := env.OK != nil && *env.OK
	mark := colorGreen + "✓" + colorReset
	if !ok {
		mark = colorRed + "✗" + colorReset
	}
	_, _ = fmt.Fprintf(w, "  %s phase %s done in %s%s%s tokens=in:%d/out:%d\n",
		mark, p.ID,
		colorDim, formatMillis(env.Duration), colorReset,
		env.Tokens.Input, env.Tokens.Output)
}

func renderAdapterEvent(w io.Writer, env envelope, opts Options) {
	var ev adapterEvent
	if err := json.Unmarshal(env.Event, &ev); err != nil {
		return
	}
	switch ev.Kind {
	case "session":
		_, _ = fmt.Fprintf(w, "  %s⚙ session: %s%s\n", colorDim, ev.SessionID, colorReset)
	case "textDelta":
		text := strings.TrimSpace(ev.Text)
		if text == "" {
			return
		}
		_, _ = fmt.Fprintf(w, "  %s⏺ %s%s\n", colorCyan, truncate(text, maxTextLen), colorReset)
	case "thinking":
		if !opts.ShowThinking {
			return
		}
		text := strings.TrimSpace(ev.Thinking)
		if text == "" {
			return
		}
		_, _ = fmt.Fprintf(w, "  %s💭 %s%s\n", colorDim, truncate(text, maxTextLen), colorReset)
	case "toolCall":
		args := compactJSON(ev.Input, maxToolArgsLen)
		_, _ = fmt.Fprintf(w, "  %sƒ %s%s%s · %s%s\n",
			colorYellow, colorBold, ev.Tool, colorReset+colorYellow, args, colorReset)
	case "toolResult":
		out := compactJSON(ev.Output, maxToolArgsLen*2)
		mark := "←"
		color := colorGray
		if ev.IsError {
			mark = "✗"
			color = colorRed
		}
		_, _ = fmt.Fprintf(w, "    %s%s %s%s\n", color, mark, out, colorReset)
	case "finish":
		// Per-adapter finish — phaseEnd already renders the phase-level
		// summary, so keep this terse.
		ok := ev.OK != nil && *ev.OK
		mark := "✓"
		color := colorGreen
		if !ok {
			mark = "✗"
			color = colorRed
		}
		_, _ = fmt.Fprintf(w, "    %s%s adapter finish in %s%s\n",
			color, mark, formatMillis(ev.Duration), colorReset)
	case "error":
		msg := strings.TrimSpace(ev.Message)
		if msg == "" {
			return
		}
		_, _ = fmt.Fprintf(w, "    %s✗ %s%s\n", colorRed, truncate(msg, maxTextLen), colorReset)
	}
}

func renderFindingDiscovered(w io.Writer, env envelope) {
	rel := env.RelPath
	if rel == "" {
		rel = env.Path
	}
	_, _ = fmt.Fprintf(w, "  %s⚑ finding draft: %s%s\n", colorMagenta, rel, colorReset)
}

func renderAuditEnd(w io.Writer, env envelope) {
	// auditEnd uses {usd,tokens}; result uses {totalUsd,totalTokens}.
	// Prefer the per-event fields and fall back to the totals shape.
	usd := env.USD
	if usd == 0 {
		usd = env.TotalUSD
	}
	tokens := env.Tokens
	if tokens.Input == 0 && tokens.Output == 0 {
		tokens = env.TotalTokens
	}
	_, _ = fmt.Fprintf(w, "\n%s[audit %s]%s status=%s findings=%d cost=$%.4f tokens=in:%d/out:%d\n",
		colorBold+colorBlue, env.AuditID, colorReset,
		env.Status, env.Findings.Total,
		usd, tokens.Input, tokens.Output)
}

func renderResult(w io.Writer, env envelope) {
	parts := make([]string, 0, len(env.Findings.BySeverity))
	for sev, n := range env.Findings.BySeverity {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%s:%d", sev, n))
		}
	}
	breakdown := strings.Join(parts, " ")
	if breakdown == "" {
		breakdown = "(none)"
	}
	_, _ = fmt.Fprintf(w, "%s%s[result]%s status=%s total=%d (%s)\n",
		colorBold, colorGreen, colorReset, env.Status, env.Findings.Total, breakdown)
}

func renderError(w io.Writer, env envelope) {
	_, _ = fmt.Fprintf(w, "%s✗ %s%s\n", colorRed, truncate(env.Message, maxTextLen), colorReset)
}

// --- helpers ---

func trimLeftSpace(b []byte) []byte {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t') {
		i++
	}
	return b[i:]
}

func truncate(s string, max int) string {
	if max <= 0 {
		return s
	}
	if len(s) <= max {
		return s
	}
	// archon NDJSON often contains literal newlines inside textDelta
	// blocks; collapse to a single line so a long block doesn't
	// fragment the activity feed across many lines.
	s = strings.ReplaceAll(s, "\n", " ⏎ ")
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// compactJSON renders a raw JSON value as compact text suitable for a
// one-liner. Strings are dequoted, objects/arrays are kept as JSON.
// Long values are truncated.
func compactJSON(raw json.RawMessage, max int) string {
	if len(raw) == 0 {
		return ""
	}
	s := strings.TrimSpace(string(raw))
	// Dequote a single string value so commands render naturally.
	var unquoted string
	if err := json.Unmarshal(raw, &unquoted); err == nil && unquoted != "" {
		return truncate(unquoted, max)
	}
	return truncate(s, max)
}

// formatMillis renders a duration-in-millis as either "<n>ms" or "<n.nn>s"
// to keep phaseEnd lines compact.
func formatMillis(ms int64) string {
	if ms <= 0 {
		return "0ms"
	}
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	return fmt.Sprintf("%.2fs", float64(ms)/1000.0)
}
