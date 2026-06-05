package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/olium/sessionlog"
	"github.com/vigolium/vigolium/pkg/olium/toollog"
	"github.com/vigolium/vigolium/pkg/terminal"
)

// transcriptFilename aliases the single source of truth in sessionlog (the
// package that writes the file) so the `vigolium log` reader can't drift from
// the writers.
const transcriptFilename = sessionlog.Filename

// Display caps for the rendered transcript. The raw, untruncated record is
// always available via `vigolium log <id> --raw`.
const (
	// transcriptMaxLineWidth clips a single rendered line so a base64 blob or
	// minified JS body can't run off the screen.
	transcriptMaxLineWidth = 200
	// transcriptMaxBlockLines caps a prose / thinking block; overflow collapses
	// to a "… (N more lines)" trailer.
	transcriptMaxBlockLines = 40
	// transcriptResultPreviewLines caps a tool-result preview — results are
	// frequently huge (web_fetch bodies, dir listings), so they get the
	// tightest budget, mirroring the verbose real-run preview.
	transcriptResultPreviewLines = 8
)

// transcriptEnvelope is the common top-level shape of every transcript line.
// Only the fields we render are decoded; unknown event types are skipped.
type transcriptEnvelope struct {
	Type     string          `json:"type"`
	Error    string          `json:"error"`    // error events
	Provider string          `json:"provider"` // model_change
	ModelID  string          `json:"modelId"`  // model_change
	Message  json.RawMessage `json:"message"`  // message events
}

// transcriptPart decodes any content part (text / thinking / toolCall) — JSON
// silently ignores the fields that don't apply to a given part type.
type transcriptPart struct {
	Type      string         `json:"type"`
	Text      string         `json:"text"`
	Thinking  string         `json:"thinking"`
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

// resolveTranscriptPath returns sessionDir/transcript.jsonl when it exists.
func resolveTranscriptPath(sessionDir string) string {
	p := filepath.Join(sessionDir, transcriptFilename)
	if info, err := os.Stat(p); err == nil && !info.IsDir() {
		return p
	}
	return ""
}

// printTranscriptBanner heads the rendered (or raw) transcript replay.
func printTranscriptBanner(path, status string, raw bool) {
	if status == "" {
		status = "unknown"
	}
	mode := "replaying transcript from"
	if raw {
		mode = "raw transcript from"
	}
	fmt.Fprintf(os.Stderr, "%s %s %s %s %s %s\n",
		terminal.InfoSymbol(),
		terminal.Gray(mode),
		terminal.HiCyan(terminal.ShortenHome(path)),
		terminal.Gray("—"),
		terminal.Gray("status:"),
		colorRunStatus(status))
	if !raw {
		fmt.Fprintf(os.Stderr, "  %s %s %s %s\n",
			terminal.TipPrefix(),
			terminal.Gray("long lines are truncated — pass"),
			terminal.HiCyan("--raw"),
			terminal.Gray("for the full JSONL"))
	}
}

// dumpFile copies a file verbatim to stdout — used for `--raw`.
func dumpFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open transcript: %w", err)
	}
	defer func() { _ = f.Close() }()
	_, err = io.Copy(os.Stdout, f)
	return err
}

// renderTranscriptFile pretty-prints a transcript.jsonl as a conversation
// replay in the same shape as a live run: assistant prose, muted ⋈ thinking
// blocks, ▶ tool cards with key=value args, and ✓/✗ tool results. Long lines
// are truncated and oversized blocks capped; `--raw` shows the verbatim JSONL.
func renderTranscriptFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open transcript: %w", err)
	}
	defer func() { _ = f.Close() }()

	w := bufio.NewWriter(os.Stdout)
	defer func() { _ = w.Flush() }()
	return renderTranscript(w, f)
}

// errWriter wraps an io.Writer and latches the first write error so the
// per-line render helpers can stay void; renderTranscript reports it. This also
// means write failures (a closed pipe, full disk) now surface instead of being
// silently dropped at each Fprintf.
type errWriter struct {
	w   io.Writer
	err error
}

// printf mirrors fmt.Fprintf but swallows further writes once a write has
// failed, recording only the first error.
func (e *errWriter) printf(format string, args ...any) {
	if e.err != nil {
		return
	}
	_, e.err = fmt.Fprintf(e.w, format, args...)
}

// renderTranscript reads JSONL records from r and writes the rendered replay to
// w. Split from renderTranscriptFile so it can be unit-tested without stdout.
func renderTranscript(w io.Writer, r io.Reader) error {
	// ReadString (not Scanner) so an untruncated multi-megabyte tool-result
	// line can't trip the scanner's max-token limit.
	reader := bufio.NewReader(r)
	ew := &errWriter{w: w}
	for {
		line, readErr := reader.ReadString('\n')
		if strings.TrimSpace(line) != "" {
			renderTranscriptLine(ew, line)
		}
		if ew.err != nil {
			return ew.err
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

func renderTranscriptLine(w *errWriter, raw string) {
	var env transcriptEnvelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return // skip malformed / partial line
	}
	switch env.Type {
	case "message":
		renderTranscriptMessage(w, env.Message)
	case "error":
		if env.Error != "" {
			w.printf("\n%s\n", terminal.Red("✖ "+truncateLine("error: "+env.Error, transcriptMaxLineWidth)))
		}
	case "model_change":
		if env.Provider != "" || env.ModelID != "" {
			w.printf("%s %s\n",
				terminal.Muted("◆ model:"),
				terminal.Muted(strings.TrimSpace(env.Provider+" "+env.ModelID)))
		}
	}
	// session / thinking_level_change: structural metadata, nothing to show.
}

func renderTranscriptMessage(w *errWriter, rawMsg json.RawMessage) {
	if len(rawMsg) == 0 {
		return
	}
	// One decode into a superset of every role's fields — JSON ignores the
	// fields that don't apply to a given role (the same forgiving pattern
	// transcriptPart already relies on), so there's no need for a separate
	// head/role pre-decode.
	var m struct {
		Role     string           `json:"role"`
		Content  []transcriptPart `json:"content"`
		ToolName string           `json:"toolName"`
		IsError  bool             `json:"isError"`
	}
	if err := json.Unmarshal(rawMsg, &m); err != nil {
		return
	}

	switch m.Role {
	case "user":
		lines := clampBlock(joinTextParts(m.Content), transcriptMaxBlockLines)
		if len(lines) == 0 {
			return
		}
		w.printf("\n%s\n%s\n", terminal.BoldBlue("▸ user"), indentLines(lines, "    "))

	case "assistant":
		for _, p := range m.Content {
			switch p.Type {
			case "thinking":
				lines := clampBlock(toollog.CompactThinking(p.Thinking), transcriptMaxBlockLines)
				if len(lines) == 0 {
					continue
				}
				w.printf("\n%s\n%s\n",
					terminal.Muted("  "+terminal.SymbolBowtie+" thinking"),
					terminal.Muted(indentLines(lines, "    ")))
			case "text":
				lines := clampBlock(p.Text, transcriptMaxBlockLines)
				if len(lines) == 0 {
					continue
				}
				// Assistant prose flows at column 0, like a live run.
				w.printf("\n%s\n", strings.Join(lines, "\n"))
			case "toolCall":
				renderTranscriptToolCall(w, p)
			}
		}

	case "toolResult":
		renderTranscriptToolResult(w, m.ToolName, joinTextParts(m.Content), m.IsError)
	}
}

// renderTranscriptToolCall mirrors the live run's `▶ <tool> key=value …` start
// line. Args render keys teal, values blue, with long values clipped.
func renderTranscriptToolCall(w *errWriter, p transcriptPart) {
	name := p.Name
	if name == "" {
		name = "tool"
	}
	arrow := terminal.Cyan(terminal.SymbolStart)
	args := transcriptColoredArgs(p.Arguments)
	if args == "" {
		w.printf("\n%s %s\n", arrow, terminal.BoldCyan(name))
		return
	}
	w.printf("\n%s %s %s\n", arrow, terminal.BoldCyan(name), args)
}

// renderTranscriptToolResult mirrors the live run's `✓ … bytes` / `✗ failed`
// line plus a short, truncated preview of the result body.
func renderTranscriptToolResult(w *errWriter, toolName, body string, isErr bool) {
	if toolName == "" {
		toolName = "tool"
	}
	if isErr {
		w.printf("  %s %s\n",
			terminal.Red("✗"),
			terminal.Red("failed: "+truncateLine(firstNonEmptyLine(body), 120)))
		return
	}
	w.printf("  %s %s  %s\n",
		terminal.Green("✓"),
		terminal.Muted(toolName),
		terminal.Muted(fmt.Sprintf("%d bytes", len(body))))
	if preview := clampBlock(body, transcriptResultPreviewLines); len(preview) > 0 {
		w.printf("%s\n", terminal.Muted(indentLines(preview, "    ")))
	}
}

// transcriptColoredArgs renders tool-call arguments as `key=value` with stable
// key ordering, mirroring toollog's start-line args (values clipped at 80).
func transcriptColoredArgs(args map[string]any) string {
	if len(args) == 0 {
		return ""
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sep := terminal.Muted("=")
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		val := strings.ReplaceAll(fmt.Sprintf("%v", args[k]), "\n", " ")
		val = truncateLine(val, 80)
		parts = append(parts, terminal.HiTeal(k)+sep+terminal.HiBlue(val))
	}
	return strings.Join(parts, " ")
}

// joinTextParts concatenates the text of every text part in a content array.
// The sessionlog recorder always tags text parts with Type "text".
func joinTextParts(parts []transcriptPart) string {
	var b strings.Builder
	for _, p := range parts {
		if p.Type == "text" {
			b.WriteString(p.Text)
		}
	}
	return b.String()
}

// clampBlock trims trailing blank lines, caps the block at maxLines (with a
// "… (N more lines)" trailer), and truncates each kept line to
// transcriptMaxLineWidth. Returns the rendered lines, or nil for blank input.
// Returning the slice lets callers indent + join in one pass instead of
// splitting the joined result again.
func clampBlock(text string, maxLines int) []string {
	text = strings.TrimRight(text, "\n")
	if strings.TrimSpace(text) == "" {
		return nil
	}
	lines := strings.Split(text, "\n")
	var trailer string
	if maxLines > 0 && len(lines) > maxLines {
		extra := len(lines) - maxLines
		lines = lines[:maxLines]
		plural := "s"
		if extra == 1 {
			plural = ""
		}
		trailer = fmt.Sprintf("… (%d more line%s)", extra, plural)
	}
	for i, l := range lines {
		lines[i] = truncateLine(l, transcriptMaxLineWidth)
	}
	if trailer != "" {
		lines = append(lines, trailer)
	}
	return lines
}

// indentLines prefixes every line with prefix and joins them into one string.
func indentLines(lines []string, prefix string) string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = prefix + l
	}
	return strings.Join(out, "\n")
}

// truncateLine clips s to max display runes, appending … when it cuts. Rune-
// based so multi-byte UTF-8 is never split mid-character.
func truncateLine(s string, max int) string {
	if max <= 1 {
		return s
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}

// firstNonEmptyLine returns the first non-blank line of s (for one-line error
// summaries), trimmed.
func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return strings.TrimSpace(s)
}
