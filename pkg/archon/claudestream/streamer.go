// Package claudestream decodes Claude Code's stream-json output format
// and renders it as a compact, colored activity feed suitable for a
// terminal. Used by the vigolium `agent archon` command to show live
// progress while a headless claude session executes an audit.
package claudestream

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
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
)

// maxToolArgsLen caps the inline JSON rendering of tool arguments.
const maxToolArgsLen = 180

// maxTextLen caps individual text lines so one verbose block doesn't flood the terminal.
const maxTextLen = 400

// Options controls how Stream renders output.
type Options struct {
	// ShowThinking renders thinking blocks (dim). Off by default — they are very noisy.
	ShowThinking bool
	// ShowRateLimit renders rate_limit_event notices.
	ShowRateLimit bool
	// RawLog, if non-nil, receives every raw JSON line (with trailing newline) for replay.
	RawLog io.Writer
}

// Stream reads newline-delimited JSON events from r, renders a human-readable
// feed to w, and mirrors every raw line to opts.RawLog if set. It returns when
// r reaches EOF or an unrecoverable read error occurs. Individual malformed
// lines are tolerated — they are written to w as a dim warning and skipped.
func Stream(r io.Reader, w io.Writer, opts Options) error {
	scanner := bufio.NewScanner(r)
	// stream-json lines can be large (tool results with file contents).
	buf := make([]byte, 0, 1<<20)
	scanner.Buffer(buf, 16<<20) // up to 16 MiB per line

	start := time.Now()

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

		switch env.Type {
		case "system":
			renderSystem(w, env)
		case "assistant":
			renderAssistant(w, env, opts)
		case "user":
			renderUser(w, env)
		case "result":
			renderResult(w, env, start)
		case "rate_limit_event":
			if opts.ShowRateLimit {
				renderRateLimit(w, env)
			}
		case "stream_event":
			// Low-level per-token deltas — ignored in favor of finalized events.
		default:
			// Unknown event type; render a dim fallback.
			_, _ = fmt.Fprintf(w, "%s[?] %s%s\n", colorGray, env.Type, colorReset)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("stream read: %w", err)
	}
	return nil
}

// envelope is the minimal shape of every stream-json line.
type envelope struct {
	Type    string          `json:"type"`
	Subtype string          `json:"subtype,omitempty"`
	Message json.RawMessage `json:"message,omitempty"`

	// system.init fields
	CWD       string `json:"cwd,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Model     string `json:"model,omitempty"`

	// result fields
	DurationMS int64  `json:"duration_ms,omitempty"`
	NumTurns   int    `json:"num_turns,omitempty"`
	IsError    bool   `json:"is_error,omitempty"`
	Result     string `json:"result,omitempty"`

	// rate_limit_event fields
	RateLimitInfo json.RawMessage `json:"rate_limit_info,omitempty"`
}

type messagePayload struct {
	Role    string         `json:"role"`
	Content []contentBlock `json:"content"`
	Model   string         `json:"model,omitempty"`
}

type contentBlock struct {
	Type string `json:"type"`

	// text
	Text string `json:"text,omitempty"`

	// thinking
	Thinking string `json:"thinking,omitempty"`

	// tool_use
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`

	// tool_result
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"`
	IsError   bool            `json:"is_error,omitempty"`
}

func renderSystem(w io.Writer, env envelope) {
	if env.Subtype != "init" {
		return
	}
	short := shortSession(env.SessionID)
	model := env.Model
	if model == "" {
		model = "?"
	}
	_, _ = fmt.Fprintf(w, "%s[stream]%s session %s%s%s  model=%s  cwd=%s\n",
		colorCyan, colorReset,
		colorBold, short, colorReset,
		model,
		env.CWD,
	)
}

func renderAssistant(w io.Writer, env envelope, opts Options) {
	var msg messagePayload
	if err := json.Unmarshal(env.Message, &msg); err != nil {
		return
	}
	for _, block := range msg.Content {
		switch block.Type {
		case "text":
			text := strings.TrimRight(block.Text, "\n")
			if text == "" {
				continue
			}
			for _, line := range strings.Split(text, "\n") {
				_, _ = fmt.Fprintf(w, "  %s%s%s\n", colorReset, truncate(line, maxTextLen), colorReset)
			}
		case "tool_use":
			args := compactInput(block.Input)
			_, _ = fmt.Fprintf(w, "  %s→%s %s%s%s %s(%s)%s\n",
				colorBlue, colorReset,
				colorBold, block.Name, colorReset,
				colorDim, args, colorReset,
			)
		case "thinking":
			if !opts.ShowThinking {
				continue
			}
			text := strings.TrimSpace(block.Thinking)
			if text == "" {
				continue
			}
			_, _ = fmt.Fprintf(w, "  %s∴ %s%s\n", colorGray, truncate(text, maxTextLen), colorReset)
		}
	}
}

func renderUser(w io.Writer, env envelope) {
	var msg messagePayload
	if err := json.Unmarshal(env.Message, &msg); err != nil {
		return
	}
	for _, block := range msg.Content {
		if block.Type != "tool_result" {
			continue
		}
		summary := summarizeToolResult(block.Content)
		marker := "←"
		color := colorGreen
		if block.IsError {
			marker = "✗"
			color = colorYellow
		}
		_, _ = fmt.Fprintf(w, "  %s%s%s %s%s\n",
			color, marker, colorReset,
			colorDim, summary+colorReset,
		)
	}
}

func renderResult(w io.Writer, env envelope, start time.Time) {
	dur := time.Duration(env.DurationMS) * time.Millisecond
	if dur == 0 {
		dur = time.Since(start)
	}
	status := "✓ complete"
	color := colorGreen
	if env.IsError {
		status = "✗ failed"
		color = colorYellow
	}
	_, _ = fmt.Fprintf(w, "%s[stream]%s %s%s%s  turns=%d  duration=%s\n",
		colorCyan, colorReset,
		color, status, colorReset,
		env.NumTurns,
		dur.Round(time.Second),
	)
}

func renderRateLimit(w io.Writer, env envelope) {
	_, _ = fmt.Fprintf(w, "  %s[rate-limit] %s%s\n", colorGray, truncate(string(env.RateLimitInfo), 120), colorReset)
}

// compactInput renders a tool_use input JSON as a single-line, truncated summary.
func compactInput(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	// Re-encode with no indentation to drop whitespace differences.
	var tmp interface{}
	if err := json.Unmarshal(raw, &tmp); err != nil {
		return truncate(string(raw), maxToolArgsLen)
	}
	out, err := json.Marshal(tmp)
	if err != nil {
		return truncate(string(raw), maxToolArgsLen)
	}
	s := string(out)
	// Strip outer object braces for compactness: {"k":"v"} -> "k":"v"
	if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
		s = s[1 : len(s)-1]
	}
	return truncate(s, maxToolArgsLen)
}

// summarizeToolResult collapses a tool_result.content value (which may be a
// string or an array of blocks) into a single-line, truncated summary.
func summarizeToolResult(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "(empty)"
	}
	// Case 1: string content
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return oneLine(s, maxTextLen)
	}
	// Case 2: array of blocks — pull any text fields out
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &blocks); err == nil {
		var parts []string
		for _, b := range blocks {
			if b.Text != "" {
				parts = append(parts, b.Text)
			}
		}
		if len(parts) > 0 {
			return oneLine(strings.Join(parts, " "), maxTextLen)
		}
	}
	// Fallback: truncated raw JSON
	return truncate(string(raw), maxTextLen)
}

// oneLine collapses newlines, trims whitespace, and truncates.
func oneLine(s string, max int) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	if s == "" {
		return "(empty)"
	}
	return truncate(s, max)
}

// truncate returns s truncated to max bytes with an ellipsis.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// shortSession returns the first 8 chars of a UUID-like session id.
func shortSession(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

// trimLeftSpace trims leading ASCII whitespace from b without allocating.
func trimLeftSpace(b []byte) []byte {
	for i, c := range b {
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			return b[i:]
		}
	}
	return b[:0]
}
