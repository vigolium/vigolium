// Package pistream decodes Pi's `--mode json` output (newline-delimited
// AgentSessionEvent JSON, schema in pi-coding-agent docs/json.md) into a
// compact colored terminal feed for `vigolium agent audit`. Unknown event
// types render as a dim fallback so the feed survives schema evolution.
package pistream

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
	colorRed     = "\033[31m"
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
	// ShowThinking renders thinking-style blocks. Off by default.
	ShowThinking bool
	// RawLog, if non-nil, receives every raw JSON line (with trailing newline) for replay.
	RawLog io.Writer
}

// Stream reads newline-delimited JSON events from r, renders a human-readable
// feed to w, and mirrors every raw line to opts.RawLog if set. It returns when
// r reaches EOF or an unrecoverable read error occurs. Individual malformed
// lines are tolerated — they are written to w as a dim warning and skipped.
func Stream(r io.Reader, w io.Writer, opts Options) error {
	scanner := bufio.NewScanner(r)
	// pi --mode json lines can be large (tool results with file contents).
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
		case "session":
			renderSession(w, env)
		case "agent_start":
			_, _ = fmt.Fprintf(w, "%s[piolium]%s %sagent started%s\n", colorCyan, colorReset, colorDim, colorReset)
		case "agent_end":
			renderAgentEnd(w, env, start)
		case "turn_start", "turn_end", "message_start", "message_update", "tool_execution_update", "queue_update", "session_info_changed":
			// Dropped: redundant with the *_end events we render below, or
			// UI-state-only and uninteresting on a CLI feed. (Piolium's
			// archon-stream custom messages are emitted on both
			// message_start and message_end with identical payloads — we
			// render them on message_end to avoid double-printing.)
		case "message_end":
			renderMessage(w, env, opts)
		case "tool_execution_start":
			renderToolStart(w, env)
		case "tool_execution_end":
			renderToolEnd(w, env)
		case "auto_retry_start":
			_, _ = fmt.Fprintf(w, "  %s↻ retry %d/%d in %dms — %s%s\n",
				colorYellow,
				env.Attempt, env.MaxAttempts, env.DelayMs,
				oneLine(env.ErrorMessage, 120),
				colorReset,
			)
		case "auto_retry_end":
			marker := "✓"
			color := colorGreen
			if !env.Success {
				marker = "✗"
				color = colorRed
			}
			_, _ = fmt.Fprintf(w, "  %s%s retry %d %s%s\n",
				color, marker, env.Attempt,
				retrySuffix(env), colorReset,
			)
		case "compaction_start":
			_, _ = fmt.Fprintf(w, "  %s⚙ compaction (%s)%s\n", colorGray, env.Reason, colorReset)
		case "compaction_end":
			marker := "✓"
			if env.Aborted || env.ErrorMessage != "" {
				marker = "✗"
			}
			detail := env.Reason
			if env.ErrorMessage != "" {
				detail += " — " + oneLine(env.ErrorMessage, 120)
			}
			_, _ = fmt.Fprintf(w, "  %s%s compaction done (%s)%s\n", colorGray, marker, detail, colorReset)
		default:
			_, _ = fmt.Fprintf(w, "%s[?] %s%s\n", colorGray, env.Type, colorReset)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("stream read: %w", err)
	}
	return nil
}

// envelope is the minimal shape of every Pi --mode json line. Pi's events
// are heterogeneous; we use json.RawMessage for variable shapes (Args,
// Result, Message) and decode them lazily in the per-type renderers.
type envelope struct {
	Type string `json:"type"`

	// session
	ID        string `json:"id,omitempty"`
	CWD       string `json:"cwd,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`

	// message_start / message_end / turn_end carry an AgentMessage
	Message json.RawMessage `json:"message,omitempty"`
	// agent_end carries the full message log
	Messages json.RawMessage `json:"messages,omitempty"`

	// tool_execution_*
	ToolCallID string          `json:"toolCallId,omitempty"`
	ToolName   string          `json:"toolName,omitempty"`
	Args       json.RawMessage `json:"args,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
	IsError    bool            `json:"isError,omitempty"`

	// auto_retry_*
	Attempt      int    `json:"attempt,omitempty"`
	MaxAttempts  int    `json:"maxAttempts,omitempty"`
	DelayMs      int    `json:"delayMs,omitempty"`
	ErrorMessage string `json:"errorMessage,omitempty"`
	Success      bool   `json:"success,omitempty"`
	FinalError   string `json:"finalError,omitempty"`

	// compaction_*
	Reason  string `json:"reason,omitempty"`
	Aborted bool   `json:"aborted,omitempty"`
}

// agentMessage models the fields of pi-ai's AgentMessage we render.
//
// Content is RawMessage rather than a typed slice because Pi serializes
// "role": "custom" messages with a *string* content (piolium emits these
// as customType="archon-stream" tool/phase events) while every other
// role serializes content as []contentBlock. Decoding both shapes is
// done lazily in renderMessage.
type agentMessage struct {
	Role         string          `json:"role"`
	CustomType   string          `json:"customType,omitempty"`
	Content      json.RawMessage `json:"content"`
	Display      *bool           `json:"display,omitempty"`
	Details      *streamDetails  `json:"details,omitempty"`
	Provider     string          `json:"provider,omitempty"`
	Model        string          `json:"model,omitempty"`
	StopReason   string          `json:"stopReason,omitempty"`
	ErrorMessage string          `json:"errorMessage,omitempty"`
	Usage        *usageBlock     `json:"usage,omitempty"`
}

type contentBlock struct {
	Type     string          `json:"type"`
	Text     string          `json:"text,omitempty"`
	Thinking string          `json:"thinking,omitempty"`
	Name     string          `json:"name,omitempty"`
	Input    json.RawMessage `json:"input,omitempty"`
}

// streamDetails decodes the `details` field on piolium's archon-stream
// custom messages. Only Kind drives rendering today (it picks the line
// color); piolium attaches more fields per kind but the content string
// already includes the human-readable rendering of those values.
type streamDetails struct {
	Kind string `json:"kind,omitempty"`
}

type usageBlock struct {
	Input       int `json:"input"`
	Output      int `json:"output"`
	CacheRead   int `json:"cacheRead"`
	CacheWrite  int `json:"cacheWrite"`
	TotalTokens int `json:"totalTokens"`
}

func renderSession(w io.Writer, env envelope) {
	short := shortSession(env.ID)
	_, _ = fmt.Fprintf(w, "%s[piolium]%s session %s%s%s  cwd=%s\n",
		colorCyan, colorReset,
		colorBold, short, colorReset,
		env.CWD,
	)
}

func renderMessage(w io.Writer, env envelope, opts Options) {
	if len(env.Message) == 0 {
		return
	}
	var msg agentMessage
	if err := json.Unmarshal(env.Message, &msg); err != nil {
		return
	}
	// Surface API errors without flooding the user with empty assistant turns.
	if msg.ErrorMessage != "" {
		_, _ = fmt.Fprintf(w, "  %s✗ %s%s\n", colorRed, oneLine(msg.ErrorMessage, maxTextLen), colorReset)
		return
	}
	// Skip user echoes — they're prompts the orchestrator sent, not new info.
	if msg.Role == "user" {
		return
	}
	// Piolium's phase/tool activity arrives as role:"custom" messages with
	// customType:"archon-stream" and a *string* content (already prefixed
	// with [Q2] →/←/✗ markers). Handle those before falling through to the
	// standard []contentBlock path.
	if msg.Role == "custom" {
		renderCustomMessage(w, msg)
		return
	}
	blocks, err := decodeContentBlocks(msg.Content)
	if err != nil {
		return
	}
	for _, block := range blocks {
		switch block.Type {
		case "text":
			text := strings.TrimRight(block.Text, "\n")
			if text == "" {
				continue
			}
			for _, line := range strings.Split(text, "\n") {
				_, _ = fmt.Fprintf(w, "  %s%s%s\n", colorReset, truncate(line, maxTextLen), colorReset)
			}
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

// decodeContentBlocks tolerates Pi's content polymorphism. Standard
// agent messages serialize content as []contentBlock; custom messages
// (which we handle before this is called) serialize it as a string.
// Returning a nil slice on a string payload lets the caller skip rendering.
func decodeContentBlocks(raw json.RawMessage) ([]contentBlock, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if raw[0] != '[' {
		return nil, nil
	}
	var blocks []contentBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return nil, err
	}
	return blocks, nil
}

// renderCustomMessage renders piolium's archon-stream events. The
// content string is already pre-formatted by piolium (e.g.
// "[Q2] → read piolium/attack-surface/lite-recon.md"), so we just
// reprint it with a color picked from details.kind so the feed reads
// like a tool/phase log.
func renderCustomMessage(w io.Writer, msg agentMessage) {
	if msg.Display != nil && !*msg.Display {
		return
	}
	var content string
	if err := json.Unmarshal(msg.Content, &content); err != nil {
		// Fall back to raw bytes if Pi ever switches to a non-string
		// content for custom messages — better noisy than silent.
		content = strings.TrimSpace(string(msg.Content))
	}
	content = strings.TrimSpace(content)
	if content == "" {
		return
	}

	color := colorGray
	if msg.Details != nil {
		switch msg.Details.Kind {
		case "tool-start":
			color = colorBlue
		case "tool-end":
			color = colorGreen
		case "tool-error":
			color = colorYellow
		case "tool-warning":
			color = colorYellow
		case "phase-start", "phase":
			color = colorMagenta
		case "phase-end":
			color = colorMagenta
		case "note", "info":
			color = colorReset
		}
	}

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, " \t\r")
		if line == "" {
			continue
		}
		_, _ = fmt.Fprintf(w, "  %s%s%s\n", color, truncate(line, maxTextLen), colorReset)
	}
}

func renderToolStart(w io.Writer, env envelope) {
	args := compactInput(env.Args)
	_, _ = fmt.Fprintf(w, "  %s→%s %s%s%s %s(%s)%s\n",
		colorBlue, colorReset,
		colorBold, env.ToolName, colorReset,
		colorDim, args, colorReset,
	)
}

func renderToolEnd(w io.Writer, env envelope) {
	marker := "←"
	color := colorGreen
	if env.IsError {
		marker = "✗"
		color = colorYellow
	}
	summary := summarizeToolResult(env.Result)
	_, _ = fmt.Fprintf(w, "  %s%s%s %s%s%s\n",
		color, marker, colorReset,
		colorDim, summary, colorReset,
	)
}

func renderAgentEnd(w io.Writer, env envelope, start time.Time) {
	_ = env
	dur := time.Since(start).Round(time.Second)
	_, _ = fmt.Fprintf(w, "%s[piolium]%s %s✓ complete%s  duration=%s\n",
		colorCyan, colorReset,
		colorGreen, colorReset,
		dur,
	)
}

func retrySuffix(env envelope) string {
	if env.Success {
		return ""
	}
	if env.FinalError != "" {
		return " — " + oneLine(env.FinalError, 120)
	}
	return ""
}

// compactInput renders a tool input JSON as a single-line, truncated summary.
func compactInput(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var tmp interface{}
	if err := json.Unmarshal(raw, &tmp); err != nil {
		return truncate(string(raw), maxToolArgsLen)
	}
	out, err := json.Marshal(tmp)
	if err != nil {
		return truncate(string(raw), maxToolArgsLen)
	}
	s := string(out)
	if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
		s = s[1 : len(s)-1]
	}
	return truncate(s, maxToolArgsLen)
}

// summarizeToolResult collapses a tool result (which may be a string, an
// object, or an array) into a single-line, truncated summary.
func summarizeToolResult(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "(empty)"
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return oneLine(s, maxTextLen)
	}
	// Some tool results are an object with an "output" or "text" field.
	var obj struct {
		Output string `json:"output"`
		Text   string `json:"text"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		if obj.Output != "" {
			return oneLine(obj.Output, maxTextLen)
		}
		if obj.Text != "" {
			return oneLine(obj.Text, maxTextLen)
		}
	}
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

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func shortSession(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

func trimLeftSpace(b []byte) []byte {
	for i, c := range b {
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			return b[i:]
		}
	}
	return b[:0]
}
