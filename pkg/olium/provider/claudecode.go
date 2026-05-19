package provider

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// ClaudeCode drives the user's Claude Code CLI (`claude -p --output-format
// stream-json`) as an LLM provider. It unlocks the Claude Pro/Max
// subscription without requiring an API key.
//
// Important design note: Claude Code has its OWN tool set (Bash, Read,
// Grep, etc.) and runs them internally. This provider does NOT surface
// those as engine-level tool calls — if it did, the engine would try to
// re-execute them. Instead, tool invocations are rendered inline as
// formatted text so the user still sees what the agent is doing.
type ClaudeCode struct {
	binary string
	model  string
}

// NewClaudeCode constructs a Claude Code provider. `binary` is the
// absolute path to the `claude` CLI.
func NewClaudeCode(binary, model string) *ClaudeCode {
	return &ClaudeCode{binary: binary, model: model}
}

func (*ClaudeCode) Name() string { return "claude-code" }

func (c *ClaudeCode) Stream(ctx context.Context, req Request) (<-chan stream.Event, error) {
	prompt := renderClaudeCodePrompt(req)

	// `claude -p` is non-interactive (stdout is a pipe, no TTY), so any
	// tool that hits the default permission gate comes back as a
	// `tool_result` saying "This command requires approval" and the agent
	// can never make progress. The user has explicitly opted into this
	// provider for autonomous operation; bypass permissions so Bash /
	// Read / Glob / WebFetch behave like they would inside an interactive
	// `claude` session that has already approved every tool.
	args := []string{
		"-p", prompt,
		"--output-format", "stream-json",
		"--verbose",
		"--permission-mode", "bypassPermissions",
	}
	if c.model != "" {
		args = append(args, "--model", c.model)
	}
	cmd := exec.CommandContext(ctx, c.binary, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = nil // let claude manage its own errors; result event will carry is_error

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("claude-code: start: %w", err)
	}

	out := make(chan stream.Event, 32)
	go c.consume(ctx, cmd, stdout, out)
	return out, nil
}

// renderClaudeCodePrompt flattens olium's structured history into a single
// string that Claude Code can consume via its `-p` flag. Format is
// deliberately plain so Claude Code's own tokenizer/context tooling treats
// it as normal prose rather than a structured transcript.
func renderClaudeCodePrompt(req Request) string {
	var b strings.Builder
	if req.System != "" {
		b.WriteString(req.System)
		b.WriteString("\n\n")
	}
	if len(req.Messages) > 1 {
		b.WriteString("Conversation so far:\n")
		for i, m := range req.Messages {
			if i == len(req.Messages)-1 && m.Role == RoleUser {
				break // last user msg is the actual prompt, emitted below
			}
			switch m.Role {
			case RoleUser:
				fmt.Fprintf(&b, "\n[user]: %s\n", m.Text)
			case RoleAssistant:
				if m.Text != "" {
					fmt.Fprintf(&b, "\n[assistant]: %s\n", m.Text)
				}
			case RoleTool:
				// Tool results from prior turns aren't relevant to Claude Code
				// since it manages its own tool loop; omit to save tokens.
			}
		}
		b.WriteString("\n---\n")
	}
	if last := lastUserText(req.Messages); last != "" {
		b.WriteString(last)
	}
	return b.String()
}

func lastUserText(msgs []Message) string {
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == RoleUser {
			return msgs[i].Text
		}
	}
	return ""
}

func (c *ClaudeCode) consume(ctx context.Context, cmd *exec.Cmd, stdout io.ReadCloser, out chan<- stream.Event) {
	defer close(out)
	defer func() { _ = stdout.Close() }()

	scanner := bufio.NewScanner(stdout)
	// Claude Code's stream-json can emit very large lines (e.g., tool_result
	// content blocks with file dumps).
	scanner.Buffer(make([]byte, 0, 256*1024), 64*1024*1024)

	var usage stream.Usage

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			return
		default:
		}

		var ev map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue
		}
		t, _ := ev["type"].(string)
		switch t {
		case "assistant":
			msg, _ := ev["message"].(map[string]any)
			if msg == nil {
				continue
			}
			content, _ := msg["content"].([]any)
			for _, block := range content {
				bm, ok := block.(map[string]any)
				if !ok {
					continue
				}
				btype, _ := bm["type"].(string)
				switch btype {
				case "text":
					if text, _ := bm["text"].(string); text != "" {
						out <- stream.Event{Type: stream.EventTextDelta, Delta: text}
					}
				case "tool_use":
					name, _ := bm["name"].(string)
					inputJSON, _ := json.Marshal(bm["input"])
					formatted := fmt.Sprintf("\n\n🔧 %s %s\n", name, truncateInline(string(inputJSON), 200))
					out <- stream.Event{Type: stream.EventTextDelta, Delta: formatted}
				case "thinking":
					if text, _ := bm["thinking"].(string); text != "" {
						out <- stream.Event{Type: stream.EventThinkingDelta, Delta: text}
					}
				}
			}

		case "user":
			// Claude Code wraps tool results in user-role messages.
			msg, _ := ev["message"].(map[string]any)
			if msg == nil {
				continue
			}
			content, _ := msg["content"].([]any)
			for _, block := range content {
				bm, ok := block.(map[string]any)
				if !ok {
					continue
				}
				if btype, _ := bm["type"].(string); btype == "tool_result" {
					resultText := toolResultToText(bm["content"])
					formatted := fmt.Sprintf("   ↳ %s\n", truncateInline(resultText, 400))
					out <- stream.Event{Type: stream.EventTextDelta, Delta: formatted}
				}
			}

		case "result":
			if u, ok := ev["usage"].(map[string]any); ok {
				usage.Input = intField(u, "input_tokens")
				usage.Output = intField(u, "output_tokens")
				usage.CacheRead = intField(u, "cache_read_input_tokens")
				usage.CacheWrite = intField(u, "cache_creation_input_tokens")
				usage.TotalTokens = usage.Input + usage.Output
			}
			stop := stream.StopReasonStop
			if isErr, _ := ev["is_error"].(bool); isErr {
				stop = stream.StopReasonError
				if errStr, _ := ev["error"].(string); errStr != "" {
					out <- stream.Event{Type: stream.EventError, Err: errStr}
					_ = cmd.Wait()
					return
				}
			}
			out <- stream.Event{Type: stream.EventDone, StopReason: stop, Usage: &usage}
		}
	}
	if err := scanner.Err(); err != nil {
		out <- stream.Event{Type: stream.EventError, Err: err.Error()}
	}
	_ = cmd.Wait()
}

// toolResultToText extracts a renderable string from Claude Code's
// tool_result content, which may be a plain string or an array of
// content blocks.
func toolResultToText(v any) string {
	switch vv := v.(type) {
	case string:
		return vv
	case []any:
		var b strings.Builder
		for _, item := range vv {
			if m, ok := item.(map[string]any); ok {
				if t, _ := m["text"].(string); t != "" {
					b.WriteString(t)
				}
			}
		}
		return b.String()
	}
	return ""
}

func truncateInline(s string, max int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
