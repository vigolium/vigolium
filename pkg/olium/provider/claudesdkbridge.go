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

// BridgeAuth carries the per-run credentials forwarded to the
// `vigolium-audit bridge` sidecar. All fields are optional: when every field
// is empty the bridge falls back to the ambient Claude Code subscription
// (`claude login`) or an API key it detects from the environment itself, which
// is the common "just use my logged-in Claude Code" path.
type BridgeAuth struct {
	APIKey        string // → --api-key (sk-ant-api…)
	OAuthToken    string // → --oauth-token (sk-ant-oat…, from `claude setup-token`)
	OAuthCredFile string // → --oauth-cred-file (a claude OAuth cred JSON)
}

// ClaudeSDKBridge drives Claude Code (or Codex) through the Agent SDK by
// shelling out to the `vigolium-audit bridge run --json` sidecar. The Agent
// SDK is TypeScript-only, so this is how a Go caller reaches it: one headless
// SDK invocation per Stream call, reading the bridge's normalized NDJSON event
// stream back (see platform/vigolium-audit/docs/bridge.md).
//
// Important design note (mirrors ClaudeCode): the bridge runs its OWN agent
// loop with its own tools (Bash, Read, Grep, the `vigolium-scanner` skill,
// etc.) and executes them internally. This provider does NOT surface those as
// engine-level tool calls — if it did, the olium engine would try to
// re-execute them. Instead, tool activity is rendered inline as formatted text
// so the user still sees what the agent is doing, and the whole task resolves
// in a single assistant turn with no tool calls (the engine then stops).
type ClaudeSDKBridge struct {
	binary string // absolute path to the vigolium-audit binary
	model  string // "" = let the bridge/runtime pick its default
	agent  string // "claude" (default) | "codex"
	auth   BridgeAuth
}

// NewClaudeSDKBridge constructs a bridge-backed provider. `binary` is the
// absolute path to the `vigolium-audit` executable (resolved by the caller:
// explicit override → embedded blob → PATH). `agent` selects the SDK flavor
// ("claude" or "codex"); empty defaults to "claude".
func NewClaudeSDKBridge(binary, model, agent string, auth BridgeAuth) *ClaudeSDKBridge {
	if agent == "" {
		agent = "claude"
	}
	return &ClaudeSDKBridge{binary: binary, model: model, agent: agent, auth: auth}
}

func (*ClaudeSDKBridge) Name() string { return "claude-sdk-bridge" }

func (c *ClaudeSDKBridge) Stream(ctx context.Context, req Request) (<-chan stream.Event, error) {
	// Reuse ClaudeCode's prompt flattener: it folds the system prompt, prior
	// turns, and the final user message into one plain string. The bridge's
	// `run` preset then treats that as the user instruction. We deliberately do
	// NOT also pass --system-prompt to avoid duplicating the system text that
	// renderClaudeCodePrompt already prepends.
	prompt := renderClaudeCodePrompt(req)

	args := []string{
		"bridge", "run",
		"--json",
		"--agent", c.agent,
		// The bridge bypasses permissions by default (required for autonomous
		// tool use); AskUserQuestion is always denied on its side. Nothing to
		// set here — we simply don't pass --no-bypass-permissions.
		"--prompt", prompt,
	}
	if c.model != "" {
		args = append(args, "--model", c.model)
	}
	// Forward explicit credentials; empty fields are omitted so the bridge can
	// fall back to subscription / ambient-env auth on its own.
	if c.auth.APIKey != "" {
		args = append(args, "--api-key", c.auth.APIKey)
	}
	if c.auth.OAuthToken != "" {
		args = append(args, "--oauth-token", c.auth.OAuthToken)
	}
	if c.auth.OAuthCredFile != "" {
		args = append(args, "--oauth-cred-file", c.auth.OAuthCredFile)
	}

	cmd := exec.CommandContext(ctx, c.binary, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = nil // the bridge reports failures on the result line / a bridge fatal line

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("claude-sdk-bridge: start: %w", err)
	}

	out := make(chan stream.Event, 32)
	go c.consume(ctx, cmd, stdout, out)
	return out, nil
}

// bridgeRunResult mirrors the subset of BridgeRunResult (docs/bridge.md) that
// this provider needs to close a turn: success flag, token/cost usage, an
// error string, and the verbatim final message used as a text fallback.
type bridgeRunResult struct {
	OK        bool   `json:"ok"`
	Error     string `json:"error"`
	OutputRaw string `json:"outputRaw"`
	USD       float64
	Tokens    struct {
		Input  int `json:"input"`
		Output int `json:"output"`
	} `json:"tokens"`
}

// UnmarshalJSON tolerates the "usd" field being null/absent without failing
// the whole result parse.
func (r *bridgeRunResult) UnmarshalJSON(data []byte) error {
	type alias bridgeRunResult
	aux := struct {
		USD *float64 `json:"usd"`
		*alias
	}{alias: (*alias)(r)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.USD != nil {
		r.USD = *aux.USD
	}
	return nil
}

func (c *ClaudeSDKBridge) consume(ctx context.Context, cmd *exec.Cmd, stdout io.ReadCloser, out chan<- stream.Event) {
	defer close(out)
	defer func() { _ = stdout.Close() }()

	scanner := bufio.NewScanner(stdout)
	// Bridge tool_result lines can be very large (file dumps, scan output).
	scanner.Buffer(make([]byte, 0, 256*1024), 64*1024*1024)

	var usage stream.Usage
	sawText := false
	emittedDone := false

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			return
		default:
		}

		var env struct {
			Kind   string          `json:"kind"`
			Event  json.RawMessage `json:"event"`
			Result json.RawMessage `json:"result"`
			OK     *bool           `json:"ok"`    // top-level "bridge" fatal line
			Error  string          `json:"error"` // top-level "bridge" fatal line
		}
		if err := json.Unmarshal(scanner.Bytes(), &env); err != nil {
			continue
		}

		switch env.Kind {
		case "event":
			// handleEvent only ever signals via sawText; no terminal here.
			c.handleEvent(env.Event, out, &sawText)
		case "result":
			var res bridgeRunResult
			if err := json.Unmarshal(env.Result, &res); err != nil {
				out <- stream.Event{Type: stream.EventError, Err: fmt.Sprintf("claude-sdk-bridge: bad result line: %v", err)}
				out <- stream.Event{Type: stream.EventDone, StopReason: stream.StopReasonError, Usage: &usage}
				emittedDone = true
				continue
			}
			usage.Input = res.Tokens.Input
			usage.Output = res.Tokens.Output
			usage.TotalTokens = res.Tokens.Input + res.Tokens.Output
			usage.Cost = res.USD
			if !res.OK {
				if res.Error != "" {
					out <- stream.Event{Type: stream.EventError, Err: res.Error}
				}
				out <- stream.Event{Type: stream.EventDone, StopReason: stream.StopReasonError, Usage: &usage}
				emittedDone = true
				continue
			}
			// Success. The bridge normally streams textDelta events, but if it
			// buffered the whole answer we still deliver it via the verbatim
			// final message so the engine never sees an empty turn.
			if !sawText && strings.TrimSpace(res.OutputRaw) != "" {
				out <- stream.Event{Type: stream.EventTextDelta, Delta: res.OutputRaw}
			}
			out <- stream.Event{Type: stream.EventDone, StopReason: stream.StopReasonStop, Usage: &usage}
			emittedDone = true
		case "bridge":
			// A fatal before the run started (bad flags, missing binary).
			if env.OK == nil || !*env.OK {
				msg := env.Error
				if msg == "" {
					msg = "vigolium-audit bridge: fatal error"
				}
				out <- stream.Event{Type: stream.EventError, Err: msg}
				out <- stream.Event{Type: stream.EventDone, StopReason: stream.StopReasonError, Usage: &usage}
				emittedDone = true
			}
		default:
			// "ready" and any unknown envelope kinds carry no turn content.
		}
	}
	if err := scanner.Err(); err != nil {
		out <- stream.Event{Type: stream.EventError, Err: err.Error()}
	}
	_ = cmd.Wait()

	// The process died before emitting a terminal result (crash, killed,
	// truncated stream). Emit a Done so the engine's drain loop doesn't hang.
	if !emittedDone {
		out <- stream.Event{Type: stream.EventDone, StopReason: stream.StopReasonError, Usage: &usage}
	}
}

// handleEvent maps one normalized bridge adapter event (the inner object of an
// {"kind":"event","event":{…}} envelope) onto the olium stream. Returns true
// if it emitted assistant text (so the caller can note that text was seen).
func (c *ClaudeSDKBridge) handleEvent(raw json.RawMessage, out chan<- stream.Event, sawText *bool) bool {
	var ev struct {
		Kind    string          `json:"kind"`
		Text    string          `json:"text"`
		Tool    string          `json:"tool"`
		Input   json.RawMessage `json:"input"`
		Output  json.RawMessage `json:"output"`
		Message string          `json:"message"`
	}
	if err := json.Unmarshal(raw, &ev); err != nil {
		return false
	}
	switch ev.Kind {
	case "textDelta":
		if ev.Text != "" {
			out <- stream.Event{Type: stream.EventTextDelta, Delta: ev.Text}
			*sawText = true
			return true
		}
	case "thinking":
		if ev.Text != "" {
			out <- stream.Event{Type: stream.EventThinkingDelta, Delta: ev.Text}
		}
	case "toolCall":
		formatted := fmt.Sprintf("\n\n🔧 %s %s\n", ev.Tool, truncateInline(string(ev.Input), 200))
		out <- stream.Event{Type: stream.EventTextDelta, Delta: formatted}
	case "toolResult":
		formatted := fmt.Sprintf("   ↳ %s\n", truncateInline(rawJSONToText(ev.Output), 400))
		out <- stream.Event{Type: stream.EventTextDelta, Delta: formatted}
	case "error":
		if ev.Message != "" {
			out <- stream.Event{Type: stream.EventError, Err: ev.Message}
		}
	case "session", "finish", "rateLimits":
		// session: inventory only. finish: superseded by the authoritative
		// result line. rateLimits: subscription quota telemetry — none carry
		// turn content the engine needs.
	}
	return false
}

// rawJSONToText renders a bridge event field that may be a JSON string or a
// structured value into a compact display string. A JSON string decodes to its
// contents; anything else is shown as its raw JSON form.
func rawJSONToText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}
