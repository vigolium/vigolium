package provider

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/vigolium/vigolium/pkg/olium/stream"
)

// writeFakeBridge creates an executable stub standing in for `vigolium-audit`.
// It records its argv to argvFile (one arg per line) and prints stdoutBody
// verbatim, then exits 0. Returns the script path.
func writeFakeBridge(t *testing.T, argvFile, stdoutBody string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake bridge uses a POSIX shell script")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "vigolium-audit")
	// Single-quote the heredoc terminator so the body is emitted literally
	// (no shell expansion of the JSON braces/dollar signs).
	body := "#!/usr/bin/env bash\n" +
		"printf '%s\\n' \"$@\" > \"" + argvFile + "\"\n" +
		"cat <<'BRIDGE_EOF'\n" +
		stdoutBody +
		"\nBRIDGE_EOF\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake bridge: %v", err)
	}
	return script
}

// drainBridge runs one Stream call to completion and returns the events.
func drainBridge(t *testing.T, p *ClaudeSDKBridge, req Request) []stream.Event {
	t.Helper()
	ch, err := p.Stream(context.Background(), req)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	var got []stream.Event
	for ev := range ch {
		got = append(got, ev)
	}
	return got
}

func concatText(evs []stream.Event) string {
	var b strings.Builder
	for _, e := range evs {
		if e.Type == stream.EventTextDelta {
			b.WriteString(e.Delta)
		}
	}
	return b.String()
}

func lastDone(t *testing.T, evs []stream.Event) stream.Event {
	t.Helper()
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Type == stream.EventDone {
			return evs[i]
		}
	}
	t.Fatalf("no EventDone in stream: %+v", evs)
	return stream.Event{}
}

// TestClaudeSDKBridge_StreamSuccess covers the happy path: streamed text +
// inline tool rendering, terminal result with usage, and correct argv.
func TestClaudeSDKBridge_StreamSuccess(t *testing.T) {
	argvFile := filepath.Join(t.TempDir(), "argv")
	ndjson := strings.Join([]string{
		`{"kind":"ready","action":"run","platform":"claude","output":"text"}`,
		`{"kind":"event","event":{"kind":"session","sessionId":"s1","model":"claude-opus-4-7"}}`,
		`{"kind":"event","event":{"kind":"thinking","text":"pondering"}}`,
		`{"kind":"event","event":{"kind":"textDelta","text":"Hello "}}`,
		`{"kind":"event","event":{"kind":"toolCall","id":"t1","tool":"Bash","input":{"command":"vigolium finding --id 42"}}}`,
		`{"kind":"event","event":{"kind":"toolResult","id":"t1","output":"finding is real","isError":false}}`,
		`{"kind":"event","event":{"kind":"textDelta","text":"world"}}`,
		`{"kind":"result","result":{"ok":true,"action":"run","sessionId":"s1","model":"claude-opus-4-7","usd":0.12,"tokens":{"input":1000,"output":50},"outputRaw":"Hello world"}}`,
	}, "\n")

	bin := writeFakeBridge(t, argvFile, ndjson)
	p := NewClaudeSDKBridge(bin, "opus", "claude", BridgeAuth{})
	evs := drainBridge(t, p, Request{Messages: []Message{{Role: RoleUser, Text: "check finding 42"}}})

	text := concatText(evs)
	for _, want := range []string{"Hello ", "world", "🔧 Bash", "vigolium finding --id 42", "↳ finding is real"} {
		if !strings.Contains(text, want) {
			t.Errorf("streamed text missing %q\ngot: %q", want, text)
		}
	}

	// thinking must be a thinking delta, not folded into assistant text.
	var sawThinking bool
	for _, e := range evs {
		if e.Type == stream.EventThinkingDelta && e.Delta == "pondering" {
			sawThinking = true
		}
	}
	if !sawThinking {
		t.Error("expected a thinking delta for the thinking event")
	}

	done := lastDone(t, evs)
	if done.StopReason != stream.StopReasonStop {
		t.Errorf("stop reason = %q, want stop", done.StopReason)
	}
	if done.Usage == nil || done.Usage.Input != 1000 || done.Usage.Output != 50 || done.Usage.TotalTokens != 1050 {
		t.Errorf("usage = %+v, want input=1000 output=50 total=1050", done.Usage)
	}
	if done.Usage != nil && done.Usage.Cost != 0.12 {
		t.Errorf("usage cost = %v, want 0.12", done.Usage.Cost)
	}

	// argv construction: --json, --agent claude, --model opus, --prompt <text>.
	raw, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatalf("read argv: %v", err)
	}
	argv := string(raw)
	for _, want := range []string{"bridge", "run", "--json", "--agent", "claude", "--model", "opus", "--prompt", "check finding 42"} {
		if !strings.Contains(argv, want) {
			t.Errorf("argv missing %q\ngot:\n%s", want, argv)
		}
	}
	// No auth flags when BridgeAuth is empty (subscription path).
	for _, unwanted := range []string{"--api-key", "--oauth-token", "--oauth-cred-file"} {
		if strings.Contains(argv, unwanted) {
			t.Errorf("argv unexpectedly contains %q with empty auth\ngot:\n%s", unwanted, argv)
		}
	}
}

// TestClaudeSDKBridge_BufferedFallback verifies that when the bridge streams no
// textDelta events, the verbatim final message is emitted so the engine never
// sees an empty turn.
func TestClaudeSDKBridge_BufferedFallback(t *testing.T) {
	argvFile := filepath.Join(t.TempDir(), "argv")
	ndjson := strings.Join([]string{
		`{"kind":"ready","action":"run","platform":"claude"}`,
		`{"kind":"result","result":{"ok":true,"outputRaw":"the whole answer","tokens":{"input":5,"output":7}}}`,
	}, "\n")
	bin := writeFakeBridge(t, argvFile, ndjson)
	p := NewClaudeSDKBridge(bin, "", "claude", BridgeAuth{})
	evs := drainBridge(t, p, Request{Messages: []Message{{Role: RoleUser, Text: "hi"}}})

	if text := concatText(evs); !strings.Contains(text, "the whole answer") {
		t.Errorf("expected buffered outputRaw as text, got %q", text)
	}
	if done := lastDone(t, evs); done.StopReason != stream.StopReasonStop {
		t.Errorf("stop reason = %q, want stop", done.StopReason)
	}

	// Empty model → no --model flag.
	raw, _ := os.ReadFile(argvFile)
	if strings.Contains(string(raw), "--model") {
		t.Errorf("argv should omit --model when model is empty\ngot:\n%s", raw)
	}
}

// TestClaudeSDKBridge_ResultError maps ok:false into an error event + a
// terminal Done with StopReasonError.
func TestClaudeSDKBridge_ResultError(t *testing.T) {
	argvFile := filepath.Join(t.TempDir(), "argv")
	ndjson := strings.Join([]string{
		`{"kind":"ready","action":"run","platform":"claude"}`,
		`{"kind":"result","result":{"ok":false,"error":"agent hit max turns","tokens":{"input":10,"output":0}}}`,
	}, "\n")
	bin := writeFakeBridge(t, argvFile, ndjson)
	p := NewClaudeSDKBridge(bin, "sonnet", "claude", BridgeAuth{})
	evs := drainBridge(t, p, Request{Messages: []Message{{Role: RoleUser, Text: "go"}}})

	var sawErr bool
	for _, e := range evs {
		if e.Type == stream.EventError && strings.Contains(e.Err, "max turns") {
			sawErr = true
		}
	}
	if !sawErr {
		t.Errorf("expected an error event carrying the result error, got %+v", evs)
	}
	if done := lastDone(t, evs); done.StopReason != stream.StopReasonError {
		t.Errorf("stop reason = %q, want error", done.StopReason)
	}
}

// TestClaudeSDKBridge_FatalLine handles a top-level bridge fatal (bad flags /
// setup failure) emitted instead of a result.
func TestClaudeSDKBridge_FatalLine(t *testing.T) {
	argvFile := filepath.Join(t.TempDir(), "argv")
	ndjson := `{"kind":"bridge","ok":false,"error":"missing binary"}`
	bin := writeFakeBridge(t, argvFile, ndjson)
	p := NewClaudeSDKBridge(bin, "", "claude", BridgeAuth{})
	evs := drainBridge(t, p, Request{Messages: []Message{{Role: RoleUser, Text: "x"}}})

	var sawErr bool
	for _, e := range evs {
		if e.Type == stream.EventError && strings.Contains(e.Err, "missing binary") {
			sawErr = true
		}
	}
	if !sawErr {
		t.Errorf("expected an error event from the fatal line, got %+v", evs)
	}
	if done := lastDone(t, evs); done.StopReason != stream.StopReasonError {
		t.Errorf("stop reason = %q, want error", done.StopReason)
	}
}

// TestClaudeSDKBridge_AuthForwarding asserts explicit credentials become the
// corresponding bridge flags.
func TestClaudeSDKBridge_AuthForwarding(t *testing.T) {
	argvFile := filepath.Join(t.TempDir(), "argv")
	ndjson := `{"kind":"result","result":{"ok":true,"outputRaw":"ok","tokens":{"input":1,"output":1}}}`
	bin := writeFakeBridge(t, argvFile, ndjson)
	p := NewClaudeSDKBridge(bin, "", "claude", BridgeAuth{APIKey: "sk-ant-api-XXX", OAuthToken: "sk-ant-oat-YYY"})
	_ = drainBridge(t, p, Request{Messages: []Message{{Role: RoleUser, Text: "x"}}})

	raw, _ := os.ReadFile(argvFile)
	argv := string(raw)
	for _, want := range []string{"--api-key", "sk-ant-api-XXX", "--oauth-token", "sk-ant-oat-YYY"} {
		if !strings.Contains(argv, want) {
			t.Errorf("argv missing forwarded auth %q\ngot:\n%s", want, argv)
		}
	}
}

// TestClaudeSDKBridge_NameDefault checks the agent default and Name().
func TestClaudeSDKBridge_NameDefault(t *testing.T) {
	p := NewClaudeSDKBridge("/bin/true", "", "", BridgeAuth{})
	if p.Name() != "claude-sdk-bridge" {
		t.Errorf("Name() = %q", p.Name())
	}
	if p.agent != "claude" {
		t.Errorf("empty agent should default to claude, got %q", p.agent)
	}
}
