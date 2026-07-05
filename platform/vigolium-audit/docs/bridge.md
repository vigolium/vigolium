# `vigolium-audit bridge` — the SDK sidecar

The **bridge** lets a non-TypeScript caller — chiefly the Go `vigolium` scanner —
drive Claude Code (or Codex) through the Agent SDK for a single, focused task:
**triage** a finding, develop an **exploit**, or **plan** an attack. The Agent
SDK is TypeScript-only, so `vigolium` shells out to this binary and reads a
normalized event stream back.

Unlike `vigolium-audit run`, the bridge does **not** run the audit phase graph.
It is one headless SDK invocation: resolve a task preset → assemble an ephemeral
plugin (always including the `vigolium-scanner` skill) → run one agent loop →
return a structured result. The `vigolium-scanner` skill is always loaded so the
driven agent knows how to operate the `vigolium` CLI.

## Two ways to call it

| Mode | Command | Use when |
|---|---|---|
| **one-shot** | `vigolium-audit bridge <task> …` | One task per process, then exit. Simplest to shell out to; matches how Go already spawns this binary. |
| **daemon** | `vigolium-audit bridge serve …` | Keep the Node process (loaded SDK + content + built plugins) warm across many calls. Concurrent, cancellable, session-aware. Best for batch triage. |

Both share the same task presets, parameters, event schema, and result schema.
The only difference is transport (argv + one stdout stream vs. a persistent
stdin/stdout request loop).

## Tasks (presets)

Presets live under `src/content/bridge-tasks/<name>.md` (frontmatter declares
skills / tools / model / output shape; the body is the system prompt). Override
per-user at `$VIGOLIUM_AUDIT_CONFIG_DIR/bridge-tasks/<name>.md`.

| Task | Purpose | Default output | Extra skill |
|---|---|---|---|
| `triage` | Is this finding real or a false positive? | `json` verdict | `fp-check` |
| `exploit` | Minimal reproducible PoC for a confirmed finding | `json` result | `variant-analysis` |
| `plan` | Prioritized attack plan from code + attack surface | `json` plan | `security-threat-model` |
| `run` | No preset — your raw `--prompt` / `params.prompt` | `text` | — |

`vigolium-audit bridge list` prints the presets (add `--json` for a machine list).

## Parameters

Every knob has a one-shot flag and a daemon JSON `params` key. They resolve
identically.

| Flag (one-shot) | `params` key (daemon) | Meaning |
|---|---|---|
| `<action>` (positional) | `action` | Task preset, or `run`. Defaults to `run` in the daemon. |
| `--agent claude\|codex` | `agent` | Runtime. Bridge always uses the SDK flavor. Default `claude`. |
| `--model <id>` | `model` | e.g. `sonnet`, `opus`, a full model id. Falls back to preset, then `VIGOLIUM_AUDIT_MODEL`, then runtime default. |
| `--cwd <dir>` / `--target <dir>` | `cwd` | Working dir = the target. Default `.` |
| `--prompt <text>` / `--prompt-file <p>` / stdin | `prompt` | User instruction text. |
| `--input <text>` / `--input-file <p>` | `input` | Structured context (a finding); wrapped under a `# Task input` block. |
| `--system-prompt <text>` / `--system-prompt-file <p>` | `systemPrompt` | System-prompt override (honored for `run` only). |
| `--skill <name>` (repeatable) | `skills` (string[]) | Extra skills. `vigolium-scanner` is always added. |
| `--allow-tools a,b` | `tools` (string[]) | Tool allow-list. Default: all tools. |
| `--deny-tools a,b` | `denyTools` (string[]) | Extra denied tools. `AskUserQuestion` is always denied. |
| `--max-turns <n>` | `maxTurns` | Hard turn cap. |
| `--resume <sessionId>` | `resume` | Continue a prior session (see [Chaining](#chaining-triage--exploit)). |
| `--output json\|text` | `output` | Override the preset's output mode. |
| `--no-bypass-permissions` | `bypassPermissions: false` | Default is to bypass (required for autonomous tool use). |
| `--api-key` / `--oauth-token` / `--oauth-cred-file` | — (set once at daemon launch) | Per-run auth; restored on exit. |

At least one of `prompt` / `input` must be non-empty, or the run errors before
starting.

## Event schema

Both modes stream the adapter's normalized events. Each has a `kind`; the shape
per kind:

| `kind` | Fields |
|---|---|
| `session` | `sessionId`, and optionally `model`, `agents[]`, `commands[]`, `skills[]`, `plugins[]`, `permissionMode` — the session's loaded inventory. |
| `textDelta` | `text` — a chunk of assistant message text. |
| `thinking` | `text` — extended-thinking text (only when the model emits it). |
| `toolCall` | `id`, `tool`, `input` (the tool's arguments). |
| `toolResult` | `id`, `output`, `isError`, `partial?`. |
| `finish` | `ok`; on ok: `result` (final text), `usd`, `tokens{input,output}`, `durationMs`; on not-ok: `reason` + the same cost fields. |
| `error` | `message`, `transient` (serialized from the thrown error). |
| `rateLimits` | `data` — Anthropic subscription quota snapshot (subscribers only). |

You usually only need `toolCall` / `textDelta` for a live progress UI; the
authoritative outcome is the **result** object below, not the `finish` event.

## Result schema

The final object for a run (`BridgeRunResult` in
[`src/engine/bridge.ts`](../src/engine/bridge.ts)):

```jsonc
{
  "ok": true,
  "action": "triage",
  "platform": "claude",
  "sessionId": "…",           // resumable via `resume`
  "model": "claude-…",
  "usd": 0.42,
  "tokens": { "input": 12000, "output": 900 },
  "durationMs": 38000,
  "output": { "verdict": "false-positive", "confidence": 0.9, "…": "…" },
  "outputRaw": "…",           // the agent's final message, verbatim
  "outputParseError": "…",    // present only when output===json but no JSON was found
  "loadedSkills": ["fp-check", "vigolium-scanner"],
  "missingSkills": [],
  "error": "…"                // present only when ok===false
}
```

- `output` is parsed from the **last fenced ` ```json ` block** in the agent's
  final message (falls back to any fenced block that parses, then the whole
  message). `null` with `outputParseError` set if nothing parsed. Only populated
  when the effective `output` mode is `json`.
- `outputRaw` is always the verbatim final message — parse it yourself if you
  need something the preset didn't emit as JSON.

## One-shot NDJSON contract (`--json`)

One JSON object per line on stdout:

```jsonc
{"kind":"ready","action":"triage","platform":"claude","cwd":"/abs/repo","model":null,"output":"json","skills":["fp-check","vigolium-scanner"],"authSource":"subscription"}
{"kind":"event","event":{"kind":"session","sessionId":"…","model":"claude-…"}}
{"kind":"event","event":{"kind":"toolCall","id":"…","tool":"Bash","input":{"command":"vigolium finding --id 42 --json --with-records"}}}
{"kind":"event","event":{"kind":"toolResult","id":"…","output":"…","isError":false}}
{"kind":"result","result":{ /* BridgeRunResult */ }}
```

- Line 1 is always `ready` (echoes the resolved plan). Then zero or more
  `event` lines. The last line is `result` (the result object is nested under
  `result`, same as the daemon).
- **Exit codes:** `0` when `result.ok`, `1` when the agent ran but `ok===false`,
  `2` for a fatal before the run (bad flags, missing binary). A fatal prints a
  single `{"kind":"bridge","ok":false,"error":"…"}` line instead of `result`.
- Without `--json`, the same run prints a human log + a pretty `output:` block;
  use `--json` for any programmatic caller.

## Daemon protocol (`bridge serve`)

Newline-delimited JSON in on stdin, out on stdout. Runs are concurrent and
demultiplexed by the caller-chosen `id`.

**Server → on start:**
```jsonc
{"kind":"ready-daemon","tasks":["exploit","plan","triage"],"defaultPlatform":"claude","cwd":"/abs/repo"}
```

**Client → run** (kick off a task):
```jsonc
{"id":"r1","method":"run","params":{"action":"triage","input":"{…finding…}","cwd":"/abs/repo","model":"sonnet"}}
```
**Server → for that run:**
```jsonc
{"id":"r1","kind":"accepted","action":"triage","platform":"claude","model":"sonnet","output":"json","skills":["fp-check","vigolium-scanner"],"authSource":"subscription"}
{"id":"r1","kind":"event","event":{ /* adapter event */ }}     // many
{"id":"r1","kind":"result","result":{ /* BridgeRunResult */ }} // exactly one, terminal
```

**Control messages:**
```jsonc
{"id":"r1","method":"cancel"}   // → {"id":"r1","kind":"cancelled"}; the run then emits its terminal result (ok:false)
{"method":"ping"}                // → {"kind":"pong"}
{"method":"shutdown"}            // → aborts in-flight runs, {"kind":"bye"}, exit 0
```

Error lines carry the offending `id` when known:
`{"id":"r1","kind":"error","error":"duplicate run id: r1"}`. A malformed input
line yields `{"kind":"error","error":"malformed request (invalid JSON)"}` and is
otherwise ignored.

Rules to implement against:
- Every `run` gets exactly one **terminal** line: `result` (normal) or `error`
  (setup failed, e.g. no binary / bad params). After that, the `id` is free to
  reuse.
- A `cancel` is acked immediately with `cancelled`, but the run still emits its
  terminal `result` a moment later (with `ok:false`). Don't treat `cancelled` as
  terminal.
- `id`s must be unique among *in-flight* runs; reuse after the terminal line.
- Auth is established **once** at launch (flags/env), not per request.
- Closing stdin drains in-flight runs, emits `bye`, and exits.

## Go client

### One-shot exec

```go
package bridge

import (
	"bufio"
	"context"
	"encoding/json"
	"os/exec"
)

// Result mirrors BridgeRunResult (see docs/bridge.md).
type Result struct {
	OK        bool            `json:"ok"`
	Action    string          `json:"action"`
	SessionID string          `json:"sessionId"`
	Model     string          `json:"model"`
	USD       float64         `json:"usd"`
	Tokens    struct{ Input, Output int } `json:"tokens"`
	Output    json.RawMessage `json:"output"`    // task-specific verdict/plan/PoC
	OutputRaw string          `json:"outputRaw"`
	Error     string          `json:"error,omitempty"`
}

type envelope struct {
	Kind   string          `json:"kind"`
	Event  json.RawMessage `json:"event"`
	Result *Result         `json:"result"`
}

// Run executes one bridge task and returns its result. onEvent (optional)
// receives each adapter event as raw JSON for a progress UI.
func Run(ctx context.Context, args []string, onEvent func(json.RawMessage)) (*Result, error) {
	cmd := exec.CommandContext(ctx, "vigolium-audit", append([]string{"bridge"}, append(args, "--json")...)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var result *Result
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20) // tool outputs can be large
	for sc.Scan() {
		var env envelope
		if json.Unmarshal(sc.Bytes(), &env) != nil {
			continue
		}
		switch env.Kind {
		case "event":
			if onEvent != nil {
				onEvent(env.Event)
			}
		case "result":
			result = env.Result
		}
	}
	_ = cmd.Wait() // exit code: 0 ok, 1 not-ok, 2 fatal — detail is in result
	return result, nil
}

// Triage is a typed convenience wrapper.
func Triage(ctx context.Context, repoDir, findingFile string, onEvent func(json.RawMessage)) (*Result, error) {
	return Run(ctx, []string{"triage", "--cwd", repoDir, "--input-file", findingFile}, onEvent)
}
```

### Daemon client

Spawn `bridge serve` once, read stdout in a single goroutine, and demux by `id`.

```go
package bridge

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sync"
)

type RunParams struct {
	Action     string   `json:"action,omitempty"`
	Agent      string   `json:"agent,omitempty"`
	Cwd        string   `json:"cwd,omitempty"`
	Prompt     string   `json:"prompt,omitempty"`
	Input      string   `json:"input,omitempty"`
	Skills     []string `json:"skills,omitempty"`
	Tools      []string `json:"tools,omitempty"`
	DenyTools  []string `json:"denyTools,omitempty"`
	Model      string   `json:"model,omitempty"`
	MaxTurns   int      `json:"maxTurns,omitempty"`
	Resume     string   `json:"resume,omitempty"`
	Output     string   `json:"output,omitempty"` // "json" | "text"
}

type request struct {
	ID     string     `json:"id,omitempty"`
	Method string     `json:"method"`
	Params *RunParams `json:"params,omitempty"`
}

// A live run: Events streams adapter events; Done delivers the terminal result.
type Run struct {
	Events chan json.RawMessage
	Done   chan *Result
}

type Client struct {
	cmd  *exec.Cmd
	stdin io.WriteCloser
	mu   sync.Mutex
	runs map[string]*Run
	seq  int
}

func NewClient(cwd string, extraArgs ...string) (*Client, error) {
	args := append([]string{"bridge", "serve", "--cwd", cwd, "--json"}, extraArgs...)
	cmd := exec.Command("vigolium-audit", args...)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &Client{cmd: cmd, stdin: stdin, runs: map[string]*Run{}}
	go c.readLoop(stdout)
	return c, nil
}

func (c *Client) readLoop(stdout io.Reader) {
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		var msg struct {
			ID     string          `json:"id"`
			Kind   string          `json:"kind"`
			Event  json.RawMessage `json:"event"`
			Result *Result         `json:"result"`
			Error  string          `json:"error"`
		}
		if json.Unmarshal(sc.Bytes(), &msg) != nil {
			continue
		}
		c.mu.Lock()
		run := c.runs[msg.ID]
		c.mu.Unlock()
		if run == nil {
			continue // ready-daemon / pong / bye / unassigned error
		}
		switch msg.Kind {
		case "event":
			run.Events <- msg.Event
		case "result":
			run.Done <- msg.Result
			c.finish(msg.ID)
		case "error":
			run.Done <- &Result{Error: msg.Error}
			c.finish(msg.ID)
		}
	}
}

func (c *Client) finish(id string) {
	c.mu.Lock()
	if run := c.runs[id]; run != nil {
		close(run.Events)
		delete(c.runs, id)
	}
	c.mu.Unlock()
}

func (c *Client) Run(p RunParams) (*Run, error) {
	c.mu.Lock()
	c.seq++
	id := fmt.Sprintf("r%d", c.seq)
	run := &Run{Events: make(chan json.RawMessage, 64), Done: make(chan *Result, 1)}
	c.runs[id] = run
	c.mu.Unlock()
	if err := c.send(request{ID: id, Method: "run", Params: &p}); err != nil {
		c.finish(id)
		return nil, err
	}
	return run, nil
}

func (c *Client) Cancel(id string) error { return c.send(request{ID: id, Method: "cancel"}) }

func (c *Client) Close() error {
	_ = c.send(request{Method: "shutdown"})
	return c.cmd.Wait()
}

func (c *Client) send(r request) error {
	b, _ := json.Marshal(r)
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := fmt.Fprintf(c.stdin, "%s\n", b)
	return err
}
```

Usage:

```go
client, _ := bridge.NewClient("./repo")
defer client.Close()

run, _ := client.Run(bridge.RunParams{Action: "triage", Input: findingJSON, Model: "sonnet"})
go func() { for ev := range run.Events { /* progress UI */ _ = ev } }()
result := <-run.Done
```

## Chaining triage → exploit

Every result carries a `sessionId`. Pass it as `resume` (flag `--resume`) on a
follow-up call to continue the *same conversation* — so `exploit` already has all
of `triage`'s context and file reads. Chain across processes (one-shot) or within
one daemon; either way it's the same session id.

## Refreshing the vigolium-scanner skill

The skill is vendored under `src/content/skills/vigolium-scanner/` so the
compiled binary is self-contained. Re-sync it from the scanner repo with:

```bash
bun run sync-scanner-skill                       # sibling ../vigolium
VIGOLIUM_REPO=/path/to/vigolium bun run sync-scanner-skill
```
