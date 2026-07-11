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
| `--permission <profile>` | `permission` | Least-privilege profile: `read-only` / `workspace-write` / `full-access`. Overrides the task default. |
| `--network` / `--no-network` | `network` (bool) | Allow/deny network egress. Codex **enforces** it via its OS sandbox; Claude has no per-run egress control and treats it as advisory (the system prompt carries the intent). Profile default otherwise. |
| — | `timeoutMs` (daemon only) | Per-run wall-clock deadline in ms (covers queue wait + retries). Falls back to the daemon default (`VIGOLIUM_AUDIT_BRIDGE_TIMEOUT_MS`, off by default). |
| `--no-bypass-permissions` | `bypassPermissions: false` | Explicit override. By default the resolved profile decides — always bypass in a headless run (the sandbox / tool deny-list is the real boundary, not a prompt the agent can't answer). |
| `--api-key` / `--oauth-token` / `--oauth-cred-file` | — (set once at daemon launch) | Per-run auth; restored on exit. |

At least one of `prompt` / `input` must be non-empty, or the run errors before
starting.

### Permission profiles (least privilege)

Each task runs under a profile that bounds what it can touch. A profile resolves
to a Codex OS sandbox (enforced), a Claude tool deny-list + advisory prompt
(best-effort — a headless run can't answer a permission prompt), and a network
scope:

| Profile | Codex sandbox | Network | Claude tools | Default for |
|---|---|---|---|---|
| `read-only` | `read-only` | off (opt-in) | write family (`Write`/`Edit`/`MultiEdit`/`NotebookEdit`) denied | `plan`, `triage` |
| `workspace-write` | `workspace-write` | on | unrestricted | `exploit` |
| `full-access` | `danger-full-access` | on | unrestricted | `run`, and any task without a `permission:` |

`triage` is `read-only` but opts network **on** (`network: true`) so it can
replay a request to confirm exploitability; it still cannot write the workspace.
A task or request can override both: `--permission workspace-write --network` to
loosen, or `--permission read-only --no-network` to tighten. Presets declare
their profile in frontmatter (`permission:` / `network:`); a task with neither
falls back to `full-access` for backward compatibility.

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
  "ok": true,                 // compatibility summary === transportOk
  "transportOk": true,        // the adapter run completed (no error / finish.ok)
  "contractOk": true,         // json output validated? true/false, or null for text
  "action": "triage",
  "platform": "claude",
  "sessionId": "…",           // resumable via `resume`
  "model": "claude-…",
  "usd": 0.42,
  "tokens": { "input": 12000, "output": 900 },
  "durationMs": 38000,
  "attempts": 1,              // >1 means a transient/quota retry fired
  "output": { "verdict": "false-positive", "confidence": 0.9, "…": "…" },
  "outputRaw": "…",           // the agent's final message, verbatim
  "outputParseError": "…",    // present only when output===json but no JSON was found
  "loadedSkills": ["fp-check", "vigolium-scanner"],
  "missingSkills": [],
  "error": "…"                // present only when transportOk===false
}
```

- **Three independent outcomes** — don't overload `ok`:
  - `transportOk` — did the run *execute*? `false` = adapter error / non-ok finish
    (see `error`). `ok` mirrors this for older callers.
  - `contractOk` — was the *requested output shape* produced? `true`/`false` for
    `output:"json"`, `null` for `output:"text"` (not requested). `transportOk:true`
    + `contractOk:false` = the agent ran fine but its final message wasn't valid
    JSON (see `outputParseError`).
  - the **task verdict** lives inside `output` (e.g. `verdict`, `exploited`). A
    legitimate negative (`"exploited": false`) is `transportOk:true` +
    `contractOk:true` — distinct from a malformed result.
- `output` is parsed from the **last fenced ` ```json ` block** in the agent's
  final message (falls back to any fenced block that parses, then the whole
  message). `null` with `outputParseError` set if nothing parsed. Only populated
  when the effective `output` mode is `json`.
- `outputRaw` is always the verbatim final message — parse it yourself if you
  need something the preset didn't emit as JSON.
- `attempts` counts adapter tries. A **cold** transient failure (429/5xx/idle
  timeout that lands *before any output streams*) or a quota limit is retried
  with backoff; a failure *after* progress is **not** replayed (a half-run
  exploit/replay must not re-fire). `usd`/`tokens`/`durationMs` are cumulative
  across attempts. Tune with `VIGOLIUM_AUDIT_TRANSIENT_MAX_RETRIES` /
  `…_TRANSIENT_BACKOFF_MS` / `…_QUOTA_MAX_RETRIES`.

## One-shot NDJSON contract (`--json`)

One JSON object per line on stdout:

```jsonc
{"kind":"ready","action":"triage","platform":"claude","cwd":"/abs/repo","model":null,"output":"json","permission":"read-only","skills":["fp-check","vigolium-scanner"],"requestedSkills":["fp-check"],"authSource":"subscription"}
{"kind":"event","event":{"kind":"session","sessionId":"…","model":"claude-…"}}
{"kind":"event","event":{"kind":"toolCall","id":"…","tool":"Bash","input":{"command":"vigolium finding --id 42 --json --with-records"}}}
{"kind":"event","event":{"kind":"toolResult","id":"…","output":"…","isError":false}}
{"kind":"result","result":{ /* BridgeRunResult */ }}
```

- Line 1 is always `ready` (echoes the resolved plan). Then zero or more
  `event` lines. The last line is `result` (the result object is nested under
  `result`, same as the daemon).
- `skills` on `ready`/`accepted` is the set that will **actually load** — it
  includes the always-on `vigolium-scanner`, and is empty on Codex (no plugin
  mechanism). `requestedSkills` is what the caller asked for; compare the two to
  detect a platform that dropped skills. The post-run `loadedSkills` /
  `missingSkills` on the result reflect the real plugin build.
- **Exit codes:** `0` when `result.ok`, `1` when the agent ran but `ok===false`,
  `2` for a fatal before the run (bad flags, missing binary). A fatal prints a
  single `{"kind":"bridge","ok":false,"error":"…"}` line instead of `result`.
- Without `--json`, the same run prints a human log + a pretty `output:` block;
  use `--json` for any programmatic caller.

## Daemon protocol (`bridge serve`)

Newline-delimited JSON in on stdin, out on stdout. Runs are concurrent and
demultiplexed by the caller-chosen `id`. Every request is schema-validated before
dispatch (see [`bridge-protocol.ts`](../src/cli/bridge-protocol.ts)); a malformed
one is rejected structurally instead of crashing the daemon.

**Server → on start** (advertises the protocol version and scheduler limits):
```jsonc
{"kind":"ready-daemon","protocolVersion":1,"tasks":["exploit","plan","triage"],"defaultPlatform":"claude","cwd":"/abs/repo","limits":{"maxConcurrent":4,"maxQueued":64,"defaultTimeoutMs":0}}
```

**Client → run** (kick off a task):
```jsonc
{"id":"r1","method":"run","params":{"action":"triage","input":"{…finding…}","cwd":"/abs/repo","model":"sonnet","timeoutMs":120000}}
```
**Server → for that run:**
```jsonc
{"id":"r1","kind":"queued","position":2}                        // only if it had to wait for a slot
{"id":"r1","kind":"accepted","protocolVersion":1,"action":"triage","platform":"claude","model":"sonnet","output":"json","permission":"read-only","skills":["fp-check","vigolium-scanner"],"requestedSkills":["fp-check"],"authSource":"subscription"}
{"id":"r1","kind":"event","event":{ /* adapter event */ }}      // many
{"id":"r1","kind":"result","result":{ /* BridgeRunResult */ }}  // exactly one terminal
```

**Control messages:**
```jsonc
{"id":"r1","method":"cancel"}    // → exactly one {"id":"r1","kind":"cancelled"} terminal (no separate result)
{"method":"ping"}                // → {"kind":"pong"}
{"method":"shutdown"}            // → aborts in-flight + queued runs (each gets a cancelled terminal), {"kind":"bye"}, exit 0
```

**Terminal / error taxonomy.** A run ends in exactly one of: `result` (ran),
`cancelled` (cancel / shutdown), or `error` (with a stable `code`). Non-run
errors (bad request, cancel of an unknown id) also use `error`:

```jsonc
{"id":"r1","kind":"error","code":"invalid_request","retryable":false,"error":"invalid run request: params.skills: expected array, received string"}
```

| `code` | Meaning | `retryable` |
|---|---|---|
| `invalid_request` | Malformed JSON, unknown method, wrong field type, duplicate id, cancel of an unknown id. | `false` |
| `queue_full` | `maxConcurrent + maxQueued` reached; run not accepted. | `true` |
| `deadline_exceeded` | Run passed its `timeoutMs` (or the daemon default). | `true` |
| `internal_error` | Setup threw (e.g. no binary) or an unexpected failure. | `false` |

Scheduler limits come from env: `VIGOLIUM_AUDIT_BRIDGE_MAX_CONCURRENT` (4),
`…_MAX_QUEUED` (64), `…_TIMEOUT_MS` (0 = no default deadline; per-run `timeoutMs`
still applies).

Rules to implement against:
- **Exactly one terminal per accepted run**: `result`, `cancelled`, or `error`.
  Treat all three as terminal — the earlier "cancel is acked, then a result
  follows" behavior is gone; a cancelled run emits **only** `cancelled`. After
  the terminal, the `id` is free to reuse.
- A `run` that has to wait for a concurrency slot first emits `queued`
  (non-terminal) with its 1-based `position`, then `accepted` when it starts.
- `queue_full` and `deadline_exceeded` are `retryable:true` — back off and
  resubmit (a new `id`).
- `id`s must be unique among *in-flight / queued* runs; reuse after the terminal.
- Auth is established **once** at launch (flags/env), not per request.
- `shutdown` aborts everything and flushes `bye` before exit; closing stdin
  drains in-flight + queued runs, then emits `bye` and exits. `bye` is flushed to
  the pipe (no truncation under a slow reader). A dead reader (EPIPE) aborts runs
  and exits quietly.

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
	OK          bool            `json:"ok"`          // == TransportOK
	TransportOK bool            `json:"transportOk"` // adapter run completed
	ContractOK  *bool           `json:"contractOk"`  // json validated? nil for text
	Action      string          `json:"action"`
	Permission  string          `json:"permission"`
	SessionID   string          `json:"sessionId"`
	Model       string          `json:"model"`
	USD         float64         `json:"usd"`
	Tokens      struct{ Input, Output int } `json:"tokens"`
	Attempts    int             `json:"attempts"`
	Output      json.RawMessage `json:"output"`    // task-specific verdict/plan/PoC
	OutputRaw   string          `json:"outputRaw"`
	Error       string          `json:"error,omitempty"`
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
	Output     string   `json:"output,omitempty"`     // "json" | "text"
	Permission string   `json:"permission,omitempty"` // read-only | workspace-write | full-access
	Network    *bool    `json:"network,omitempty"`
	TimeoutMs  int      `json:"timeoutMs,omitempty"`
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
			ID       string          `json:"id"`
			Kind     string          `json:"kind"`
			Event    json.RawMessage `json:"event"`
			Result   *Result         `json:"result"`
			Error    string          `json:"error"`
			Code     string          `json:"code"`     // on kind:error
			Position int             `json:"position"` // on kind:queued
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
		case "result": // terminal
			run.Done <- msg.Result
			c.finish(msg.ID)
		case "cancelled": // terminal (cancel / deadline via error, or shutdown)
			run.Done <- &Result{Error: "cancelled"}
			c.finish(msg.ID)
		case "error": // terminal (msg.Code: invalid_request | queue_full | deadline_exceeded | internal_error)
			run.Done <- &Result{Error: msg.Error}
			c.finish(msg.ID)
			// queued (non-terminal) carries msg.Position; ignore or surface as progress.
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
