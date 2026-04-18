Phase: 8
Sequence: 067
Slug: yolo-mode-denylist-quoting-bypass
Verdict: VALID
Rationale: `--experimental-yolo` skips `approval.IsAllowed` entirely (`x/cmd/run.go:400-402`) leaving `IsDenied` (`x/cmd/run.go:378`) as the sole remaining guard — and `IsDenied` uses `strings.Contains` with literal patterns that are trivially defeated by bash quoting (`r''m`, `r""m`, `${IFS}`, `$'\x72m'`). Advocate notes the flag is explicit opt-in with a warning banner, but the functional issue is that there IS a guard (IsDenied) in yolo mode, and that guard is broken — a subtle but real hardening gap.
Severity-Original: HIGH
PoC-Status: executed
Pre-FP-Flag: check-5-ambiguous (yolo mode is explicit opt-in with warning; the bug is that yolo's sole guard is a broken denylist)
Debate: archon/chamber-workspace/chamber-04/debate.md
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Direct invocation of `agent.IsDenied` at main@57653b8e returns false for `r''m -rf /`, `r""m -rf /`, `'rm' -rf /`, `rm${IFS}-rf${IFS}/`, and `$'\x72m' -rf /`, and `bash -c` on each bypass string deletes files — confirming both halves of the attack on the real codebase.
Severity-Final: MEDIUM
PoC-Status: executed

## Summary

The original pre-seed claimed "yolo mode skips IsDenied" — Tracer corrected this to "yolo mode still runs IsDenied; IsAllowed is the skipped check". That distinction matters: under yolo, IsDenied IS supposed to be a safety floor preventing the most egregious commands (`rm -rf`, `sudo`, `dd of=/dev/`). But IsDenied uses `strings.Contains` with literal patterns on the raw command string:

```go
// x/agent/approval.go:94-122 — denyPatterns (excerpts)
{Pattern: "rm -rf", ...},
{Pattern: "sudo ", ...},
{Pattern: "/etc/shadow", ...},
...

// x/agent/approval.go:175-193 — IsDenied
for _, p := range denyPatterns {
    if strings.Contains(lower, strings.ToLower(p.Pattern)) {
        return true, ...
    }
}
```

Bash normalizes quoting AFTER the denylist has looked at the raw string:

- `r''m -rf /` — `strings.Contains("r''m -rf /", "rm -rf")` is false; bash expands `r''m` to `rm`.
- `r""m -rf /` — ditto with double-quote empty string.
- `$'\x72m' -rf /` — hex-escape expansion; bash interprets at runtime.
- `rm${IFS}-rf${IFS}/` — IFS-expansion bypass (different separator, same runtime effect).
- `'rm' -rf /` — leading quoting also breaks contains (`"rm` != `rm `).

The denylist is the only guard in yolo mode; every pattern is a string-literal whose bypass is trivial.

## Location

- `x/agent/approval.go:94-122` — `denyPatterns`
- `x/agent/approval.go:175-193` — `IsDenied` — `strings.Contains` over raw command
- `x/cmd/run.go:375-387` — `IsDenied(cmd)` call, unconditional in all modes
- `x/cmd/run.go:400-402` — `if opts.YoloMode { ... }` branch that skips `IsAllowed`
- `cmd/cmd.go:2161` — flag registration: `Bool("experimental-yolo", false, "Skip all tool approval prompts (use with caution)")`
- `x/cmd/run.go:718-720` — startup banner: "warning: yolo mode - all tool approvals will be skipped"

## Attacker Control

LLM output emitting a denylist-bypassing command. Requires only that the user opted into `--experimental-yolo`.

## Trust Boundary Crossed

B11 (LLM/model → host).

## Impact

Instant RCE in yolo mode — no user prompt at all. The flag name "experimental-yolo" and its description "use with caution" plus the runtime banner constitute documentation that the user accepts risk; however, the specific failure mode (denylist bypassable via shell quoting) is NOT documented. A user who reads "yolo mode skips approval prompts" reasonably expects the denylist to still block `rm -rf /` — that expectation is incorrect.

Distinct from p8-065 because:
- p8-065 is approved-mode (cache collision after one innocuous approval)
- This finding is yolo-mode (no prompt at all; IsDenied is the floor and IsDenied is broken)

## Evidence

Tracer confirmed the exact code: `strings.Contains` with literal pattern at `approval.go:175-193`; yolo skip at `run.go:400-402`.

Advocate: "Pattern-6 MATCH — exploitation requires the user to set `--experimental-yolo`, which is explicitly branded 'use with caution' and prints a warning banner." Synthesizer accepts the opt-in framing but retains HIGH (not LOW) because: (a) the denylist in yolo mode is a publicly-visible safety claim that does NOT hold, (b) "skip approval prompts" is a weaker warning than "skip all safety checks including string filtering", (c) hardening the denylist is cheap.

Adversarial reviewer independently reproduced both halves at main@57653b8e: (i) `IsDenied` returns false for `r''m -rf /`, `r""m -rf /`, `'rm' -rf /`, `rm${IFS}-rf${IFS}/`, and `$'\x72m' -rf /` when compiled against the real `x/agent` package; (ii) `bash -c` on each of those strings deletes actual files. Full log at `archon/real-env-evidence/yolo-mode-denylist-quoting-bypass/isdenied-output.txt`.

## Reproduction Steps

1. `ollama run --agent --experimental-yolo`.
2. Prompt-injected LLM emits: `cat tools/x && r''m -rf ~/.ssh`.
3. `IsDenied("cat tools/x && r''m -rf ~/.ssh")` → false (substring match fails on `r''m`).
4. Yolo branch fires: command executes via `bash -c`. `/bin/bash` expands `r''m` → `rm`. `~/.ssh` is removed.

Remediation:
- Tokenize the command through `shlex`-equivalent before applying the denylist; match per-token after quoting is resolved.
- Add `${IFS}` / `$'...'` / `"..."` / `'...'` patterns to the denylist as a stop-gap.
- Extend the yolo banner: "Warning: yolo mode skips approval prompts. The denylist is a best-effort filter and can be bypassed by quoting. Only use with trusted models/prompts."
