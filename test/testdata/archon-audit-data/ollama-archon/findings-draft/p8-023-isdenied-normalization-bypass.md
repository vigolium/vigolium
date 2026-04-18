Phase: 8
Sequence: 023
Slug: isdenied-normalization-bypass
Verdict: VALID
Rationale: Tracer confirmed the normalization bypass is real; Advocate correctly identified that full exploitation requires YoloMode. The deny-list bypass is meaningful as a defense-in-depth failure that compounds with other approval bypasses.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: check-3-ambiguous -- trust boundary crossing partial in default mode (user still sees command)
Debate: archon/chamber-workspace/chamber-B/debate.md

## Summary

The `IsDenied` function (approval.go:174-191) uses raw `strings.Contains` for pattern matching without whitespace normalization. Inserting extra whitespace between command tokens (e.g., `rm  -rf` with double space) bypasses all deny patterns that contain single spaces. This defeats the deny-list defense layer. In YoloMode, this enables direct execution of denied commands. In default mode, the command proceeds to user approval but the deny-list safety net is absent.

## Location

- `x/agent/approval.go:174-191` -- `IsDenied` function
- `x/agent/approval.go:179` -- `strings.Contains(commandLower, strings.ToLower(pattern))` raw substring match
- `x/agent/approval.go:94-121` -- `denyPatterns` list with single-space patterns

## Attacker Control

The LLM controls whitespace in commands:
1. `rm  -rf /` (double space) bypasses `"rm -rf"` pattern
2. `sudo  rm -rf /` bypasses `"sudo "` (extra space after sudo, though `"rm -rf"` would still match unless also double-spaced)
3. `chmod  777 /` bypasses `"chmod 777"` pattern
4. Tab characters: `rm\t-rf /` -- `strings.Contains` won't match `"rm -rf"` against tab-separated tokens

## Trust Boundary Crossed

Defense-in-depth boundary. `IsDenied` is meant to be an absolute block regardless of approval state. The bypass removes this safety layer. In YoloMode, this is the ONLY remaining defense, so its bypass crosses the last trust boundary.

## Impact

- In YoloMode: Direct execution of denied destructive commands (rm -rf, sudo, chmod 777)
- In default mode: Deny-list safety net removed; command proceeds to user approval without the "blocked" warning
- Compounds with other findings: If combined with H-01 pipe bypass, denied commands in pipe tails are never checked by IsDenied anyway

## Evidence

1. `approval.go:179`: `strings.Contains(commandLower, strings.ToLower(pattern))` -- literal substring match
2. `approval.go:95`: `"rm -rf"` pattern contains single space
3. No `strings.Fields`-based or regex-based normalization before matching
4. No whitespace collapsing (`strings.Join(strings.Fields(cmd), " ")`) applied

## Reproduction Steps

1. In YoloMode session, LLM issues `rm  -rf /tmp/important-data` (double space)
2. `IsDenied`: `strings.Contains("rm  -rf /tmp/important-data", "rm -rf")` returns false
3. Command passes IsDenied check, YoloMode skips approval, command executes
4. Without YoloMode: same IsDenied bypass, but user sees the command in approval prompt
