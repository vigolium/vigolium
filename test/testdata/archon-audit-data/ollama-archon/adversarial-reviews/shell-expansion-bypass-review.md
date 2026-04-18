Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Unit test confirmed IsAllowed returns true for command substitution, backtick, and brace expansion payloads after a legitimate cat:tools/ prefix is stored; IsDenied has no patterns matching shell metacharacters $() or backticks.
Severity-Original: CRITICAL
Severity-Final: HIGH
PoC-Status: executed

## Cold Verification Summary

The shell expansion bypass vulnerability in the agent approval system is CONFIRMED. The approval prefix matching in `x/agent/approval.go` uses shell-unaware Go string operations (`strings.Fields`, `path.Clean`, `path.Dir`) that cannot interpret shell metacharacters. Command substitution (`$(...)`) and backtick syntax pass through all validation and produce prefixes that match previously approved directory prefixes via exact or hierarchical matching. The `IsDenied` function has no patterns for shell metacharacters. Commands are then executed unmodified via `bash -c` (bash.go:64), which evaluates all shell expansions.

Severity downgraded from CRITICAL to HIGH due to realistic but meaningful preconditions: requires a prior user approval to exist and requires LLM manipulation via prompt injection.

## Corrections

1. The brace expansion example targeting `/etc/passwd` is blocked by `IsDenied` (the finding overstates this vector). Brace expansion to non-denied paths remains exploitable.
2. For the command substitution payload, the prefix match succeeds via exact prefix lookup (`a.prefixes["cat:tools/"]`), not via `matchesHierarchicalPrefix` as implied.

## Evidence

Test file: `archon/real-env-evidence/shell-expansion-bypass/test_output.go`
Test output confirmed all three bypass vectors (command substitution, backticks, brace expansion to non-denied paths).
