Phase: 8
Sequence: 025
Slug: multi-path-scope-escape
Verdict: VALID
Rationale: Tracer confirmed first-path-only evaluation with specific grep example; Advocate found no multi-argument checking. Prefix accumulation amplifies all other approval bypass vulnerabilities.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-B/debate.md

## Summary

The `extractBashPrefix` function (approval.go:228-285) returns immediately after finding the first path-like argument, ignoring all subsequent arguments. Commands like `grep -r "" api/ /home/user/secrets/` have only the first path (`api/`) checked; the second path (`/home/user/secrets/`) is never examined. This enables scope escape -- reading files from any directory while the prefix check only validates the first directory.

Additionally, the prefix accumulation pattern (no aggregate scope review across a session) means individually reasonable approvals compound into near-unrestricted filesystem access: `cat:tools/` + `grep:api/` + `sed:tools/` + `find:tools/` collectively enable read, write, search, and execution across multiple directories.

## Location

- `x/agent/approval.go:284` -- `return fmt.Sprintf("%s:%s/", baseCmd, dir)` returns after first path arg
- `x/agent/approval.go:228-285` -- first-pass loop with early return
- `x/agent/approval.go:459-477` -- `AddToAllowlist` accumulates prefixes without aggregate review

## Attacker Control

The LLM controls all arguments to commands:
1. `grep -r "pattern" api/ /etc/` -- second path arg reads from /etc/
2. `grep -r "" tools/ ~/` -- reads user's home directory
3. Multi-turn: LLM gradually accumulates `cat:tools/`, `grep:src/`, `find:./`, `sed:tools/` prefixes

## Trust Boundary Crossed

User approval boundary for individual paths. The user approved access to `api/` but the command reads from additional directories. The accumulation crosses a scope boundary -- no mechanism reviews the aggregate set of permissions.

## Impact

- **Arbitrary file read**: Additional path arguments read from any filesystem location
- **Scope creep**: Multi-turn prefix accumulation creates increasingly broad access
- **Amplification**: Combined prefixes enable H-01, H-02, H-03 attacks across multiple directories

## Evidence

1. `approval.go:284`: Early return after first path -- `return fmt.Sprintf("%s:%s/", baseCmd, dir)`
2. `approval.go:228-285`: Loop `for _, arg := range fields[1:]` with return inside, not continue
3. `approval.go:469`: `a.prefixes[prefix] = true` -- each approval adds to prefix set, no removal or review
4. No mechanism to display or audit accumulated prefixes

## Reproduction Steps

1. Start agent session; approve `grep -r "TODO" api/` (stores `grep:api/`)
2. LLM issues `grep -r "" api/ /etc/passwd` 
3. `extractBashPrefix` finds `api/` as first path arg, returns `grep:api/`
4. Matches stored prefix, auto-approved
5. bash executes `grep -r "" api/ /etc/passwd` -- reads both `api/` and `/etc/passwd`
6. For accumulation: across multiple turns, LLM obtains `cat:tools/`, `grep:api/`, `sed:tools/`, `find:./`
7. With `find:./`, the LLM can `find . -name "*.env"` to discover sensitive files, then use `cat:tools/` + pipe bypass (H-01) to exfiltrate them
