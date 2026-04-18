Phase: 10
Sequence: 032
Slug: allowlisted-prefix-bypasses-cwd-warning
Verdict: VALID
Rationale: isCommandOutsideCwd is only invoked inside RequestApproval; when a bash command matches an allowlisted prefix via IsAllowed, RequestApproval is never called, so the outside-cwd warning and path check are silently skipped.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-020-bash-pipe-semicolon-bypass.md
Origin-Pattern: AP-020

## Summary
The approval flow in `run.go:404` short-circuits to tool execution when `IsAllowed` returns true. `isCommandOutsideCwd` is only called inside `RequestApproval` (approval.go:503). Therefore, once a user has approved `"cat:tools/"` for the session, any subsequent command whose `extractBashPrefix` returns `"cat:tools/"` executes without calling `RequestApproval` — meaning the outside-cwd warning is never shown. Because `extractBashPrefix` only examines the first pipe segment (AP-020 root cause), a command like `cat tools/readme.md | tee /etc/crontab` extracts prefix `"cat:tools/"`, matches the allowlist, and executes directly, writing to `/etc/crontab` without any user notification.

## Location
`x/cmd/run.go:404` — `else if !skipApproval && !approval.IsAllowed(...)` short-circuit  
`x/agent/approval.go:389-423` — `IsAllowed` returns true for prefix match, never reaching cwd check  
`x/agent/approval.go:501-505` — `isCommandOutsideCwd` only inside `RequestApproval`  
`x/agent/approval.go:204-207` — `extractBashPrefix` splits only on `|`

## Attacker Control
After any one user approval of a `cat:tools/` command (legitimate use), subsequent LLM tool calls with piped payloads are fully auto-executed.

## Trust Boundary Crossed
Session allowlist entry -> unrestricted write access outside cwd with no user warning. Allowlist approval semantics are violated: user approved read-only `cat` in a directory but gets silent write to system paths.

## Impact
Arbitrary file write to any path writable by the process (crontab, ssh authorized_keys, etc.) without any prompt or warning. Severity HIGH: requires one prior legitimate approval (low barrier), then fully silent.

## Evidence
```go
// run.go:404 — skips RequestApproval entirely when IsAllowed returns true
} else if !skipApproval && !approval.IsAllowed(toolName, args) {
    result, err := approval.RequestApproval(...)  // isCommandOutsideCwd only here
    ...
}
// else branch at run.go:430: just prints "running:" and executes

// approval.go:204-207 — extractBashPrefix sees only first pipe segment
parts := strings.Split(command, "|")
firstCmd := strings.TrimSpace(parts[0])
// "cat tools/readme.md | tee /etc/crontab" -> firstCmd = "cat tools/readme.md"
// returns "cat:tools/"  -- tee /etc/crontab unchecked
```

## Reproduction Steps
1. Start `ollama run` with bash tool.
2. Ask model to `cat tools/README.md`. Approve with "Allow for this session".
3. Allowlist now contains prefix `"cat:tools/"`.
4. Ask model to read a file and save somewhere. Model emits: `cat tools/README.md | tee /etc/crontab`
5. `IsAllowed` returns true (prefix match), `RequestApproval` is never called, command executes silently.
