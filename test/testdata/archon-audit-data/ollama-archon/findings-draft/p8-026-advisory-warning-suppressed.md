Phase: 8
Sequence: 026
Slug: advisory-warning-suppressed
Verdict: VALID
Rationale: Tracer confirmed the warning is structurally suppressed for auto-approved commands; Advocate correctly notes it does not create new attack vectors but removes the last visibility layer for dangerous auto-approved commands.
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-B/debate.md

## Summary

The `isCommandOutsideCwd` function (approval.go:312-373) correctly detects when bash commands target paths outside the current working directory, including `~` home directory paths, `..` traversal, and absolute paths. However, its result is only used to set `isWarning=true` in the `RequestApproval` function (approval.go:498-506). When a command is auto-approved via `IsAllowed` (run.go:404), `RequestApproval` is never called, so the warning is structurally suppressed.

This means that all commands exploiting H-01 (pipe bypass), H-02 (shell expansion), H-03 (sed/find escalation), H-05 (multi-path escape) that target paths outside CWD will never trigger the outside-CWD warning.

## Location

- `x/agent/approval.go:498-506` -- `isCommandOutsideCwd` result used only in `RequestApproval` display
- `x/cmd/run.go:404` -- `!approval.IsAllowed(toolName, args)` gates `RequestApproval` call
- `x/agent/approval.go:312-373` -- `isCommandOutsideCwd` detection logic (correctly implemented but result discarded)

## Attacker Control

Indirect. The LLM benefits from the suppressed warning: auto-approved commands that target `~/.ssh/`, `/etc/`, or other external paths execute without any user-visible indication that they access paths outside the project.

## Trust Boundary Crossed

Visibility boundary. The user expected to see warnings for commands accessing paths outside the project. The auto-approval mechanism bypasses this visibility layer.

## Impact

- **Amplification**: All other findings (H-01 through H-06) are amplified by the absence of outside-CWD warnings
- **False sense of security**: The warning system exists in code but is architecturally dead for the most dangerous commands
- **Detection gap**: No logging or alerting when auto-approved commands access external paths

## Evidence

1. `approval.go:501-503`: `if isCommandOutsideCwd(cmd) { isWarning = true; warningMsg = "command targets paths outside project" }` -- only sets display variables
2. `run.go:404`: `} else if !skipApproval && !approval.IsAllowed(toolName, args) { result, err := approval.RequestApproval(...)` -- RequestApproval only called when IsAllowed returns false
3. When IsAllowed returns true (lines 400-403 for YoloMode, line 404 else branch not taken), code falls through to execution at line 436 without any warning display

## Reproduction Steps

1. Start agent session; approve `cat tools/a.go` (stores `cat:tools/`)
2. LLM issues `cat tools/a.go | tee ~/.ssh/authorized_keys` (H-01 pipe bypass)
3. `IsAllowed` returns true (prefix match on `cat:tools/`)
4. `RequestApproval` is NOT called -- `isCommandOutsideCwd` is never invoked
5. The "command targets paths outside project" warning is never displayed
6. User has no indication that the command wrote to `~/.ssh/authorized_keys`
