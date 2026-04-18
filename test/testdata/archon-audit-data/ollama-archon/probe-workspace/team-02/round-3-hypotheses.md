# Round 3 Hypotheses — Causal Verification
# Causal Verifier: Counterfactual and intervention tests applied to all findings

## Verification of CROSS-01: Universal IsDenied Bypass + Pipe Target Write

**Question**: Does `cat tools/a.go | base64 -d | bash` pass IsDenied AND get approved via `cat:tools/` prefix?

**Counterfactual test — IsDenied**:
- Input: `cat tools/a.go | base64 -d | bash`
- Lowercased: `cat tools/a.go | base64 -d | bash`
- denyPatterns check: `rm -rf`? NO. `sudo `? NO. `nc `? NO (must match "nc " with trailing space; `| bash` does not match). `/etc/shadow`? NO. `/etc/passwd`? NO.
- denyPathPatterns: `.env`? NO. `.key`? NO.
- **Result: IsDenied returns FALSE** — command PASSES deny check

**Counterfactual test — extractBashPrefix**:
- `strings.Split("cat tools/a.go | base64 -d | bash", "|")` → `["cat tools/a.go ", " base64 -d ", " bash"]`
- `firstCmd = "cat tools/a.go"`
- `fields = ["cat", "tools/a.go"]`
- `baseCmd = "cat"` → in safeCommands
- `arg = "tools/a.go"` → contains `/` → path-like; not absolute; `path.Clean = "tools/a.go"`; `path.Dir = "tools"`
- Returns `"cat:tools/"`
- `matchesHierarchicalPrefix("cat:tools/")` with stored `"cat:tools/"` → `strings.HasPrefix("tools/", "tools/")` = TRUE
- **Result: IsAllowed returns TRUE** — command APPROVED without prompt

**Intervention**: Removing `| base64 -d | bash` makes the command safe. Adding it makes it arbitrary-code-execution. The approval system cannot distinguish between these two because pipe tail is structurally invisible to all approval logic.

**Verdict: CONFIRMED CRITICAL** — full pipe chain auto-approved when any `cat:tools/` prefix is stored.

---

## Verification of PH-01 (Pipe Target Tee)

**Counterfactual**: If `tee` were added to denyPatterns, `cat tools/a.go | tee /etc/cron.d/x` would be blocked.
**Intervention test**: Change `strings.Split(command, "|")` to `strings.FieldsFunc(command, func(r rune) bool { return r == '|' || r == ';' || r == '&' })` in `extractBashPrefix` and validate each segment. This would require ALL pipe segments to be safe commands in the approved directory.
**Code confirmation**:
- `extractBashPrefix` line 206: `parts := strings.Split(command, "|")` → only first part examined
- `denyPatterns` (lines 95-122): `tee` absent, `bash` absent, `sh` absent, `base64` absent
- **Verdict: CONFIRMED CRITICAL**

---

## Verification of PH-02 (sed -i Escalation)

**Counterfactual**: If `sed` were removed from `safeCommands` OR if the `-i` flag triggered a separate prompt, this would be blocked.
**Code confirmation**:
- `safeCommands` (line 218): `"sed": true` — confirmed
- extractBashPrefix processes `sed -i 's/x/y/' tools/a.go`: `baseCmd="sed"` (safeCommand), first path arg is `tools/a.go` → `"sed:tools/"`
- The `-i` flag is treated as just another flag (starts with `-`, skipped) — no special handling
- **Verdict: CONFIRMED HIGH**

---

## Verification of PH-03 (find -exec bash)

**Counterfactual test for `find tools/ -exec bash {} \;`**:
- IsDenied: does it contain `rm -rf`? NO. `sudo `? NO. None of the deny patterns match `bash` standalone.
- `extractBashPrefix("find tools/ -exec bash {} \\;")`:
  - `baseCmd = "find"` → safeCommand
  - First non-flag arg: `tools/` → contains `/` → path-like; `path.Clean("tools/") = "tools"`, `path.Dir("tools/") = "tools"` (isDir=true so `dir = "tools"`)
  - Returns `"find:tools/"`
- With stored `"find:tools/"` → auto-approved
- bash executes `find tools/ -exec bash {} \;` — runs every file in tools/ as a bash script
**Verdict: CONFIRMED HIGH**

---

## Verification of PH-04 (Command Substitution)

**Counterfactual test**: `cat tools/$(id)/a.go`
- `strings.Fields` → `["cat", "tools/$(id)/a.go"]`
- First non-flag arg: `"tools/$(id)/a.go"` → contains `/` → path-like
- `path.IsAbs("tools/$(id)/a.go")` = false (doesn't start with `/`)
- `path.Clean("tools/$(id)/a.go")` = `"tools/$(id)/a.go"` (no `..` components to remove; `$()` is opaque)
- `strings.HasPrefix(cleaned, "..")` = false
- `strings.Contains(arg, "..")` = false — sibling check NOT triggered
- `path.Dir("tools/$(id)/a.go")` = `"tools/$(id)"` — wait: `path.Dir` of `tools/$(id)/a.go` → removes last element → `"tools/$(id)"`
- Returns `"cat:tools/$(id)/"` — NOT `"cat:tools/"`!
- So this exact variant would NOT match stored `"cat:tools/"` because `matchesHierarchicalPrefix("cat:tools/$(id)/")` checks `strings.HasPrefix("tools/$(id)/", "tools/")` = TRUE! The stored `"cat:tools/"` is a prefix of `"tools/$(id)/"`.
- **Result: CONFIRMED** — `cat tools/$(id)/a.go` is auto-approved because `"tools/$(id)/"` starts with `"tools/"` (hierarchical match)
**Verdict: CONFIRMED CRITICAL** — subshell in path component auto-approved via hierarchical prefix match

---

## Verification of PH-09 (SSH authorized_keys)

**Counterfactual test**:
- Command: `cat tools/pubkey.go | tee ~/.ssh/authorized_keys`
- IsDenied scan: `.ssh/id_rsa`? command contains `.ssh/authorized_keys`, not `.ssh/id_rsa` → NO. `.ssh/id_dsa`? NO. `.ssh/id_ecdsa`? NO. `.ssh/id_ed25519`? NO. `.ssh/config`? NO. `.ssh/authorized_keys` is NOT in any deny pattern.
- extractBashPrefix: pipe split → `cat tools/pubkey.go` → `cat:tools/`
- matchesHierarchicalPrefix with stored `cat:tools/` → TRUE
- **Verdict: CONFIRMED CRITICAL** — `.ssh/authorized_keys` is the ONLY critical SSH file not in denyPathPatterns; all key files (id_rsa, id_dsa, id_ecdsa, id_ed25519, config) are blocked but authorized_keys is not.

---

## Verification of CROSS-02 (grep multi-path + semicolon)

**Counterfactual test**: `grep -r "" api/ /etc/ ; id > /tmp/out`
- IsDenied: no deny pattern in this string
- extractBashPrefix splits on `|` only. Full string taken as `firstCmd` (no pipe). `fields = ["grep", "-r", "\"\"", "api/", "/etc/", ";", "id", ">", "/tmp/out"]`
- First non-flag path arg: `""` — no `/` → skip. `api/` → contains `/` → path-like. Not absolute. `path.Clean("api/")` = `"api"`. `dir = "api"`. Returns `"grep:api/"`.
- Wait: but `;` is also in the fields list. extractBashPrefix just picks up the first path-containing arg (api/) and ignores everything after including `;`.
- With stored `grep:api/` → auto-approved.
- bash executes: grep on both `api/` AND `/etc/`; then `;` runs `id > /tmp/out`
**Verdict: CONFIRMED HIGH** for grep extra-path reads; CONFIRMED HIGH for semicolon injection after grep

---

## Verification of PH-11 (IsDenied double-space bypass)

**Counterfactual test**: `rm  -rf /tmp/important` (double space)
- `IsDenied`: `commandLower = "rm  -rf /tmp/important"`. `strings.Contains("rm  -rf /tmp/important", "rm -rf")` = FALSE (double space vs single space)
- **Result: IsDenied returns FALSE** — double-space rm -rf bypasses deny list
**Intervention**: `strings.Fields` followed by rejoin with single space before IsDenied check would fix this. Currently no normalization.
**Verdict: CONFIRMED HIGH**

---

## Verification of PH-14 (fallbackApproval non-TTY default)

**Code analysis**: `fallbackApproval` (line 949-971):
- `fmt.Scanln(&input)` — if stdin is closed/EOF, `fmt.Scanln` returns an error and `input` remains `""` (empty string)
- `switch input { case "1": ApprovalOnce; case "2": ApprovalAlways; default: ApprovalDeny }`
- Empty string hits `default` → **returns ApprovalDeny**
- **Result: SAFE in non-TTY with EOF stdin** — defaults to deny
- BUT: `fallbackApproval` is only called when `RequestApproval` is called. If `IsAllowed` returns true (prefix cached), `RequestApproval` is never called. So the TTY issue is irrelevant for prefix-based bypasses.
**Verdict: INVALIDATED as standalone attack** — fallback defaults to deny; not exploitable. However it confirms that PH-04/CROSS-03 bypasses work REGARDLESS of TTY state (they bypass the approval prompt entirely).

---

## Verification of PH-17 (grep multi-path)

**Deeper verification**: `grep -r "secret" api/ /home/user/`
- extractBashPrefix: fields = `["grep", "-r", "\"secret\"", "api/", "/home/user/"]`
- First non-flag, non-numeric arg without `/`: `"secret"` — WAIT: `"secret"` does not contain `/` → does NOT pass the path-like check in the first pass
- Second arg: `api/` → contains `/` → path-like → `path.Clean("api/") = "api"` → returns `"grep:api/"`
- The `/home/user/` argument is completely ignored by extractBashPrefix
- With stored `grep:api/` → auto-approved
- bash runs grep on BOTH directories
**Verdict: CONFIRMED HIGH**

---

## Verification of PH-12 (autoAllowPrefixes — currently dead code)

**Code trace**: run.go:391-394 is commented out:
```go
// TODO(parthsareen): re-enable with tighter scoped allowlist
// if agent.IsAutoAllowed(cmd) {
//     fmt.Fprintf(os.Stderr, "\033[1mauto-allowed:\033[0m %s\n", formatToolShort(toolName, args))
//     skipApproval = true
// }
```
- `IsAutoAllowed` is defined and tested but never called
- The `autoAllowPrefixes` list includes `"make"`, `"go build"`, `"go test"`, `"npm run"`, `"cargo build"` — all capable of executing arbitrary code
- **Current state**: SAFE (dead code)
- **Re-enable risk**: CRITICAL — `make` with attacker-controlled Makefile executes arbitrary commands with zero prompt
**Verdict: NEEDS-DEEPER (future risk)** — currently inactive but the TODO + tighter-scoped comment suggests active development intent

---

## PH-23 (New Finding from Causal Analysis): isCommandOutsideCwd Misses `$HOME` and `~` in Pipe Tails

**Discovery**: During verification of CROSS-06, `isCommandOutsideCwd` splits on `|`, `;`, `&` — so it DOES check `tee ~/.ssh/authorized_keys` separately. For `tee ~/.ssh/authorized_keys`:
- `fields = ["tee", "~/.ssh/authorized_keys"]`
- `arg = "~/.ssh/authorized_keys"` → starts with `~` → `home, err := os.UserHomeDir(); !strings.HasPrefix(home, cwd)` → returns TRUE (home is outside cwd)
- So `isCommandOutsideCwd` WOULD return true for this command
- HOWEVER: as PH-16 confirmed, `isCommandOutsideCwd` is only used for a VISUAL WARNING, never for blocking
- And when `IsAllowed` returns true (prefix cached), `RequestApproval` is never called, so the warning is NEVER shown
**Verdict**: Confirms CROSS-06. The `isCommandOutsideCwd` function correctly detects the danger but can't act on it because it's downstream of the allow/deny decision.

---

## Summary of Causal Verification Results

| Hypothesis | Verified | Severity | Confidence |
|---|---|---|---|
| PH-01 (Pipe tee bypass) | CONFIRMED | CRITICAL | HIGH |
| PH-02 (sed -i) | CONFIRMED | HIGH | HIGH |
| PH-03 (find -exec bash) | CONFIRMED | HIGH | HIGH |
| PH-04 (command substitution $()) | CONFIRMED | CRITICAL | HIGH |
| PH-06 (semicolon injection) | CONFIRMED | HIGH | HIGH |
| PH-07 (non-bash blanket approval) | CONFIRMED | HIGH | HIGH |
| PH-08 (YoloMode) | CONFIRMED | HIGH | MEDIUM (design) |
| PH-09 (SSH authorized_keys) | CONFIRMED | CRITICAL | HIGH |
| PH-10 (brace expansion) | CONFIRMED | HIGH | MEDIUM |
| PH-11 (IsDenied double-space) | CONFIRMED | HIGH | HIGH |
| PH-12 (autoAllowPrefixes dead code) | NEEDS-DEEPER | CRITICAL (future) | HIGH |
| PH-13 (unknown tool name) | INVALIDATED | — | HIGH |
| PH-14 (fallbackApproval non-TTY) | INVALIDATED | — | HIGH |
| PH-15 (race condition) | INVALIDATED | — | HIGH |
| PH-16 (isCommandOutsideCwd advisory) | CONFIRMED | MEDIUM | HIGH |
| PH-17 (grep multi-path) | CONFIRMED | HIGH | HIGH |
| PH-18 ($HOME bypass isCommandOutsideCwd) | CONFIRMED (advisory only) | MEDIUM | HIGH |
| PH-19 (prefix accumulation) | CONFIRMED | HIGH | HIGH |
| PH-20 (prompt injection via tool output) | NEEDS-DEEPER | MEDIUM | MEDIUM |
| PH-21 (DoS via timeouts) | NEEDS-DEEPER | LOW | LOW |
| PH-22 (web_fetch file:// scheme) | NEEDS-DEEPER | MEDIUM | MEDIUM |
| CROSS-01 (base64 pipe chain) | CONFIRMED | CRITICAL | HIGH |
| CROSS-02 (grep+semicolon) | CONFIRMED | HIGH | HIGH |
| CROSS-03 (command substitution + headless) | CONFIRMED | CRITICAL | HIGH |
| CROSS-04 (sed -i silent) | CONFIRMED | HIGH | HIGH |
| CROSS-05 (autoAllow+YoloMode future) | NEEDS-DEEPER | CRITICAL | HIGH |
| CROSS-06 (authorized_keys zero-layer) | CONFIRMED | CRITICAL | HIGH |
