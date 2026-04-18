# Evidence File — Group E Deep Probe

## Evidence for PH-01 / PH-C01: Shell Metachar Injection via Approved Prefix

**File**: `x/agent/approval.go:204-300` (extractBashPrefix)
**File**: `x/cmd/run.go:374-436` (tool dispatch loop)
**File**: `x/tools/bash.go:64` (execution sink)

Key code evidence:
- `strings.Split(command, "|")` at approval.go:206 — only `|` is a recognized separator; `;`, `&&`, `||`, command substitution are not processed
- `safeCommands` map at approval.go:218 — `cat`, `ls`, `head`, `tail`, `less`, `more`, `file`, `wc`, `grep`, `find`, `tree`, `stat`, `sed` — ALL can be chained with `;` or `&&`
- `exec.CommandContext(ctx, "bash", "-c", command)` at bash.go:64 — raw string passed to bash
- Denylist at approval.go:96-122 does not include `;`, `&&`, `||`, `$(`, backtick
- KB bypass analysis for `44179b7e` explicitly confirms: "cat tools/file.go ; cat /etc/hosts — ALLOWED"

**Fragility**: SOLID. The behavior is deterministic and documented in the KB bypass analysis.

---

## Evidence for PH-02 / PH-C04: Denylist Substring Bypass via Quoting

**File**: `x/agent/approval.go:175-193` (IsDenied)

Key code evidence:
- `strings.Contains(commandLower, strings.ToLower(pattern))` — raw string comparison pre-bash-evaluation
- Bash processes quoting at exec time, after IsDenied check has already returned
- KB bypass analysis explicitly lists: `r''m -rf /`, `$'\x2fetc\x2fpasswd'`, `cat $HOME/.ssh/id''_rsa` as bypasses

**Fragility**: SOLID. This is a fundamental architectural issue (string comparison vs. semantic comparison).

---

## Evidence for PH-03: Multi-Argument Bypass

**File**: `x/agent/approval.go:231-285` (extractBashPrefix, first path-like arg loop)

Key code evidence:
- `for _, arg := range fields[1:]` — iterates all args but `return` on first match
- After return, remaining args are never checked
- `exec.CommandContext(ctx, "bash", "-c", command)` receives the full unmodified command string

**Fragility**: SOLID. Code structure makes this deterministic.

---

## Evidence for PH-04 / CROSS-04: Yolo Mode Total Bypass

**File**: `cmd/cmd.go:2161` — `runCmd.Flags().Bool("experimental-yolo", false, ...)`
**File**: `x/cmd/run.go:400-403`

Key code evidence:
```go
if opts.YoloMode {
    if !skipApproval {
        fmt.Fprintf(os.Stderr, "\033[1mrunning:\033[0m %s\n", formatToolShort(toolName, args))
    }
} else if !skipApproval && !approval.IsAllowed(toolName, args) {
```
- Yolo branch skips the `approval.IsAllowed` + `approval.RequestApproval` path entirely
- `IsDenied` at lines 376-387 runs before this conditional — it is NOT skipped in yolo mode
- But PH-02 shows IsDenied itself is bypassable

**Fragility**: SOLID. Flag is documented and the code branch is unambiguous.

---

## Evidence for PH-05 / PH-C03: ZipSlip via tar

**File**: `cmd/launch/openclaw.go:771-789` (ensureWebSearchPlugin)

Key code evidence:
```go
pack := exec.Command(npmBin, "pack", webSearchNpmPackage, "--pack-destination", pluginDir)
out, err := pack.Output()
tgzName := strings.TrimSpace(string(out))
tgzPath := filepath.Join(pluginDir, tgzName)
defer os.Remove(tgzPath)
tar := exec.Command("tar", "xzf", tgzPath, "--strip-components=1", "-C", pluginDir)
```
- No `archive/tar` in Go — uses system tar binary
- No per-entry path validation
- `--strip-components=1` removes first path element; remaining path is relative to `-C pluginDir`
- No integrity/signature check on tarball
- `webSearchNpmPackage = "@ollama/openclaw-web-search"` — external npm registry dependency

KB commit archaeology confirms pattern: `0aaf6119` `$VISUAL/$EDITOR -> exec.Command(args[0], args[1:]...)` flagged as "env-controlled binary name" dangerous pattern.

**Fragility**: SOLID. The tar extraction without path filtering is a well-documented ZipSlip pattern.

---

## Evidence for PH-06 / PH-C05: $VISUAL/$EDITOR Arbitrary Binary

**File**: `cmd/interactive.go:643-692` (editInExternalEditor)
**KB commit**: `0aaf6119` explicitly flagged as "Dangerous Pattern HIGH"

Key code evidence:
```go
editor := envconfig.Editor()        // OLLAMA_EDITOR
if editor == "" { editor = os.Getenv("VISUAL") }
if editor == "" { editor = os.Getenv("EDITOR") }
...
args := strings.Fields(editor)
args = append(args, tmpFile.Name())
cmd := exec.Command(args[0], args[1:]...)
```
- Three env vars read in priority order, all attacker-controllable via process environment
- `strings.Fields` splits on whitespace — enables flag injection
- `exec.LookPath` checks only `args[0]` (e.g., `bash`) which always exists
- Trigger: Ctrl+G in interactive mode

**Fragility**: SOLID. KB Phase 2 candidate; code is unambiguous.

---

## Evidence for PH-07: Hierarchical Prefix Scope Creep

**File**: `x/agent/approval.go:425-457` (matchesHierarchicalPrefix)
**File**: `x/agent/approval.go:461-478` (AddToAllowlist — stores directory prefix not exact command)

Key code evidence:
```go
if strings.HasPrefix(currentPath, storedPath) {
    return true
}
```
- `cat tools/file.go` → stored as `cat:tools/`
- `cat tools/any/deep/nested/path` → `currentPath = "tools/any/deep/nested/"` → HasPrefix of `"tools/"` → TRUE
- Symlink in `tools/` directory not detected at approval time (approval.go uses `path.Clean`, not `filepath.EvalSymlinks`)

**Fragility**: SOLID for the scope-creep aspect; the symlink exploitation requires a prior bash command to create the symlink, which adds a precondition.

---

## Evidence for PH-08 / PH-C02: Command Substitution in Path

**File**: `x/agent/approval.go:231-245` (extractBashPrefix first-pass loop)

Key code evidence:
- arg check: `if !strings.Contains(arg, "/") && !strings.Contains(arg, "\\") && !strings.HasPrefix(arg, ".")` — `$()` contains neither `/` nor `\`, would be skipped... 
- BUT `tools/$(id)` DOES contain `/` → passes the path-like check
- `path.Clean("tools/$(id)")` → `"tools/$(id)"` (no `..`) → dir = `"tools"` → prefix `cat:tools/`
- Bash then evaluates `$(id)` as a subshell

**Fragility**: SOLID. Go's `path.Clean` treats `$(id)` as a literal directory name component.

---

## Evidence for PH-09: web_fetch SSRF (Needs-Deeper)

**File**: `x/tools/webfetch.go:84-87`

Key code evidence:
```go
if _, err := url.Parse(urlStr); err != nil {
    return "", fmt.Errorf("invalid URL: %w", err)
}
```
- `url.Parse("file:///etc/passwd")` returns no error
- `url.Parse("http://169.254.169.254/")` returns no error
- URL is forwarded to `https://ollama.com/api/web_fetch` as JSON body field
- Whether ollama.com fetches the URL server-side is NOT verifiable from local code

**Fragility**: FRAGILE (the security impact depends on server-side behavior unknown from local source)

---

## Evidence for PH-12: autoAllowCommands Dormant Bypass

**File**: `x/agent/approval.go:62-69` (autoAllowCommands)
**File**: `x/cmd/run.go:389-394` (commented-out IsAutoAllowed call)

Key code evidence:
```go
// TODO(parthsareen): re-enable with tighter scoped allowlist
// if agent.IsAutoAllowed(cmd) {
//     ...
//     skipApproval = true
// }
```
`autoAllowCommands` includes `echo`, `pwd`, `date` — all can be used with command substitution:
- `echo $(cat /etc/shadow)` — would pass IsAutoAllowed if re-enabled
- The TODO indicates planned re-activation

**Fragility**: FRAGILE currently (dead code); would become SOLID if the TODO is acted on
