Phase: 8
Sequence: 021
Slug: shell-expansion-bypass
Verdict: VALID
Rationale: Tracer confirmed path.Clean cannot interpret shell metacharacters and matchesHierarchicalPrefix allows $() subdirectories to match parent prefix; Advocate confirmed no shell-aware sanitization exists.
Severity-Original: CRITICAL
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-B/debate.md

## Summary

The agent approval system uses `path.Clean` (approval.go:253) for path normalization, which is documented as lexical-only and cannot interpret shell metacharacters. Shell command substitution `$()` and brace expansion `{}` in path arguments pass through all validation checks unmodified. When bash executes the command, these expansions are evaluated, enabling arbitrary code execution (via `$()`) and arbitrary file reads (via `{}`).

The `matchesHierarchicalPrefix` function (approval.go:449-451) makes this worse: `cat tools/$(malicious)/a.go` generates prefix `cat:tools/$(malicious)/` which matches stored `cat:tools/` via `strings.HasPrefix`.

## Location

- `x/agent/approval.go:253` -- `path.Clean(arg)` lexical-only normalization
- `x/agent/approval.go:260-268` -- sibling check using `path.Clean` (also lexical-only)
- `x/agent/approval.go:449-451` -- `matchesHierarchicalPrefix` uses `strings.HasPrefix` on uninterpreted shell syntax
- `x/tools/bash.go:64` -- `exec.CommandContext(ctx, "bash", "-c", command)` evaluates all shell expansions

## Attacker Control

The LLM controls the path arguments in bash commands. After `cat:tools/` is approved:
1. Command substitution: `cat tools/$(id > /tmp/pwned)/a.go` -- `$(id > /tmp/pwned)` executes during bash expansion
2. Brace expansion: `cat tools/{safe.go,../../etc/passwd}` -- bash expands to two separate file reads
3. Backtick substitution: `` cat tools/`id`/a.go `` -- equivalent to `$()`

## Trust Boundary Crossed

User approval boundary. The user approved read access to a specific directory. Shell expansion enables arbitrary code execution and file reads outside the approved scope without any user visibility.

## Impact

- **Arbitrary code execution**: `$(arbitrary_command)` executes during bash path expansion
- **Arbitrary file read**: `{safe.go,../../etc/passwd}` reads files outside approved directory
- **Stealth**: The command appears to be a legitimate file-read in the approved directory

## Evidence

1. `approval.go:253`: `cleaned := path.Clean(arg)` -- Go docs: "Clean returns the shortest path name equivalent to path by purely lexical processing"
2. `approval.go:256`: `strings.HasPrefix(cleaned, "..")` -- checks for `..` escape but `$()` content is opaque
3. `approval.go:262-268`: sibling check compares `origBase` vs `cleanedBase` -- brace content `{safe.go,../../etc/passwd}` has origBase=cleanedBase="tools" because `path.Clean` cannot evaluate braces
4. `approval.go:449-451`: `strings.HasPrefix(currentPath, storedPath)` -- `"tools/$(id)/".HasPrefix("tools/")` = true

## Reproduction Steps

1. Start agent session, approve `cat tools/README.md` with "Allow for this session" (stores `cat:tools/`)
2. Command substitution RCE: LLM issues `cat tools/$(echo pwned > /tmp/rce-proof)/a.go`
   - `extractBashPrefix` returns `cat:tools/$(echo pwned > /tmp/rce-proof)/` 
   - `matchesHierarchicalPrefix`: `"tools/$(echo pwned > /tmp/rce-proof)/"` has prefix `"tools/"` = true
   - Auto-approved; bash creates `/tmp/rce-proof` during expansion
3. Brace expansion file read: LLM issues `cat tools/{Makefile,../../etc/passwd}`
   - `extractBashPrefix` gets arg `tools/{Makefile,../../etc/passwd}`, path.Clean preserves it, sibling check passes
   - Returns `cat:tools/` prefix, auto-approved
   - bash expands to `cat tools/Makefile tools/../../etc/passwd`, reads both files

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Unit test confirmed IsAllowed returns true for command substitution, backtick, and brace expansion payloads after a legitimate cat:tools/ prefix is stored; IsDenied has no patterns matching shell metacharacters $() or backticks.
Severity-Final: HIGH
PoC-Status: executed

## Cold Verification

### Verdict: CONFIRMED (downgraded from CRITICAL to HIGH)

### Restated Claim

The agent approval system's prefix-based auto-approval mechanism fails to account for shell metacharacters in command arguments. Because `extractBashPrefix` uses Go string splitting (`strings.Fields`) and `path.Clean` -- neither of which understand shell syntax -- an attacker-controlled LLM can embed command substitution (`$(...)`, backticks) or brace expansion (`{...}`) in path arguments that lexically match an already-approved directory prefix but execute arbitrary code when `bash -c` evaluates the full command string.

### Sub-claim Decomposition

- **Sub-claim A (Attacker controls input)**: The LLM generates bash commands including path arguments. VERIFIED -- the LLM is the direct source of the `command` parameter passed to the bash tool (bash.go:53-57).
- **Sub-claim B (Input passes validation unmodified)**: Shell metacharacters `$()` and backticks pass through `extractBashPrefix` and `IsDenied` without detection. VERIFIED by code trace and unit test.
- **Sub-claim C (Security effect)**: Auto-approved command is executed via `bash -c` which evaluates all shell expansions. VERIFIED -- bash.go:64 uses `exec.CommandContext(ctx, "bash", "-c", command)`.

### Independent Code Path Trace

1. `x/cmd/run.go:378`: `IsDenied(cmd)` checked first -- no deny pattern matches `$(...)` syntax
2. `x/cmd/run.go:404`: `approval.IsAllowed(toolName, args)` called
3. `x/agent/approval.go:402`: `extractBashPrefix(cmd)` called on the malicious command
4. `approval.go:210`: `strings.Fields` splits `cat tools/$(echo pwned > /tmp/rce)/a.go` into `["cat", "tools/$(echo", "pwned", ">", "/tmp/rce)/a.go"]`
5. `approval.go:231-284`: First path-like field `"tools/$(echo"` contains `/`, is not absolute, `path.Clean` preserves it, `path.Dir` returns `"tools"`, function returns `"cat:tools/"`
6. `approval.go:405`: `a.prefixes["cat:tools/"]` is true (stored from prior approval) -- auto-approved
7. `bash.go:64`: Full command executed via `bash -c`, shell evaluates `$(echo pwned > /tmp/rce)`

### Protection Surface Analysis

| Layer | Protection Found | Blocks Attack? |
|-------|-----------------|----------------|
| Application | `IsDenied` deny patterns | No -- no pattern matches `$()` or backtick syntax |
| Application | `path.Clean` normalization | No -- lexical only, shell metacharacters opaque |
| Application | `..` traversal check | No -- irrelevant to command substitution |
| Application | `isCommandOutsideCwd` | No -- only used for warning display, not blocking; unreachable if auto-approved |
| Application | Absolute path rejection | No -- `/tmp/rce)/a.go` is a later field but `extractBashPrefix` already returned after processing `tools/$(echo` |

### Reproduction Evidence

Unit test executed in the actual codebase at current HEAD (commit 8c8f8f34). Test confirmed:
- `IsAllowed` returns TRUE for `cat tools/$(echo pwned > /tmp/rce-proof)/a.go` after `cat:tools/` stored
- `IsAllowed` returns TRUE for backtick variant `` cat tools/`id`/a.go ``
- `IsDenied` returns FALSE for the command substitution payload
- `IsDenied` returns TRUE for the `/etc/passwd` brace expansion example (partial mitigation)
- `IsAllowed` returns TRUE for brace expansion targeting non-denied paths

Evidence stored at: `archon/real-env-evidence/shell-expansion-bypass/test_output.go`

### Prosecution Brief

The vulnerability is genuine and reproducible. The approval system in `x/agent/approval.go` uses shell-unaware Go string operations to extract and match command prefixes. When a user approves any command like `cat tools/README.md`, the stored prefix `cat:tools/` can be matched by subsequent commands containing shell command substitution (e.g., `cat tools/$(arbitrary)/file`). The `extractBashPrefix` function processes only the first path-like whitespace-delimited token, which for `cat tools/$(echo pwned > /tmp/rce)/a.go` is `tools/$(echo` -- producing `path.Dir` result `tools` and prefix `cat:tools/`. The `IsDenied` function has no patterns for `$(`, backticks, or `{` shell syntax. The command then executes unmodified via `bash -c`. This was confirmed by unit test execution.

### Defense Brief

The specific `/etc/passwd` brace expansion example given in the finding IS blocked by `IsDenied` (confirmed by test), so that particular example is a false positive. However, the command substitution vector (`$(...)`) and backtick vector are entirely unblocked. The attack requires: (1) a user to have previously approved at least one command creating a directory prefix, and (2) the LLM to be manipulated (via prompt injection) into issuing a command with embedded shell metacharacters. Both preconditions are realistic within the system's threat model, but they do represent meaningful prerequisites that reduce severity from CRITICAL.

### Severity Assessment

Original: CRITICAL. Challenged: HIGH.
- The vulnerability enables arbitrary code execution, which is severe
- However, it requires a prior user approval to exist (realistic but still a precondition)
- It requires the LLM to be adversarially manipulated (prompt injection), which is the core threat model but adds a step
- The attack is not directly internet-facing or unauthenticated -- it requires a local interactive agent session
- Downgraded from CRITICAL to HIGH: meaningful preconditions exist, though the impact (RCE) is severe

### Corrections to Original Finding

1. The brace expansion example `cat tools/{Makefile,../../etc/passwd}` is actually blocked by `IsDenied` because the command string contains `/etc/passwd`. The finding should note this. However, brace expansion to non-denied paths (e.g., `cat tools/{Makefile,../../tmp/secret.txt}`) is NOT blocked and IS auto-approved.
2. The `extractBashPrefix` trace in reproduction step 2 is slightly inaccurate -- the prefix extracted is `cat:tools/` (from `path.Dir("tools/$(echo")` = `"tools"`), and the hierarchical match succeeds because `a.prefixes["cat:tools/"]` is already true (exact match), not because of `matchesHierarchicalPrefix`. The `matchesHierarchicalPrefix` path would also work but is not the primary match path for this specific payload.
