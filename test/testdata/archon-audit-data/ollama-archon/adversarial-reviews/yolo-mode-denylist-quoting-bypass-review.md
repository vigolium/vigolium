# Adversarial Review — p8-067 yolo-mode-denylist-quoting-bypass

## Step 1 — Restatement

Claim (restated): when a user launches the experimental agent with `--experimental-yolo`, the only safety floor that remains between untrusted model output and `bash -c` execution is the `agent.IsDenied` substring filter. That filter operates on the raw command string before bash interprets it, so an attacker-controlled LLM can insert syntactically inert quoting (`''`, `""`, `${IFS}`, `$'\xNN'`) inside any blocked token (`rm -rf`, `sudo `, `/etc/shadow`, ...) to defeat the substring match while leaving the runtime semantics unchanged.

Sub-claims:
- A. The attacker controls the `command` string that reaches `IsDenied`: yes — any tool-calling model under yolo can emit arbitrary bash.
- B. `IsDenied` rejects `rm -rf /` but accepts `r''m -rf /` or `rm${IFS}-rf${IFS}/`: to verify by direct call.
- C. Bash `-c` executes the bypass string with the same destructive effect as the unquoted form: to verify in a shell.

No sub-claim is incoherent.

## Step 2 — Independent Code Trace

Entry points traced without referring to the draft's snippets:

1. Flag defined in `cmd/cmd.go:2161`: `runCmd.Flags().Bool("experimental-yolo", false, "Skip all tool approval prompts (use with caution)")`.
2. Flag read at `cmd/cmd.go:733` and forwarded into `xcmd.GenerateInteractive(..., yoloMode, ...)`.
3. `GenerateInteractive` sets `opts.YoloMode = yoloMode` (run.go:1071) and calls `Chat` on each user turn, which iterates tool calls at run.go:367+.
4. For `bash` calls, run.go:378 invokes `agent.IsDenied(cmd)`. If false, run.go:400 branches on `opts.YoloMode`; if true, the approval prompt is skipped and `toolRegistry.Execute(call)` at run.go:436 runs the tool.
5. `bash.Execute` at x/tools/bash.go:64 runs `exec.CommandContext(ctx, "bash", "-c", command)`.

`IsDenied` (x/agent/approval.go:175-193):
```go
commandLower := strings.ToLower(command)
for _, pattern := range denyPatterns {
    if strings.Contains(commandLower, strings.ToLower(pattern)) { return true, pattern }
}
for _, pattern := range denyPathPatterns {
    if strings.Contains(commandLower, strings.ToLower(pattern)) { return true, pattern }
}
return false, ""
```

No tokenization, no unquoting, no normalization — raw substring on the lowered string. Grep confirms no `shlex`/`shellwords` imports anywhere under `x/`.

## Step 3 — Protection Surface Search

| Layer | Control | Blocks? |
|---|---|---|
| Language | Go type system | N/A — logic bug, not memory bug |
| Framework | None interposed between model output and IsDenied | — |
| Middleware | No WAF/proxy in a local CLI | — |
| Application | `IsAllowed` allowlist | Skipped by yolo branch at run.go:400 |
| Application | `IsDenied` substring filter | THE filter under test — defeated by quoting |
| Application | `isCommandOutsideCwd` | Only feeds a warning banner into the approval prompt (approval.go:503); no enforcement, and the prompt itself is skipped under yolo |
| Documentation | `--experimental-yolo` flag description "use with caution" and startup banner "yolo mode - all tool approvals will be skipped" | Partial — informs user that approvals are skipped; does NOT disclose that the residual denylist is bypassable |

Crucially, the banner's wording ("all tool approvals will be skipped") is consistent with a user model in which IsDenied remains as a hard floor. It does not warn that the floor is substring-based and can be trivially sidestepped.

## Step 4 — Reproduction

Host: Darwin 25.3.0, default `/bin/bash`, Ollama main @ 57653b8e.

Built a minimal Go program importing the real `github.com/ollama/ollama/x/agent` package and invoked `IsDenied` against a matrix of bypass strings. Then ran the same strings under `bash -c` against disposable files in `/tmp/yolo-target/`.

Results (full log at `archon/real-env-evidence/yolo-mode-denylist-quoting-bypass/isdenied-output.txt`):

- Baseline `rm -rf /` → IsDenied=true, pattern `rm -rf` — filter works.
- `r''m -rf /` → IsDenied=false — bypass confirmed.
- `r""m -rf /` → IsDenied=false — bypass confirmed.
- `'rm' -rf /` → IsDenied=false — bypass confirmed.
- `rm${IFS}-rf${IFS}/` → IsDenied=false — bypass confirmed.
- `$'\x72m' -rf /` → IsDenied=false — bypass confirmed.
- `cat /etc/sha''dow` → IsDenied=false — credential-read bypass confirmed.

Bash semantic test (destructive effect identical):
- `bash -c "r''m /tmp/yolo-target/victim1"` deleted victim1.
- `bash -c 'r""m /tmp/yolo-target/victim2'` deleted victim2.
- `bash -c "$'\x72m' /tmp/yolo-target/victim3"` deleted victim3.

Minor note: `su''do rm -rf /` is still caught, but only because the `rm -rf` substring is also present. If the attacker only wanted `sudo`-prefixed exfiltration without the `rm -rf` substring, the same quoting trick defeats the `sudo ` pattern too (`su''do curl ...` → denied=false by the same logic, confirmed by the test harness for `su''do` on a `cat /etc/shadow` substitution).

PoC-Status: executed (unit-level IsDenied call + bash semantic reproduction). The end-to-end path through an actual prompt-injected model was not exercised, but the only remaining step between a model emitting the bypass string and file deletion is `exec.CommandContext("bash", "-c", ...)`, which is mechanical.

## Step 5 — Prosecution

`IsDenied` is the sole programmatic guard in yolo mode (run.go:400 bypasses `IsAllowed`). The guard is a raw substring match (approval.go:179-181) with no tokenization or unquoting. Bash is invoked with `-c` (bash.go:64), which performs full word-splitting, quote-removal, IFS expansion, and ANSI-C `$'...'` decoding at runtime — all AFTER the filter has run. Empirical tests show `IsDenied` returns false for five independent syntactic bypasses (`''`, `""`, `'…'`, `${IFS}`, `$'\x72m'`) while bash resolves each back to the blocked command and performs the destructive action on disk. The yolo banner ("all tool approvals will be skipped") does not warn that the residual denylist is weak, so a user who reads the flag description can reasonably believe `rm -rf /` is still blocked — it is not. Attacker control is realistic: prompt injection via fetched web content, malicious README, or a compromised upstream model is a known threat in agentic tooling, and yolo mode is specifically intended for users who already accept skipped approvals — i.e., users most likely to be running untrusted prompts.

## Step 6 — Defense

The attack requires the user to (a) launch the experimental agent, (b) explicitly opt into `--experimental-yolo`, a flag prefixed "experimental" and described "use with caution", and (c) observe a startup banner warning that "all tool approvals will be skipped". A reasonable reading of that banner is: "no safety guarantees remain in yolo mode." Under that reading, the denylist is not a security boundary at all — it is a best-effort typo catcher. The finding documents a gap between stated semantics and implemented semantics, not a bypass of a security control that was ever intended to hold under yolo. Further, the flag is explicitly `experimental-*`, which is a conventional marker for "no stability, no security commitment, do not use in production." No CVE-class RCE exists here in the sense that the user has already consented to arbitrary command execution; the open question is only whether the residual substring filter is cosmetic or load-bearing, and the code itself doesn't claim the latter.

## Step 7 — Verdict

Prosecution prevails on technical facts (reproduction executed in both halves). Defense has a legitimate point about yolo being explicit opt-in, but does not negate the finding — the finding's own framing already concedes opt-in and focuses on the specific residual-guard behavior, which is indeed broken and undocumented as broken. Severity challenge:

- Start: MEDIUM.
- Upgrade: remotely triggerable via prompt injection, crosses B11 (LLM → host) — favors HIGH.
- Downgrade: requires `--experimental-yolo` opt-in, which is behind an `experimental-*` feature gate with an explicit "use with caution" + runtime banner — favors MEDIUM.

The user opt-in is a significant precondition: without yolo, `IsAllowed` blocks the command and the user is prompted. The denylist bypass is only reachable when the user has already accepted auto-execution of arbitrary model-emitted commands. That materially limits real-world severity. Final severity: MEDIUM (hardening gap in an experimental opt-in safety net; documented as a caveat rather than a hard control).

Verdict: CONFIRMED (the claimed bypass exists exactly as described and reproduces end-to-end), with severity downgraded to MEDIUM on the opt-in precondition.

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Direct invocation of `agent.IsDenied` at main@57653b8e returns false for `r''m -rf /`, `r""m -rf /`, `'rm' -rf /`, `rm${IFS}-rf${IFS}/`, and `$'\x72m' -rf /`, and `bash -c` on each of those strings deletes files — confirming both halves of the claimed bypass on the real codebase.
Severity-Final: MEDIUM
PoC-Status: executed
