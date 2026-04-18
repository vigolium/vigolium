## Adversarial Review: configv2-time-bomb-rce

### Sub-claim Decomposition

- **Sub-claim A (Attacker controls entrypoint in OCI config JSON)**: SUPPORTED. Raw JSON blobs are stored by content-addressable hash without re-serialization. An attacker who controls a registry can embed arbitrary JSON fields.
- **Sub-claim B (Unknown fields survive on disk)**: SUPPORTED. Go json.Unmarshal ignores unknown fields by default. No DisallowUnknownFields is used. The raw blob persists on disk.
- **Sub-claim C (Agents branch deserializes Entrypoint and executes it)**: SUPPORTED. Confirmed at agents branch types/model/config.go line 51, cmd/cmd.go lines 535-536 and 584-626.
- **Sub-claim D (No protection gates the execution)**: SUPPORTED. isExperimental is retrieved but not checked before runEntrypoint call. No allowlist, no user consent, no sandbox.

### Code Path Trace

1. Attacker pushes model with `entrypoint` field in config JSON to registry
2. User pulls model: raw blob stored via `server/internal/client/ollama/registry.go:Pull()` -> `cache.Chunked()` -> disk
3. User upgrades to agents branch build
4. User runs model: `server/images.go:323` reads blob -> `json.NewDecoder(configFile).Decode(&m.Config)` -> Entrypoint field populated
5. `server/routes.go:1125` -> `ShowResponse.Entrypoint = m.Config.Entrypoint`
6. `cmd/cmd.go:506` -> `opts.Entrypoint = info.Entrypoint`
7. `cmd/cmd.go:535-536` -> `if opts.Entrypoint != "" { return runEntrypoint(cmd, opts) }`
8. `cmd/cmd.go:619-625` -> `exec.Command(execPath, args...).Run()` with inherited stdio

### Protection Surface

| Layer | Protection | Blocks Attack? |
|-------|-----------|----------------|
| Language | Go type system | No - json.Unmarshal ignores unknown fields |
| Framework | None | No framework protections |
| Application | isExperimental flag | No - checked AFTER runEntrypoint |
| Application | Allowlist | None exists |
| Application | User consent | None exists |
| Registry | Config validation | Not enforced client-side |

### Reproduction

- PoC confirmed: Go json.Unmarshal silently ignores entrypoint on main-branch struct, deserializes it on agents-branch struct
- Full end-to-end reproduction not attempted (requires registry setup)
- Core mechanism verified through code trace and partial PoC

### Prosecution Brief

The attack chain is complete and verified through independent code trace. An attacker-controlled `entrypoint` field in a model config JSON blob survives storage on disk (raw blob, no re-serialization), persists across binary upgrades, and is executed without any validation, sandboxing, or user consent on the agents branch. The `isExperimental` flag is retrieved but deliberately not checked before `runEntrypoint`. This is a textbook supply-chain RCE vector.

### Defense Brief

The vulnerable code exists only in the unmerged `parth/agents` feature branch. The attack requires: (1) the user to pull from an attacker-controlled registry, (2) the agents branch to be merged as-is without security review, and (3) the user to upgrade and run the previously-pulled model. The branch may undergo security review before merge. The isExperimental flag infrastructure exists and could be used to gate entrypoint execution.

### Severity Challenge

Starting at MEDIUM. Upgraded to HIGH based on: remote trigger (registry push), trust boundary crossing (registry to local exec), meaningful impact (arbitrary command execution). Not CRITICAL because: the vulnerable code is in an unmerged feature branch, and the attack requires pulling from an attacker-controlled registry name.

### Verdict

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Complete code path from attacker-controlled registry blob to unsandboxed exec.Command verified in parth/agents branch with no blocking protections; isExperimental flag retrieved but not checked before runEntrypoint.
Severity-Final: HIGH
PoC-Status: theoretical
