Phase: 8
Sequence: 042
Slug: gguf-div-by-zero-alignment
Verdict: VALID
Rationale: Remote unauthenticated DoS via minimal crafted GGUF with general.alignment=0; causes integer divide-by-zero panic in unprotected background goroutine, crashing server. Structural recurrence of CVE-2025-0317 and CVE-2024-8063 despite both being patched.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-C/debate.md

## Summary

The GGUF parser reads the `general.alignment` KV entry and uses it as a divisor in `ggufPadding`. When `general.alignment` is explicitly set to 0, the `kv.Uint` method returns 0 (it only applies the default of 32 when the key is absent). The value 0 is passed to `ggufPadding(offset, 0)`, which computes `offset % 0`, causing an unrecoverable integer divide-by-zero panic. This occurs in the same unprotected background goroutine as H-01, crashing the server process. The attack requires only a minimal GGUF file (~100 bytes).

## Location

- **KV read**: `fs/ggml/gguf.go:238` -- `alignment := llm.kv.Uint("general.alignment", 32)`
- **Padding call**: `fs/ggml/gguf.go:245` -- `ggufPadding(offset, int64(alignment))`
- **Panic site**: `fs/ggml/gguf.go:688` -- `(align - offset%align) % align` with align=0
- **Goroutine**: `server/create.go:99` -- unprotected background goroutine

## Attacker Control

The attacker controls the `general.alignment` KV value by setting it to 0 (uint32) in the GGUF binary. This is a standard GGUF KV entry format with no validation on the value.

## Trust Boundary Crossed

Network (unauthenticated HTTP) -> GGUF parser -> arithmetic operation -> process crash.

## Impact

- **Availability**: Complete server crash. All active sessions terminated.
- **Attack complexity**: VERY LOW. Minimal file size (~100 bytes). Single request after upload.
- **Authentication**: None required.
- **CVE lineage**: Same bug class as CVE-2025-0317 (div-by-zero via block_count=0) and CVE-2024-8063 (div-by-zero via block_count). Despite two prior CVEs patching specific instances, no general guard against zero divisors was added.

## Evidence

1. `fs/ggml/gguf.go:238` -- `alignment := llm.kv.Uint("general.alignment", 32)` returns 0 when key is explicitly 0
2. `fs/ggml/gguf.go:245` -- `padding := ggufPadding(offset, int64(alignment))` passes 0
3. `fs/ggml/gguf.go:688` -- `(align - offset%align) % align` -- `offset % 0` panics
4. `server/create.go:99` -- background goroutine without recover()
5. CVE-2025-0317 / GHSA-9gcr-28rp-cc24 -- same bug class, same component
6. CVE-2024-8063 / GHSA-2xf2-gjm6-g2c6 -- same bug class, same component

## Reproduction Steps

1. Create a minimal GGUF file with one KV entry: key="general.alignment", type=uint32, value=0
2. Upload via `POST /api/blobs/sha256:<hash>`
3. Send `POST /api/create` referencing the digest
4. Observe server crash with panic: "runtime error: integer divide by zero"
