# p4-f06: GGUF Parser — Divide-by-Zero in ggufPadding When Alignment is 0

**Severity**: HIGH
**CWE**: CWE-369 (Divide by Zero)
**DFD Slice**: DFD-4
**CVE Pattern**: CVE-2025-0317 (ggufPadding div-by-zero pattern)

## Location

- `fs/ggml/gguf.go:687-689`: `ggufPadding()`
- `fs/ggml/gguf.go:238,245`: alignment read from KV, default 32 but overridable to 0

## Description

```go
func ggufPadding(offset, align int64) int64 {
    return (align - offset%align) % align  // PANICS if align == 0
}
```

The alignment value is read from `llm.kv.Uint("general.alignment", 32)`. `KV.Uint()` calls `keyValue()`:

```go
func (kv KV) Uint(key string, defaultValue ...uint32) uint32 {
    val, _ := keyValue(kv, key, append(defaultValue, 0)...)
    return val
}
```

If `general.alignment` is present in the GGUF KV with value 0, `keyValue` returns 0 (the found value), not 32 (the default). The default is only used when the key is absent. A crafted GGUF that sets `general.alignment = 0` causes `ggufPadding(offset, 0)` → panic: integer divide by zero.

This is called twice in `gguf.Decode` (lines 245, 269) and twice in `ggml.go` (lines 573, 580), all reachable from unauthenticated blob upload + create.

## Evidence

- `fs/ggml/gguf.go:688` — `offset%align` panics when `align = 0`
- `fs/ggml/gguf.go:238` — `alignment := llm.kv.Uint("general.alignment", 32)` — returns 0 if KV contains 0
- `fs/ggml/ggml.go:316-326` — `keyValue()` returns found value even if it's the zero value

---

## Phase 7 Enrichment Verdict

**Classification**: SECURITY — likely security (DoS via server panic)

**Attacker Control**: The `general.alignment` KV entry is attacker-controlled binary data in the GGUF file. Setting it to 0 is a single-field modification requiring no special knowledge beyond the GGUF format spec.

**Runtime**: `ollama serve` Go process. `ggufPadding(offset, 0)` triggers a Go runtime panic (`integer divide by zero`). Go panics in goroutines that are not recovered propagate and crash the process.

**Trust Boundary Crossed**: Network-to-server. Unauthenticated remote attacker crashes the server with a single request pair.

**Effect**: Denial of service (server crash). Cross-user impact on shared instances.

**CodeQL Reachability**: No pre-computed slice. Manual trace: blob upload -> `/api/create` -> `gguf.Decode()` -> `alignment := llm.kv.Uint("general.alignment", 32)` (returns 0 for crafted input) -> `ggufPadding(offset, int64(alignment))` -> `offset % 0` -> panic. CVE-2025-0317 documents this exact pattern; the KB confirms it matches `GHSA-93jv-pvg8-hf3v` and is rated HIGH (CVSS 7.5). Confirmed reachable.

**KB Cross-Reference**: CVE-2025-0317 / GHSA-p2wh-w96x-w232 — "Divide-by-zero in ggufPadding; DoS" — direct match. The KB advisory inventory lists this as HIGH/7.5. The finding is a re-discovery of a known CVE pattern that may not have been fully fixed (or was reintroduced). Phase 8 should verify whether the CVE-2025-0317 fix commit is included in the current HEAD.

**Exploit Prerequisites**: Network access, no auth. Trivially exploitable — single GGUF KV field set to 0.

**Verdict**: KEEP — HIGH security finding. Fix: add a zero-check guard in `ggufPadding` (`if align == 0 { return 0 }` or return an error) AND add validation after reading `general.alignment` to reject alignment values of 0.
