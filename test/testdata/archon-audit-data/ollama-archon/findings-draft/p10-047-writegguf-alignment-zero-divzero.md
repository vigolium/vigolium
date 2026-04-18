Phase: 10
Sequence: 047
Slug: writegguf-alignment-zero-divzero
Verdict: VALID
Rationale: WriteGGUF reads general.alignment from its kv argument (attacker-controlled during model conversion) and passes it to ggufPadding without a zero-check, triggering the same integer divide-by-zero as p8-042 but in the write path executed during `ollama create`.
Severity-Original: HIGH
PoC-Status: pending
Origin-Finding: archon/findings-draft/p8-042-gguf-div-by-zero-alignment.md
Origin-Pattern: AP-042

## Summary
`WriteGGUF` at `fs/ggml/gguf.go:526-594` reads `general.alignment` from the caller-supplied KV config and uses it as a divisor in `ggufPadding` without guarding against zero:

```go
alignment := kv.Uint("general.alignment", 32)   // line 564 — default 32 but overridable
...
s += uint64(ggufPadding(int64(s), int64(alignment)))  // line 573
...
offset += ggufPadding(offset, int64(alignment))        // line 580
```

`ggufPadding(offset, 0)` executes `offset % 0`, which panics with `integer divide by zero`.

The default is 32, but the KV is populated from a `fs.Config` that, during `convert.ConvertModel`, is built from the source model's own metadata — meaning a malicious safetensors or torch checkpoint can inject `general.alignment = 0` into the converted GGUF's KV.

## Location
`fs/ggml/gguf.go:564,573,580` — `WriteGGUF`

```go
alignment := kv.Uint("general.alignment", 32)
...
s += uint64(ggufPadding(int64(s), int64(alignment)))   // panics when alignment==0
offset += ggufPadding(offset, int64(alignment))         // panics when alignment==0
```

`ggufPadding` at line 687:
```go
func ggufPadding(offset, align int64) int64 {
    return (align - offset%align) % align   // division by zero when align==0
}
```

## Attacker Control
The KV passed to `WriteGGUF` originates from the model's architecture parameters. During `ConvertModel`, the `fs.Config` is constructed from the source checkpoint's metadata fields. An attacker-supplied safetensors/pickle file can set the metadata field that maps to `general.alignment` to 0.

Alternatively, an attacker that controls the Modelfile `FROM` reference can supply a GGUF with `general.alignment=0` which is then read-back via `ggml.Decode(...,-1)` and the KV re-used in subsequent `WriteGGUF` calls.

## Trust Boundary Crossed
Uploaded model checkpoint / Modelfile FROM directive → conversion pipeline → GGUF writer. Reachable via HTTP POST /api/create.

## Impact
Panic (DoS) during model creation/conversion. The server process crashes, dropping all in-flight requests. Service requires manual restart.

## Evidence
`fs/ggml/gguf.go:564-580` contains no guard:
```go
// No: if alignment == 0 { alignment = 32 }
alignment := kv.Uint("general.alignment", 32)
```
The default 32 is only applied when the key is absent; if the key is present with value 0, `kv.Uint` returns 0.

## Reproduction Steps
1. Create a safetensors model directory with metadata JSON containing `"general.alignment": 0` (or the equivalent architecture-namespaced key).
2. POST to `/api/create` with a Modelfile `FROM <dir>`.
3. During `convert.ConvertModel` → `WriteGGUF`, `ggufPadding(offset, 0)` is called.
4. Server panics: `runtime error: integer divide by zero`.
