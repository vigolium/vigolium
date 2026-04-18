# Adversarial Review: gguf-alignment-zero-divide-by-zero

## Step 1 — Restate

The finding claims: `fs/ggml/gguf.go` computes padding as `(align - offset%align) % align` without guarding against `align == 0`. The alignment value is read via `kv.Uint("general.alignment", 32)`, whose default is only applied when the key is absent; when the attacker sets `general.alignment` to `uint32(0)` in a GGUF blob, `kv.Uint` returns 0 (type assertion succeeds), and `ggufPadding(offset, 0)` panics with "integer divide by zero". Claimed reachable via POST `/api/create`, `/api/show`, model-load path, and blob-store GC via `fixBlobs`.

Sub-claims:
- A: Attacker controls GGUF bytes uploaded to the server (via `/api/create` or an existing manifest).
- B: `kv.Uint("general.alignment", 32)` returns 0 when the blob declares `general.alignment = uint32(0)`.
- C: `int64(0)` reaches `ggufPadding`, which panics with divide-by-zero.

## Step 2 — Code Path Trace

1. `fs/ggml/ggml.go:563-591` `Decode(rs, maxArraySize)` reads magic, constructs `containerGGUF`, calls `c.Decode(rs)`.
2. `fs/ggml/gguf.go:47-71` `(*containerGGUF).Decode` reads version, reads `V1/V2/V3` counts, calls `model.Decode(rs)` on a newly constructed `*gguf`.
3. `fs/ggml/gguf.go:141-279` `(*gguf).Decode`:
   - Lines 143-191: read `numKV` KV pairs. For each, read key string, type tag, and typed value. For `ggufTypeUint32` (tag 4), reads a `uint32` and stores it as `kv[key]`.
   - An attacker-supplied KV entry `"general.alignment" = uint32(0)` (tag 4) stores `uint32(0)` in `kv["general.alignment"]`.
   - Line 238: `alignment := llm.kv.Uint("general.alignment", 32)`.
4. `fs/ggml/ggml.go:191-194` `(kv KV) Uint(key, defaultValue...uint32) uint32` calls `keyValue(kv, key, append(defaultValue, 0)...)`.
5. `fs/ggml/ggml.go:316-327` `keyValue`:
   - Key `"general.alignment"` matches `"general."` prefix, so no architecture prefixing.
   - `kv["general.alignment"].(uint32)` type-asserts — value exists and is `uint32(0)` — returns `0, true`.
   - Default is NOT applied.
6. Line 245: `padding := ggufPadding(offset, int64(0))`.
7. Line 687-689: `return (align - offset%align) % align`. `offset % 0` triggers Go runtime panic "integer divide by zero".

Lines 573 and 580 also call `ggufPadding(_, int64(alignment))` during `WriteGGUF`, but those are writer-only paths not exercised by attacker input.

No validation, sanitization, or `cmp.Or`-style default applies on this path.

## Step 3 — Protection Surface

| Layer | Protection | Blocks? |
|-------|-----------|---------|
| Language | Go bounds checking — but integer divide-by-zero is a runtime panic, not memory corruption | No — panic still occurs |
| Framework | `gin.Default()` at `server/routes.go:1674` includes Recovery middleware | Partial — converts HTTP-handler panic to 500, but does not prevent panic itself. Non-HTTP goroutine panics (model-load) are NOT covered. |
| Middleware | No WAF / normalizer ahead of GGUF byte-level parse | No |
| Application | `kv.Uint(..., 32)` default was the intended protection but it relies on key absence, not on value != 0 | No — value-0 bypasses it |
| Sibling code | `fs/gguf/gguf.go:80` uses `cmp.Or(f.KeyValue("general.alignment").Int(), 32)` which rescues zero; confirms the pattern is known | No — the vulnerable parser is the DIFFERENT one (`fs/ggml`) still in use |

No protection blocks the claimed attack path in `fs/ggml`.

## Step 4 — Real-Environment Reproduction

Wrote `archon/real-env-evidence/gguf-alignment-zero-divide-by-zero/alignment_zero_test.go`, copied into `fs/ggml`, ran with `go test -run TestAlignmentZeroPanic`.

Payload: 57 bytes — GGUF_LE magic, version 3, numTensor=0, numKV=1, key `"general.alignment"`, type 4 (uint32), value 0.

Result (captured in `test_output.log`):

```
PANIC caught: runtime error: integer divide by zero
stack:
  ...
  github.com/ollama/ollama/fs/ggml.ggufPadding(...)
      /Users/bytedance/Desktop/demo/ollama/fs/ggml/gguf.go:688
  github.com/ollama/ollama/fs/ggml.(*gguf).Decode(...)
      /Users/bytedance/Desktop/demo/ollama/fs/ggml/gguf.go:245
  github.com/ollama/ollama/fs/ggml.(*containerGGUF).Decode(...)
      /Users/bytedance/Desktop/demo/ollama/fs/ggml/gguf.go:66
  github.com/ollama/ollama/fs/ggml.Decode(...)
      /Users/bytedance/Desktop/demo/ollama/fs/ggml/ggml.go:581
CONFIRMED: integer divide by zero panic reached
```

Reproduction SUCCEEDED at the claimed source, sink, and with attacker-controlled bytes only.

Test file was removed from `fs/ggml` after reproduction to avoid polluting the codebase.

## Step 5 — Briefs

### Prosecution

1. Divide-by-zero panic definitively reproduced (Step 4) with a 57-byte GGUF.
2. Source `kv.Uint` -> sink `ggufPadding` path independently verified (Step 2).
3. `Decode` is invoked from `server/create.go:471,653,687`, `server/model.go:66`, `server/routes.go:1353` -> `llm.LoadModel` -> `ggml.Decode` (reached by `/api/show?verbose=true`), and `ml/backend/ggml/ggml.go:130` (model load). All accept attacker-supplied blob bytes.
4. The sibling parser `fs/gguf/gguf.go:80` already uses `cmp.Or(..., 32)` for the same value — demonstrating the fix is known and trivially applicable.
5. On HTTP paths the panic is recovered to 500 per request — repeatable DoS against `/api/show` for any request touching a poisoned blob. On model-load paths (non-gin goroutines), the panic may propagate and terminate the process.

### Defense

1. `gin.Default()` includes Recovery middleware, so HTTP-handler panics become 500 and the server stays up.
2. Attacker must deliver the blob to the server — either via `/api/create` (uploading their own content) or by poisoning a blob already on disk. Without a separate vulnerability (e.g., cache-hit substitution or path-traversal write), this is self-inflicted damage or requires other flaws.
3. The draft's claim that "fixBlobs during GC" is a reach path is factually wrong. `server/fixblobs.go` only renames `sha256:xxx` -> `sha256-xxx`; it does not call `ggml.Decode`. Blobs cannot be "uncollectable" via `fixBlobs` panic because `fixBlobs` never parses GGUF content.
4. No RCE, no memory corruption, no authentication bypass, no data exfiltration. The impact is confined to DoS of parser-touching endpoints on the single poisoned blob.
5. The chain with PH-A-02 (cache-hit substitution) is conditional on a separate finding being true and is not in scope here.

### Weighing

The defense does not identify a protection that blocks the panic on `fs/ggml`. `gin.Recovery` localizes damage on HTTP paths but does not prevent the panic itself; model-load paths are not gin-covered. The reproduction proved the panic is reachable. The defense DOES correctly downgrade the chain impact (fixBlobs claim is false).

## Step 6 — Severity Challenge

Start at MEDIUM.

- Remotely triggerable: yes (`/api/create`, `/api/show?verbose=true`).
- Trust boundary crossing: attacker bytes -> runtime panic in parser.
- Not RCE; not auth bypass; not mass data exfil.
- HTTP-handler impact is bounded by gin.Recovery to 500.
- Model-load path could theoretically crash the process but was NOT demonstrated in reproduction.
- One load-bearing draft claim (fixBlobs chain) is false, inflating the original HIGH assessment.

Severity stays at MEDIUM. Downgrade from original HIGH.

## Step 7 — Verdict

**CONFIRMED** — real panic, reproduced, reachable from multiple HTTP entry points, and fix pattern (cmp.Or) already exists in the sibling `fs/gguf` package proving developer intent.

Severity-Final: **MEDIUM** (downgraded from HIGH because the fixBlobs/GC escalation claim does not hold, and HTTP-facing impact is recovered to 500 by gin).

PoC-Status: executed (stack trace at `archon/real-env-evidence/gguf-alignment-zero-divide-by-zero/test_output.log`).
