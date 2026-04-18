Slug: gguf-array-length-truncation
Reviewer: cold-verification
Commit reviewed: 57653b8e (main)

## Step 1 — Restatement and Sub-claims

Claim in my words: when Ollama decodes a GGUF model blob, attacker-controlled bytes specify an array length as a 64-bit unsigned integer. The decoder reads it as uint64, then casts to `int` for allocation. On 64-bit platforms large uint64 values alias to negative ints, and the subsequent `make([]T, size)` panics with "makeslice: len out of range" because no positive-size check exists.

- Sub-claim A: A network-reachable API accepts attacker bytes that flow into `fs/ggml.Decode`.
- Sub-claim B: `readGGUFArray` reads `n` as uint64 and immediately casts with `int(n)` without validating the high bit.
- Sub-claim C: `newArray` gate at `fs/ggml/gguf.go:418` does not reject negative `size`; `make([]T, negative)` panics.

All sub-claims are individually checkable; none are incoherent.

## Step 2 — Independent Code Path Trace

Entry points (independent of draft prose):

- HTTP `/api/create` (server/routes.go:1703) → CreateHandler → ... → server/create.go:471 `ggml.Decode(bin, -1)`.
- HTTP `/api/pull`, `/api/show` → also route to ggml.Decode via server/model.go:66 and related paths (confirmed via grep for ggml.Decode callers).
- Model-load: ml/backend/ggml/ggml.go:130 `fsggml.Decode(r, -1)` in runner subprocess.

Path inside fs/ggml:

1. `ggml.Decode(rs, maxArraySize)` (fs/ggml/ggml.go:563) constructs `containerGGUF{maxArraySize: maxArraySize}` and calls its `Decode`.
2. `containerGGUF.Decode` (fs/ggml/gguf.go:47) reads version, then counts and calls `gguf.Decode`.
3. `gguf.Decode` iterates `numKV()` KVs; for each reads a type byte and dispatches. Array type → `readGGUFArray`.
4. `readGGUFArray` (gguf.go:424):
   - `t = readGGUF[uint32]` – subtype
   - `n = readGGUF[uint64]` – length (attacker controlled)
   - `switch t { case ggufTypeUint8: a := newArray[uint8](int(n), llm.maxArraySize); ... }`
5. `newArray` (gguf.go:416):
   ```
   if maxSize < 0 || size <= maxSize {
       a.values = make([]T, size)
   }
   ```

When `n = 0xFFFFFFFFFFFFFFFF`, `int(n)` on 64-bit = -1. Callers pass `maxArraySize = -1` (the common case from server/create.go, server/model.go, ml/backend/ggml, model/model.go), so `maxSize < 0` is true and `make([]T, -1)` is unconditionally invoked → runtime panic.

Even when maxArraySize = 1024 (llm/server.go:737, server/create.go:653), the second predicate `size <= maxSize` is `-1 <= 1024` which is true, so the panic still fires.

No validation function exists between the `readGGUF[uint64]` call and the `make`. No length cap is enforced.

## Step 3 — Protection Surface Search

| Layer | Control examined | Blocks? |
|-------|------------------|---------|
| Language | Go's make() does runtime length check that panics on negative — but panic is the attack, not a defense | N |
| fs/ggml | Any sanitization of `n` before cast | None found |
| fs/ggml | Any `math.MaxInt32` check | None found |
| HTTP body size | gin has no default body size; no middleware caps create/pull upload size for the GGUF stream | N (doesn't matter; a 33-byte header is enough) |
| Framework | gin.Recovery via gin.Default() at server/routes.go:1674 — catches runtime.Error | Partial — converts process-panic to per-request HTTP 500 on HTTP-entry paths |
| Runner subprocess | No recover() around ml.NewBackend → model.New path | No — panic tears down runner subprocess |
| SECURITY.md / docs | No explicit acceptance of malformed-GGUF DoS | N |

## Step 4 — Real-Environment Reproduction

Environment: unit test against the actual `github.com/ollama/ollama/fs/ggml` package at the reviewed commit, Darwin arm64, go test binary.

Blob: minimal GGUFv3 with a single KV whose value is an array of uint8 with length 0xFFFFFFFFFFFFFFFF (33 bytes of header + metadata).

Invocation: `ggml.Decode(bytes.NewReader(blob), -1)` — matches all four repo callers that pass `-1`.

Result:

```
PANIC RECOVERED: runtime error: makeslice: len out of range
```

First attempt succeeded; no variation needed. Evidence stored at `archon/real-env-evidence/gguf-array-length-truncation/poc_output.txt`.

PoC-Status: executed (unit-harness reproduction; HTTP-level reproduction against a running server was not attempted but the code path from `/api/create` to this decoder is direct and the internal panic is confirmed).

## Step 5 — Briefs

Prosecution:
- Sub-claim A confirmed: attacker-uploaded GGUF blobs are parsed by ggml.Decode on /api/create (server/create.go:471), /api/pull via resolveBlob flow, and /api/show.
- Sub-claim B confirmed: gguf.go:430 reads `n` as uint64, gguf.go:437 casts `int(n)` unconditionally. No validation between these lines.
- Sub-claim C confirmed: unit test reproduces exact panic "makeslice: len out of range" with only 33 bytes of crafted header. make([]T, -1) cannot succeed, and newArray's gate does not test for negative size.
- Impact: each malicious request terminates its handler with HTTP 500 (HTTP path) or crashes a runner subprocess (model-load path), creating a low-cost DoS primitive.

Defense:
- The HTTP handlers are all registered against gin.Default()'s router (server/routes.go:1674), which includes gin.Recovery middleware. gin.Recovery catches runtime.Error (which makeslice's error implements) and returns 500 rather than exiting the process. Therefore the HTTP-entry impact is capped at per-request DoS, not full-process crash.
- `/api/create` and `/api/pull` are typically reached only by admin-style clients on a localhost-bound daemon; internet exposure is not default. Precondition: attacker must be on the same host or a host whitelisted by the operator.
- The runner subprocess path requires the server first accepts the model into its blob store and launches a runner for it; the runner crashing does not crash the server, and the server can relaunch. The damage is limited to failing the specific model-load attempt.
- No code execution, memory corruption, or data disclosure is demonstrated.

The defense narrows but does not eliminate the vulnerability. gin.Recovery does not "block the attack"; it only blunts the blast radius. The panic still fires, the request is still denied, and on the runner-subprocess path there is no Recovery at all.

## Step 6 — Severity Challenge

Starting at MEDIUM.

Upgrade factors:
- Remotely triggerable: yes, over HTTP.
- Trust boundary crossed: untrusted bytes → process control-flow disruption.
- Preconditions: must reach /api/create or /api/pull (usually admin/local-bind).

Downgrade factors:
- gin.Recovery catches the panic on HTTP paths — no process exit, no persistent state damage.
- Ollama binds to 127.0.0.1 by default; internet exposure requires operator opt-in.
- No code execution, no auth bypass, no data leakage.

HIGH requires "meaningful trust boundary crossing + no significant preconditions". Recovery middleware means the "trust boundary crossing" effect is limited to a 500 response. CRITICAL (RCE / mass exfil) is out of scope.

Severity-Final: MEDIUM (same as original). No change.

## Step 7 — Verdict

Prosecution brief survives: the panic is real, reachable, and trivially crafted. Defense brief narrows severity but does not identify a protection that blocks the attack — gin.Recovery turns a process-exit into a per-request 500 but does not prevent the panic itself, and the non-HTTP runner path has no Recovery at all.

Real-environment reproduction: executed; panic produced on first attempt with a 33-byte crafted blob.

Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: Unit-level PoC reproduces the exact "makeslice: len out of range" panic in fs/ggml.Decode with a 33-byte crafted GGUF; no length validation exists between the attacker-controlled uint64 and make([]T, int(n)), and while gin.Recovery caps HTTP-path impact to per-request 500, the runner-subprocess callers (ml/backend/ggml/ggml.go:130) have no such protection.
Severity-Final: MEDIUM
PoC-Status: executed
