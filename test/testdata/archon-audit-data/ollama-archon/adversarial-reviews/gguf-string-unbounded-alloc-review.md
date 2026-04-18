Adversarial Cold Review: gguf-string-unbounded-alloc

## Restated claim and sub-claims

Two GGUF parsers in the ollama tree read an attacker-controlled uint64 from a
file header and pass it directly into `make([]byte, n)` without any upper bound.
An attacker who can place a malicious blob into the local blob store (via
`/api/blobs/<digest>` + `/api/create`, or indirectly by causing `/api/show` to
open the stored file) can force the server process to allocate arbitrary memory,
leading to either a recoverable panic or a kernel OOM-kill depending on host
capacity.

Sub-claim A: Attacker reaches /api/blobs or /api/create with crafted blob body.
Sub-claim B: Blob bytes flow into ggml.Decode / gguf.Open, and the uint64
length is not capped before make([]byte, length).
Sub-claim C: The resulting allocation causes memory exhaustion.

## Code path trace (independent)

Eager parser path:
- `server/routes.go:1703` registers `CreateHandler`.
- `server/create.go:46 CreateHandler` -> `ggufLayers(digest, fn)` when a
  files entry is supplied.
- `server/create.go:687` `ggml.Decode(blob, -1)` — the -1 means maxArraySize
  is unlimited (see comment at `fs/ggml/ggml.go:562`).
- `fs/ggml/gguf.go:141 Decode` loops `numKV` times calling `readGGUFString`.
- `fs/ggml/gguf.go:359-361` reads uint64 length, `if length > len(scratch)`
  (scratch is 16KB) falls to `buf = make([]byte, length)` — no cap.

Lazy parser path:
- `server/routes.go:1693` registers `ShowHandler`.
- `server/routes.go:1106 ShowHandler` -> `GetModelInfo` -> `GetModel` ->
  `m.Capabilities()`.
- `server/images.go:89 Capabilities` calls `gguf.Open(m.ModelPath)`.
- `fs/gguf/gguf.go:47 Open` reads magic, version, tensorCount, keyValueCount
  and returns. No string read yet.
- `Capabilities()` then calls `f.KeyValue("pooling_type")`, which in
  `fs/gguf/gguf.go:282` iterates `f.keyValues.next()`, calling `readKeyValue`.
- `fs/gguf/gguf.go:130 readKeyValue` calls `readString(f)`.
- `fs/gguf/gguf.go:188-196 readString` reads uint64 n, and if
  `int(n) > len(f.bts)` does `f.bts = make([]byte, n)` — no cap.

## Protections search

Per-layer analysis:

- Language / runtime: Go's mallocgc panics only at `maxAlloc` (~1<<48 on
  64-bit). Attacker-chosen values in the 1 GB-100 GB range allocate successfully.
- Framework: no BodyLimit on /api/create, /api/blobs/:digest, or /api/show.
  Grep across the server tree for MaxBytesReader returns only cloud-proxy and
  openai-compat paths (unrelated).
- Middleware: `allowedHostsMiddleware` restricts cross-origin non-loopback
  clients but admits all requests when the server is bound to 0.0.0.0 or any
  private/loopback IP.
- Application: `detectContentType` only checks the first four bytes for the
  GGUF magic; it does not validate structure or length fields. The digest check
  in `CreateBlobHandler` only verifies SHA-256 matches the URL parameter; the
  attacker computes the SHA-256 of their own malicious blob.
- Documentation: SECURITY.md not found as relevant carve-out.

No layer blocks the claimed alloc primitive.

## Real-environment reproduction

Environment: Go 1.24.1 on darwin/arm64 at commit 57653b8e.

Test 1 (eager parser, ggml.Decode):
  go test ./fs/ggml/ -run TestPocUnboundedStringAlloc -v
  Blob: 34 bytes (magic+version+numTensor=0+numKV=1+declared_length=2GiB+2 bytes)
  Result: Decode returned err="unexpected EOF"
  Memory: process Sys grew from 12 MiB to 2062 MiB (delta 2050 MiB)
  Status: CONFIRMED

Test 2 (lazy parser, gguf.Open -> KeyValue):
  go test ./fs/gguf/ -run TestPocLazyUnboundedStringAlloc -v
  Blob: 34 bytes (identical shape)
  Open: succeeded (no alloc at Open time)
  KeyValue("pooling_type"): triggered lazy read; declared 2 GiB length
  Result: "unexpected EOF" after the alloc
  Memory: process Sys grew from 8 MiB to 2062 MiB (delta 2054 MiB)
  Status: CONFIRMED

Evidence: `archon/real-env-evidence/gguf-string-unbounded-alloc/`
  - eager_poc_test.go
  - lazy_poc_test.go
  - run.txt

PoC-Status: executed

## Prosecution brief

Both `readGGUFString` (eager) and `readString` (lazy) take an attacker
uint64 and pass it verbatim to make([]byte, n). Reproduction demonstrates a
2048:1 amplification (34 byte input -> 2048 MiB allocation) with zero
parsing work. Neither `gin.Recovery` nor any MaxBytesReader intercepts the
primitive because the allocation happens inside a Go runtime make() call,
and for sizes below maxAlloc the allocation succeeds without panic. An
attacker who can reach /api/blobs and /api/create — unauthenticated on any
non-default-loopback bind — achieves either a kernel OOM-kill (declared
length near host RAM) or a persistent per-request memory-pressure spike
(declared length a few GiB, repeated). The /api/show path amplifies this
into a persistent DoS: once the malicious blob is stored, every subsequent
/api/show re-opens it and re-triggers the lazy read.

## Defense brief

The attack requires write access to the blob store which is gated by
`allowedHostsMiddleware`; default deployments bind to loopback. A Go
runtime out-of-memory panic is recovered by `gin.Recovery` when the
declared length exceeds maxAlloc. The transient 2 GB allocation seen in
reproduction releases when the goroutine returns, so repeated requests
don't accumulate. The SHA-256 digest check on /api/blobs forces the
attacker to commit to a specific blob content before upload. None of these
individually or collectively prevent the primitive, but they raise the
precondition from "any network client" to "network client that can reach
the chosen bind address with a reasonable blob."

## Severity challenge

Start: MEDIUM.
- Remotely triggerable: yes (network API).
- Trust boundary crossed: yes (untrusted client -> Go heap).
- Preconditions: unauthenticated on any non-loopback bind. On default
  loopback, requires local access.
- Impact: repeatable process-kill or recoverable heavy alloc.

Upgrade to HIGH is justified (remote + trust boundary + low precondition on
cloud/container deployments).
Not CRITICAL — DoS only, and default bind is loopback.

Severity-Final: HIGH (same as original).

## Verdict

CONFIRMED.
Decisive evidence: reproduction shows a 34-byte GGUF blob forces the Go
runtime to commit ~2 GB via attacker-controlled uint64 length, on both
eager and lazy parser paths; no framework, middleware, or application
control intervenes.
