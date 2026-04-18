Phase: 8
Sequence: 021
Slug: gguf-string-unbounded-alloc
Verdict: VALID
Rationale: readGGUFString and readString both read an attacker uint64 length from the GGUF header and pass it directly to make([]byte, length) without any cap against file size or a hard ceiling, enabling instant OOM DoS reachable from the lazy parser on /api/show.
Severity-Original: HIGH
Severity-Final: HIGH
PoC-Status: executed
Pre-FP-Flag: none
Adversarial-Verdict: CONFIRMED
Adversarial-Rationale: 34-byte GGUF blob forced process to commit 2 GiB via attacker-controlled uint64 length on both eager (ggml.Decode) and lazy (gguf.Open+KeyValue) paths; no middleware, framework, or application layer cap intervenes.
Debate: archon/chamber-workspace/chamber-02/debate.md

## Summary

Two independent GGUF parsers -- `fs/ggml/gguf.go:348-371` (eager) and `fs/gguf/gguf.go:188-205` (lazy) -- both read a uint64 length from the input stream and use it as an allocation size for a scratch buffer with no cap.

## Location

- `fs/ggml/gguf.go:359-361` -- `length := int(llm.ByteOrder.Uint64(buf)); if length > len(llm.scratch) { buf = make([]byte, length) }`
- `fs/gguf/gguf.go:194-196` -- `if int(n) > len(f.bts) { f.bts = make([]byte, n) }`

## Attacker Control

Any caller able to introduce a GGUF blob: `/api/pull`, `/api/create`, `/api/blobs/:digest`. The lazy parser is invoked from `server/images.go:89 gguf.Open` (`Capabilities()`) so a single stored blob is enough to DoS every `/api/show` call.

## Trust Boundary Crossed

Network API -> process heap (OOM kill).

## Impact

- Single-request process OOM kill on any host with less RAM than the attacker-declared string length (attacker can declare up to 9.2 EB on a 64-bit host; Linux OOM-killer fires before any Go panic recovery).
- Persistent DoS when the blob is cached: every subsequent `/api/show` re-triggers the allocation. gin.Recovery does NOT prevent the kernel OOM-killer.

## Evidence

```
// fs/ggml/gguf.go:353-371
buf := llm.scratch[:8]
_, err := io.ReadFull(r, buf)
if err != nil { return "", err }

length := int(llm.ByteOrder.Uint64(buf))   // no cap
if length > len(llm.scratch) {
    buf = make([]byte, length)             // unbounded alloc
} else {
    buf = llm.scratch[:length]
}
```

```
// fs/gguf/gguf.go:188-205
func readString(f *File) (string, error) {
    n, err := read[uint64](f)
    ...
    if int(n) > len(f.bts) {
        f.bts = make([]byte, n)            // unbounded alloc
    }
    bts := f.bts[:n]
    ...
}
```

Advocate 5-layer search (Round 3): no MaxBytesReader on `/api/create`/`/api/blobs`, no length cap anywhere in the reader path.

## Reproduction Steps

1. Craft a GGUF header declaring a KV string whose length field = 0x7FFFFFFF00000000.
2. `POST /api/blobs/sha256-<digest>` uploading just the header region (truncation is fine; the alloc fires before the bytes are read).
3. `POST /api/create` referencing that blob.
4. Observe: the server process is OOM-killed before the request completes.

## Adversarial reproduction evidence

Real-env PoCs in `archon/real-env-evidence/gguf-string-unbounded-alloc/`:
- Eager path: 34-byte blob into `ggml.Decode(blob, -1)` -> process Sys grew 12 MiB -> 2062 MiB before `ReadFull` returned `unexpected EOF`.
- Lazy path: 34-byte blob, `gguf.Open` returned nil error, first `KeyValue("pooling_type")` call -> process Sys grew 8 MiB -> 2062 MiB.
Full review: `archon/adversarial-reviews/gguf-string-unbounded-alloc-review.md`.

Fix direction: hard cap `length <= min(fileSize, 64<<20)` or similar reasonable max-string-length constant; return an explicit error when exceeded.
