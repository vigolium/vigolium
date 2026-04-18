## Summary

Two independent GGUF parsers -- `fs/ggml/gguf.go:348-371` (eager) and `fs/gguf/gguf.go:188-205` (lazy) -- both read a uint64 length from the input stream and use it as an allocation size for a scratch buffer with no cap.

## Details

Two independent GGUF parsers -- `fs/ggml/gguf.go:348-371` (eager) and `fs/gguf/gguf.go:188-205` (lazy) -- both read a uint64 length from the input stream and use it as an allocation size for a scratch buffer with no cap.

### Location

- `fs/ggml/gguf.go:359-361` -- `length := int(llm.ByteOrder.Uint64(buf)); if length > len(llm.scratch) { buf = make([]byte, length) }`
- `fs/gguf/gguf.go:194-196` -- `if int(n) > len(f.bts) { f.bts = make([]byte, n) }`

### Attacker Control

Any caller able to introduce a GGUF blob: `/api/pull`, `/api/create`, `/api/blobs/:digest`. The lazy parser is invoked from `server/images.go:89 gguf.Open` (`Capabilities()`) so a single stored blob is enough to DoS every `/api/show` call.

### Trust Boundary Crossed

Network API -> process heap (OOM kill).

### Evidence

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

## Root Cause

Validated rationale: readGGUFString and readString both read an attacker uint64 length from the GGUF header and pass it directly to make([]byte, length) without any cap against file size or a hard ceiling, enabling instant OOM DoS reachable from the lazy parser on /api/show.

Primary cited code reference: `fs/ggml/gguf.go:359`.

Merge extraction sink line: - `fs/ggml/gguf.go:359-361` -- `length := int(llm.ByteOrder.Uint64(buf)); if length > len(llm.scratch) { buf = make([]byte, length) }`

An adversarial review was preserved alongside the draft and should be consulted for counter-arguments and any severity challenge.

## Proof of Concept

Merge-normalized status: `executed`.

PoC script present: `poc.py`.

Supporting evidence is present under `evidence/`.

1. Craft a GGUF header declaring a KV string whose length field = 0x7FFFFFFF00000000.
2. `POST /api/blobs/sha256-<digest>` uploading just the header region (truncation is fine; the alloc fires before the bytes are read).
3. `POST /api/create` referencing that blob.
4. Observe: the server process is OOM-killed before the request completes.

## Impact

- Single-request process OOM kill on any host with less RAM than the attacker-declared string length (attacker can declare up to 9.2 EB on a 64-bit host; Linux OOM-killer fires before any Go panic recovery).
- Persistent DoS when the blob is cached: every subsequent `/api/show` re-triggers the allocation. gin.Recovery does NOT prevent the kernel OOM-killer.

_Synthesized during merge normalization from `archon/findings/H3-gguf-string-unbounded-alloc/draft.md`._
