Phase: 8
Sequence: 017
Slug: gguf-string-int-cast-panic-dos
Verdict: VALID
Rationale: Tracer confirmed `fs/ggml/gguf.go:354-363` reads a `uint64` length and casts to `int`, wrapping negative for values > MaxInt64 — `llm.scratch[:negative_length]` panics with "slice bounds out of range", and for values in (16384, MaxInt64] the subsequent `make([]byte, length)` panics with "len out of range"; gin recovers each to HTTP 500 so the finding is bounded to request-scope DoS, but the broader integer-cast-at-cgo-boundary pattern is a known class warranting disclosure.
Severity-Original: MEDIUM
Severity-Final: MEDIUM
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-03/debate.md

## Summary

`fs/ggml/gguf.go:354-363` (GGUF V2+ string read) does:

```go
buf = llm.scratch[:8]
io.ReadFull(r, buf)
length := int(llm.ByteOrder.Uint64(buf))     // uint64 -> int on amd64 = int64 cast
if length > len(llm.scratch) {
    buf = make([]byte, length)               // panics if length > memory
} else {
    buf = llm.scratch[:length]               // panics if length < 0
}
```

For attacker-supplied `length`:
- `length > MaxInt64` (unsigned value): cast wraps to negative. The `length > len(llm.scratch)` comparison is false (negative < positive). Falls to `llm.scratch[:length]` which panics with "slice bounds out of range [:negative]".
- `length in (len(llm.scratch), MaxInt64]`: positive; triggers `make([]byte, length)` which panics for huge values.

Both panics bubble up through the GGUF parse stack. The `POST /api/create` handler runs inside gin, whose default panic-recovery middleware converts the panic into HTTP 500. The server process does NOT crash. However, the endpoint is rendered unusable for valid requests during the parse window, and each malicious request costs the full GGUF header I/O.

## Location

- `fs/ggml/gguf.go:354-363` -- V2+ string length read; `int(uint64)` cast without validation
- `fs/ggml/gguf.go:296` -- V1 string read via `io.CopyN(buf, r, int64(length))` — related but documented as p8-030 in chamber-02 (AP-030)
- GGUF KV loop at `fs/ggml/gguf.go:143` iterates `numKV` entries, calling the string read per entry

## Attacker Control

Unauthenticated `POST /api/create` with a crafted GGUF whose KV section contains a string entry with `length = 0xFFFFFFFFFFFFFFFF` (or any value > MaxInt64 to trigger negative wrap, or > 1 GB to trigger alloc panic).

Alternate entry: `POST /api/pull` of a registry model whose manifest points to a crafted GGUF blob; pull triggers lazy parse.

## Trust Boundary Crossed

Unauthenticated HTTP upload -> GGUF parser panic -> gin recovery -> HTTP 500 on `/api/create`.

## Impact

Request-scoped DoS. Each malicious request consumes the parse-side I/O and CPU until the panic point. The process recovers, but concurrent legitimate `/api/create` requests serialized on shared GGUF parser state may stall. The DoS can be chained with p8-042 (runner OOM) or p8-040 (runner SIGSEGV) for a multi-surface denial.

More importantly, the `int(uint64)` cast pattern is a class-level concern. Chamber-02 AP-022 and AP-030 document siblings. Not all sites are behind gin panic recovery; if this pattern exists in the runner subprocess parser, the runner crashes unrecovered. Tracer flagged this as a pattern warranting audit for similar sites in hot paths.

## Evidence

Tracer verification (Round 3, H-NEW-44, 2026-04-17T10:21:00Z):

```
fs/ggml/gguf.go:354-363 -- uint64 -> int cast
fs/ggml/gguf.go:360-361 -- if length > len(scratch): make() panic path
fs/ggml/gguf.go:362-363 -- else: scratch[:length] panic path for negative length
```

Advocate's Round 1 briefs did not cover H-NEW-44 (novel). Tracer walked the panic paths and confirmed gin recovery contains the blast radius to request scope:

> "panics from GGUF parsing would crash the HTTP handler goroutine. For the `/api/create` endpoint, a panic in the goroutine serving that request would cause `net/http` to recover it (Go's HTTP server has a default panic recovery that returns 500). The panic does NOT crash `ollama serve` itself."

Synth disposition: the gin recovery converts the panic to DoS. The finding is MEDIUM because (a) the bug is real and exploitable without auth, (b) it participates in the same pattern family as chamber-02 AP-022/AP-030, (c) the recovery depends on the handler running under gin — any internal code path that parses GGUF without HTTP wrap (e.g., during server start-up or model import from disk via CLI) would propagate the panic to process crash.

## Reproduction Steps

1. Craft a minimal GGUF with one KV entry of `type=String` and `length_bytes = \xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF` (uint64 max).
2. `curl -X POST http://127.0.0.1:11434/api/blobs/sha256:<digest>` to upload.
3. `curl -X POST http://127.0.0.1:11434/api/create -d '{"model":"evil","from":"sha256:<digest>"}'`
4. Observe 500 error; server logs show slice-bounds panic recovered by gin.
5. Fix direction: at `fs/ggml/gguf.go:356`, use `math.MaxInt` check: `if rawLen > uint64(math.MaxInt32) { return ErrStringTooLong }`. Apply a hard cap (e.g., 64 MiB) appropriate for GGUF metadata strings. Audit all other `int(uint64Val)` casts in parser code against the pattern in AP-022.

Pattern: reuse AP-022 `uint64-to-int-negative-make` (chamber-02) — this is a confirmed new instance.
