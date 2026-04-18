Phase: 8
Sequence: 040
Slug: gguf-string-length-panic
Verdict: VALID
Rationale: Remote unauthenticated DoS via crafted GGUF file; uint64-to-int cast of attacker-controlled string length produces negative value causing slice bounds panic in unprotected background goroutine, crashing the server. No sanitizers exist despite prior CVEs (CVE-2024-39720, CVE-2025-66960) in same code.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-C/debate.md

## Summary

The GGUF parser's `readGGUFString` function reads an 8-byte uint64 length field from the GGUF binary and casts it to a signed `int` without checking for sign overflow or applying an upper bound. When the high bit is set (e.g., 0x8000000000000000), the cast produces `math.MinInt64` (a large negative number). This negative value is used as a slice upper bound (`llm.scratch[:MinInt64]`), causing a Go runtime panic with "slice bounds out of range". The panic occurs in a background goroutine spawned by `CreateHandler` (create.go:99) that has no `recover()` handler, so the panic kills the entire server process.

## Location

- **Primary**: `fs/ggml/gguf.go:359` -- `length := int(llm.ByteOrder.Uint64(buf))`
- **Panic site**: `fs/ggml/gguf.go:363` -- `buf = llm.scratch[:length]` (negative index)
- **Entry point**: `POST /api/blobs/:digest` (upload), then `POST /api/create` (parse)
- **Goroutine**: `server/create.go:99` -- `go func() { defer close(ch); ... }` (no recover)

## Attacker Control

The attacker fully controls the 8-byte length field. It is read directly from the uploaded GGUF binary with no validation. The upload API (`POST /api/blobs/:digest`) is unauthenticated and accepts arbitrary binary content. The create API (`POST /api/create`) triggers parsing of the uploaded blob.

## Trust Boundary Crossed

Network (unauthenticated HTTP request) -> file system (blob storage) -> GGUF parser (binary interpretation) -> Go runtime (process crash). The attacker-supplied binary crosses the network trust boundary and reaches the parser without any intermediate validation of the string length field.

## Impact

- **Availability**: Complete server process crash (DoS). All active model sessions and pending requests are terminated.
- **Recoverability**: Requires process restart. If the malicious blob remains on disk, repeated create requests will re-trigger the crash.
- **Attack complexity**: LOW. A 32-byte crafted GGUF file is sufficient.
- **Authentication**: None required.

## Evidence

1. `fs/ggml/gguf.go:348-371` -- `readGGUFString` reads uint64, casts to int, uses as slice bound
2. `fs/ggml/gguf.go:359` -- `length := int(llm.ByteOrder.Uint64(buf))` -- no sign check
3. `fs/ggml/gguf.go:360` -- `if length > len(llm.scratch)` -- MinInt64 < len(scratch), falls through
4. `fs/ggml/gguf.go:363` -- `buf = llm.scratch[:MinInt64]` -- runtime panic
5. `server/create.go:99` -- background goroutine without recover()
6. `server/routes.go:1666` -- `gin.Default()` includes Recovery, but only for handler goroutine
7. CVE-2024-39720 -- prior OOB read from 4-byte GGUF (same parser, same bug class)
8. CVE-2025-66960 -- prior unchecked string-length read (same function)

## Reproduction Steps

1. Create a minimal GGUF file (32 bytes): magic bytes (4) + version (4) + numTensor (8) + numKV=1 (8) + key-length=0x8000000000000000 (8)
2. Upload via `POST /api/blobs/sha256:<hash-of-file>` with the crafted binary as the request body
3. Send `POST /api/create` with JSON body referencing the uploaded blob digest in `files`
4. Observe server process crash with panic: "runtime error: slice bounds out of range"
5. Verify that the Ollama process has exited (not just the request failing)
