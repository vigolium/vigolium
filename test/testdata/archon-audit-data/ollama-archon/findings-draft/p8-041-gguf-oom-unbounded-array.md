Phase: 8
Sequence: 041
Slug: gguf-oom-unbounded-array
Verdict: VALID
Rationale: Remote unauthenticated OOM DoS via crafted GGUF array; maxArraySize=-1 sentinel disables the only allocation limit on the create path; attacker can allocate arbitrary heap memory. Structural recurrence of CVE-2025-0315.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-C/debate.md

## Summary

The GGUF parser's `readGGUFArray` function allocates Go slices based on the array size field read from the GGUF binary. The `newArray` function at gguf.go:416 has a `maxArraySize` parameter intended to limit allocations, but the `ggml.Decode` call from the create path passes `-1` as `maxArraySize`. The condition `maxSize < 0` at line 418 evaluates to true, causing the allocation to proceed for any requested size. An attacker can craft a GGUF file with a multi-gigabyte array declaration, upload the file via the unauthenticated blob API, and trigger OOM when `POST /api/create` parses it.

## Location

- **Primary**: `fs/ggml/gguf.go:416-422` -- `newArray` with `maxSize < 0` bypass
- **Caller**: `fs/ggml/gguf.go:437` -- `newArray[uint8](int(n), llm.maxArraySize)`
- **Decode call**: `server/create.go:684` -- `ggml.Decode(blob, -1)` (maxArraySize = -1)
- **Entry point**: `POST /api/blobs/:digest` (upload), then `POST /api/create` (parse)

## Attacker Control

The attacker controls the array size field `n` (uint64) and element type (uint32) in the GGUF KV entry. With element_type=uint8 and n=0x40000000 (1GB), the parser allocates a 1GB slice. The attacker must provide matching bytes in the file body (io.ReadFull will error on short reads), but no upload body size limit prevents uploading multi-GB files.

## Trust Boundary Crossed

Network (unauthenticated HTTP) -> file system -> GGUF parser -> Go heap allocator. Attacker-controlled binary size values directly control heap allocation size.

## Impact

- **Availability**: Server OOM. Go runtime kills the process or the OS OOM killer terminates it.
- **Amplification**: A single GGUF file with multiple large array KV entries can multiply the memory consumption.
- **Attack complexity**: LOW. Requires uploading actual bytes matching the declared array size, but no upload limit prevents this.
- **Authentication**: None required.

## Evidence

1. `fs/ggml/gguf.go:416-422` -- `newArray`: `if maxSize < 0 || size <= maxSize { a.values = make([]T, size) }`
2. `server/create.go:684` -- `ggml.Decode(blob, -1)` passes -1 as maxArraySize
3. `fs/ggml/gguf.go:39` -- `maxArraySize int` stored in containerGGUF struct
4. `server/routes.go:1538` -- `manifest.NewLayer(c.Request.Body, "")` -- no MaxBytesReader
5. CVE-2025-0315 (CWE-770) -- prior unlimited memory allocation from GGUF in same parser

## Reproduction Steps

1. Create a GGUF file with a KV entry of type=array, element_type=uint8, n=1073741824 (1GB), followed by 1GB of data
2. Upload via `POST /api/blobs/sha256:<hash>` with the file as request body
3. Send `POST /api/create` referencing the digest
4. Monitor server memory usage; observe ~1GB allocation per array entry parsed
5. Repeat with larger values or multiple array entries to trigger OOM
