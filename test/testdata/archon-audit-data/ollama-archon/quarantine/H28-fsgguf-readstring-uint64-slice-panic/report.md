## Summary

`fs/gguf/gguf.go:188-205` implements `readString()` for the `fs/gguf` package
(distinct from `fs/ggml/gguf.go`'s `readGGUFString`).  It reads a `uint64`
length, then checks whether to grow the reuse buffer:

```go
if int(n) > len(f.bts) {   // BUG: int(n) wraps negative for n >= 2^63
    f.bts = make([]byte, n)
}
bts := f.bts[:n]           // CRASH: f.bts is 4096 bytes; n is huge uint64
```

For `n >= 2^63` (e.g. `n = 0x8000000000000001`):
- `int(n)` = `-9223372036854775807` (signed wrap)
- `-9223372036854775807 > 4096` is `false`, so the buffer is NOT grown
- `f.bts[:0x8000000000000001]` panics: "runtime error: slice bounds out of range"

The panic propagates up through `readTensor()` → `newLazy()` → `Open()`,
causing `gguf.Open()` in `server/images.go:89` to terminate the goroutine with
a runtime panic.  Go's `gin.Recovery` middleware catches the panic for the
outer HTTP handler, but the model enumeration that runs at startup (outside any
HTTP handler) will crash the process.

`fs/gguf.Open()` is called from `server/images.go:89` during `Capabilities()`
which is invoked:
1. At server startup for every model in the blob store.
2. On every `GET /api/show` request.

A crafted GGUF injected into the blob store (via any of the three blob-upload
paths) causes a permanent crash loop on server restart.

## Details

`fs/gguf/gguf.go:188-205` implements `readString()` for the `fs/gguf` package
(distinct from `fs/ggml/gguf.go`'s `readGGUFString`).  It reads a `uint64`
length, then checks whether to grow the reuse buffer:

```go
if int(n) > len(f.bts) {   // BUG: int(n) wraps negative for n >= 2^63
    f.bts = make([]byte, n)
}
bts := f.bts[:n]           // CRASH: f.bts is 4096 bytes; n is huge uint64
```

For `n >= 2^63` (e.g. `n = 0x8000000000000001`):
- `int(n)` = `-9223372036854775807` (signed wrap)
- `-9223372036854775807 > 4096` is `false`, so the buffer is NOT grown
- `f.bts[:0x8000000000000001]` panics: "runtime error: slice bounds out of range"

The panic propagates up through `readTensor()` → `newLazy()` → `Open()`,
causing `gguf.Open()` in `server/images.go:89` to terminate the goroutine with
a runtime panic.  Go's `gin.Recovery` middleware catches the panic for the
outer HTTP handler, but the model enumeration that runs at startup (outside any
HTTP handler) will crash the process.

`fs/gguf.Open()` is called from `server/images.go:89` during `Capabilities()`
which is invoked:
1. At server startup for every model in the blob store.
2. On every `GET /api/show` request.

A crafted GGUF injected into the blob store (via any of the three blob-upload
paths) causes a permanent crash loop on server restart.

### Location

- `fs/gguf/gguf.go:188-204` — `readString()` uint64-to-int cast + unchecked slice
- `fs/gguf/gguf.go:93-128` — `readTensor()` calls `readString()` for tensor name
- `server/images.go:89` — `gguf.Open(m.ModelPath)` in `Capabilities()`

### Attacker Control

Same three delivery paths as AP-020: `POST /api/create`, `POST /api/pull`,
`POST /api/blobs/:digest`.  The crafted GGUF needs only 8 bytes of tensor
name-length field set to `0x8000000000000001` following a valid header, making
the payload trivial to craft.

### Trust Boundary Crossed

Network API → server startup / `Capabilities()` goroutine → Go runtime panic
that escapes HTTP handler recovery and crashes the process on next restart.

### Evidence

```go
// fs/gguf/gguf.go:188-204
func readString(f *File) (string, error) {
    n, err := read[uint64](f)        // n = 0x8000000000000001 (attacker-controlled)
    if err != nil {
        return "", err
    }

    if int(n) > len(f.bts) {        // int(0x8000000000000001) = -9223372036854775807
        // This branch is NOT taken: negative < 4096
        f.bts = make([]byte, n)
    }

    bts := f.bts[:n]                 // PANIC: f.bts is 4096 bytes, n = 0x8000000000000001
    ...
}

// fs/gguf/gguf.go:93-100
func (f *File) readTensor() (TensorInfo, error) {
    name, err := readString(f)       // <-- panics here on crafted input
    if err != nil {
        return TensorInfo{}, err
    }
    ...
}

// server/images.go:89
f, err := gguf.Open(m.ModelPath)    // <-- calls readTensor -> readString -> panic
```

Craft: valid GGUF magic + version 2 header; tensor count = 1; tensor record
begins with uint64 name-length = `0x8000000000000001`.

## Root Cause

Validated rationale: fs/gguf/gguf.go readString() reads a uint64 length field, checks int(n) > len(f.bts) to decide whether to grow the buffer, but for n >= 2^63 the int(n) cast wraps negative and the check is false; the subsequent f.bts[:n] slice expression panics because n exceeds the 4096-byte initial buffer length, crashing the server on the first GGUF open.

Primary cited code reference: `fs/gguf/gguf.go:188`.

Merge extraction sink line: - `fs/gguf/gguf.go:188-204` — `readString()` uint64-to-int cast + unchecked slice

This finding was retained as a variant during merge normalization. Origin finding: `C2`. Origin pattern: `AP-020`.

## Proof of Concept

Merge-normalized status: `pending`.

No concrete evidence artifacts were preserved under `evidence/` during the merge.

1. Build a minimal GGUF file:
   - 4-byte magic `GGUF`
   - 4-byte version `\x02\x00\x00\x00`
   - 8-byte tensor count `\x01\x00\x00\x00\x00\x00\x00\x00`
   - 8-byte KV count `\x00\x00\x00\x00\x00\x00\x00\x00`
   - tensor 0 name-length `\x01\x00\x00\x00\x00\x00\x00\x80` (= 0x8000000000000001)
2. Place in blob store via `POST /api/blobs/sha256:<digest>`.
3. Restart the Ollama server.
4. Observe: server panics during startup enumeration, never opens the HTTP port.

Fix: in `readString`, change the guard to `if n > uint64(len(f.bts))` (compare
as uint64); also add an absolute maximum (`if n > maxStringSize { return error }`).

## Impact

- **Persistent crash loop**: once a crafted GGUF is in the blob store,
  every restart of the Ollama server panics during startup enumeration before
  any HTTP listener is opened, making the server permanently inoperable.
- **Denial of service on `/api/show`**: before the crash, a request to
  `GET /api/show?model=<crafted>` triggers `Capabilities()` → panic inside the
  gin handler; gin.Recovery returns a 500, but this is also a DoS vector on
  demand.
- **No authentication required**: blob injection is unauthenticated on the
  default loopback configuration.

_Synthesized during merge normalization from `archon/findings/H28-fsgguf-readstring-uint64-slice-panic/draft.md`._
