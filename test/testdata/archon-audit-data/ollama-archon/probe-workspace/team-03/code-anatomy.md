# Code Anatomy: Team-03

## Source Files
- `fs/ggml/gguf.go` — GGUF container decoder
- `fs/ggml/ggml.go` — GGML model interface, Tensor type, Decode entry point
- `fs/ggml/type.go` — TensorType constants
- `server/routes.go` — HTTP route handlers (CreateBlobHandler, HeadBlobHandler)
- `server/create.go` — CreateHandler, ggufLayers, convertModelFromFiles, createModel
- `server/model.go` — parseFromModel, intermediateBlobs map
- `server/download.go` — downloadBlob, blobDownload
- `server/images.go` — PullModel, verifyBlob, skipVerify map
- `server/internal/cache/blob/cache.go` — DiskCache, copyNamedFile, checkWriter
- `manifest/paths.go` — BlobsPath (digest validation + path construction)
- `manifest/layer.go` — NewLayer, NewLayerFromLayer, Layer.Open

## Key Data Flow

### Upload path (CreateBlobHandler)
```
POST /api/blobs/:digest
  -> manifest.BlobsPath(digest)   [validate digest format; construct path]
  -> os.Stat(path)                [if exists: 200 OK — NO content check]
  -> manifest.NewLayer(body, "")  [read entire body; compute SHA256; rename to blob path]
  -> compare layer.Digest == c.Param("digest")  [if mismatch: 400 BAD REQUEST]
  -> 201 CREATED
```
IMPORTANT: The file is written to disk BEFORE the digest comparison. NewLayer writes to a temp file then renames. If digest matches, the blob stays on disk.

### Create model path (CreateHandler -> ggufLayers)
```
POST /api/create {files: {"model.gguf": "sha256:..."}}
  -> convertModelFromFiles(files, ...)
  -> detectModelTypeFromFiles  [reads 4 bytes for magic or checks extension]
  -> ggufLayers(digest, fn)
    -> manifest.BlobsPath(digest)
    -> os.Open(blobPath)        [NO integrity re-check]
    -> ggml.Decode(blob, -1)    [maxArraySize=-1: collect ALL arrays]
      -> binary.Read(magic)
      -> containerGGUF.Decode(rs)
        -> read Version (uint32)
        -> read numTensor, numKV (uint64 — NO max bound)
        -> loop numKV times: readGGUFString + readGGUF[type] + readGGUFArray
        -> loop numTensor times: readGGUFString + readGGUF[uint32 dims] + ...
        -> tensor bounds check (tensorOffset + tensor.Offset + tensor.Size() <= fileSize)
```

### Pull model cache hit path
```
PullModel(ctx, name, regOpts, fn)
  -> downloadBlob(ctx, opts)
    -> manifest.BlobsPath(digest)
    -> os.Stat(fp)   [if file exists: return cacheHit=true — NO hash check]
  -> skipVerify[layer.Digest] = cacheHit
  -> if skipVerify[digest]: SKIP verifyBlob  [INTEGRITY BYPASS]
  -> (on model load) ggml.Decode(blob, -1)  [unverified content enters parser]
```

### DiskCache copyNamedFile path
```
DiskCache.Put(d, r, size)
  -> copyNamedFile(c.GetFile(d), r, d, size)
    -> os.Stat(name)
    -> if err == nil && info.Size() == size: return nil  [SIZE-ONLY CHECK — SKIP HASH]
    -> else: checkWriter with sha256  [only on NEW writes]
```

## Critical Functions

### `readGGUFString` (gguf.go:348)
- Reads 8 bytes as uint64 `length`
- If `length > len(llm.scratch)` (16KB): allocates `make([]byte, length)` — no upper bound
- Calls `io.ReadFull(r, buf)` — if length is huge, this will try to read that many bytes from the file
- Mitigation: io.ReadFull will return io.ErrUnexpectedEOF if file is shorter — returns error, no crash
- BUT: `make([]byte, length)` where length is attacker-controlled uint64 interpreted as int
  - On 64-bit: int is 64-bit; max uint64 as int is -1 (negative) -> make panics or truncates
  - Values like 0x7FFFFFFFFFFFFFFF would allocate 8 exabytes -> OOM

### `readGGUFArray` (gguf.go:424)
- Reads type (uint32) and count n (uint64)
- Calls `newArray[T](int(n), llm.maxArraySize)`
- `newArray` at line 416: if `maxSize < 0 || size <= maxSize` -> `make([]T, size)`
- When maxArraySize == -1 (from ggufLayers): condition is `-1 < 0` which is TRUE
- So `make([]T, int(n))` is called for ALL arrays regardless of n
- uint64 n cast to int: on 64-bit, values > MaxInt64 become negative (make panics); values 0..MaxInt64 result in arbitrarily large allocations

### `gguf.Decode` loop (gguf.go:143)
- `for i := 0; uint64(i) < llm.numKV(); i++`
- numKV() returns uint64 from file header — no maximum
- Each iteration: readGGUFString (potential alloc) + readGGUFArray (potential alloc)
- No per-iteration memory limit; total memory unbounded

### `copyNamedFile` (cache.go:457)
- Line 459: `if err == nil && info.Size() == size { return nil }` — THE GAP
- The `// TODO: Do the hash check` comment confirms developers know this is insufficient
- The `checkWriter` at line 489 does proper SHA-256 verification — but ONLY for new files
- Existing same-size files bypass the checkWriter entirely

### `downloadBlob` cache hit (download.go:478-491)
- `fi, err := os.Stat(fp)` — follows symlinks
- No `os.Lstat` check to detect symlinks
- Returns `cacheHit=true` for ANY file that exists, including symlinks, partial files, or replaced files

### `intermediateBlobs` (model.go:20)
- `var intermediateBlobs map[string]string = make(map[string]string)`
- Plain Go map — NOT thread-safe
- Accessed in HTTP handler goroutine (CreateBlobHandler, routes.go:1501, 1510)
- Multiple concurrent POST /api/blobs/:digest requests can race on map read+delete

## Structural Observations

1. The GGUF parser has been patched multiple times (9 CVEs) but no systematic bounds checking framework exists. Each fix is a point patch.

2. The integrity verification is split across two codepaths (old: manifest/download.go, new: cache/blob/cache.go) with different and insufficient checks. Neither path verifies integrity on cache hit.

3. The `0o777` permission on blob directories (cache.go:79-85) is inconsistent with `0o755` in manifest/paths.go:56, creating a privilege inconsistency in the two cache systems.

4. `ggml.Decode` is called in multiple places with different maxArraySize values:
   - `ggufLayers` (create.go:684): maxArraySize=-1 (unlimited) — MOST DANGEROUS
   - `parseFromModel` (model.go:64): maxArraySize=-1
   - `quantizeLayer` (create.go:650): maxArraySize=1024 — bounded
   - Testing code: various values
