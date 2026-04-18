# Attack Surface Map: Team-03 (DFD-4 + CFD-3)

## Components
- DFD-4: Blob Upload -> GGUF Parse -> Crash
- CFD-3: Blob Integrity: cache hit skip, size-only check

## Entry Points

- `server/routes.go:1500` — `CreateBlobHandler` — accepts unauthenticated HTTP POST body as raw blob bytes; digest provided by caller in URL param
- `server/routes.go:1485` — `HeadBlobHandler` — accepts unauthenticated HTTP HEAD; digest from URL param
- `server/routes.go:1695` — `CreateHandler` (POST /api/create) — accepts JSON body with `files` map (filename -> digest), `from` model name, `adapters` digests; triggers GGUF decode of referenced blobs
- `server/download.go:468` — `downloadBlob` — called from `PullModel`; stat-only cache hit check; no content verification on hit
- `server/create.go:658` — `ggufLayers` — opens blob by digest, calls `ggml.Decode(blob, -1)` with maxArraySize=-1 (collect ALL arrays); direct path from unauthenticated upload to parser
- `fs/ggml/ggml.go:563` — `Decode` — entry to GGUF parser; receives `io.ReadSeeker` from opened blob file
- `fs/ggml/gguf.go:47` — `containerGGUF.Decode` — dispatches on Version (1/2/3+), reads numTensor/numKV counts; no upper-bound validation on counts
- `server/internal/cache/blob/cache.go:457` — `copyNamedFile` — size-only check before skipping hash verification; called by `Put` and `Link`
- `server/internal/cache/blob/cache.go:209` — `DiskCache.Put` — writes blob content through `checkWriter` with hash verification; sound path
- `server/internal/cache/blob/cache.go:220` — `DiskCache.Import` — computes digest from content then renames temp file; no pre-verification

## Trust Boundary Crossings

1. **HTTP boundary -> blob storage**: `CreateBlobHandler` (routes.go:1500) reads `c.Request.Body` directly into `manifest.NewLayer()` which writes to disk. The digest from the URL param is compared after writing. An attacker controls 100% of the file content.

2. **Blob storage -> GGUF parser**: `ggufLayers` (create.go:658) opens a blob file and passes it directly to `ggml.Decode(blob, -1)`. The blob was written by an attacker via CreateBlobHandler. No re-verification of content at parse time.

3. **Registry -> blob storage (cache hit skip)**: `downloadBlob` (download.go:468-491) trusts `os.Stat` success as proof of blob validity. An attacker who replaces a cached blob (via local write, symlink, or a separate vulnerability) causes the poisoned content to be loaded without any hash check.

4. **Size-only check boundary**: `copyNamedFile` (cache.go:457-465) skips the entire hash-verification path when `info.Size() == size`. An attacker who replaces a blob with a same-size but different-content file bypasses integrity entirely.

5. **Filesystem -> model runner**: `parseFromModel` (model.go:53-66) opens blob via `BlobsPath` and passes to `ggml.Decode`. At no point between the cache-hit skip in `downloadBlob` and the `ggml.Decode` call is the digest re-verified.

6. **Local user -> blob directory**: `DiskCache.Open` (cache.go:79-85) creates directories with mode `0o777`. Any local user on a multi-user system can write to the blob directory.

## Auth / AuthZ Decision Points

- `server/routes.go:1696` — `/api/blobs/:digest` route — NO authentication required. The route is registered without any auth middleware.
- `server/routes.go:1695` — `/api/create` route — NO authentication required in default configuration (CVE-2025-63389 documents missing auth on model management endpoints).
- `manifest/paths.go:40-47` — `BlobsPath` — validates digest format only (regex sha256:[0-9a-fA-F]{64}); no auth check.
- `server/download.go:478-491` — `downloadBlob` cache hit — skips `verifyBlob`; the only integrity gate is bypassed here.
- `server/images.go:639-642` — `verifyBlob` skip loop — `if skipVerify[layer.Digest] { continue }` — this is the auth/integrity bypass implemented in code.

## Validation / Sanitization Functions

- `manifest/paths.go:40-47` — `BlobsPath` — regex `^sha256[:-][0-9a-fA-F]{64}$`; validates digest format before path construction; SOUND for path traversal.
- `server/internal/cache/blob/digest.go` — `ParseDigest` — typed digest with binary storage; SOUND for path traversal.
- `server/internal/cache/blob/cache.go:427-453` — `checkWriter.Write` — verifies SHA-256 on final write in `Put` path; SOUND but only exercised on NEW blobs, not cache hits.
- `fs/ggml/gguf.go:258-262` — tensor bounds check — verifies `tensorEnd <= fileSize`; added as a CVE fix. Active but does not prevent all parser exploitation.
- `server/create.go:673-682` — `detectContentType` — reads first 512 bytes to confirm GGUF magic before calling `Decode`; prevents trivially non-GGUF files.
- `fs/ggml/gguf.go:416-421` — `newArray` — allocates only if `size <= maxSize`; when `maxArraySize == -1` (all arrays collected), there is NO upper bound on allocation.

## Layer Trust Chain

| From Layer | To Layer | Trust Assumption | Holds for ALL paths? | Alternate Paths that Skip This Layer? |
|---|---|---|:---:|---|
| HTTP Client (attacker) | `CreateBlobHandler` | Caller-provided digest matches content | NO | Digest checked AFTER write; attacker controls file content entirely |
| `CreateBlobHandler` | Blob on disk | File content was hash-verified before write | YES (manifest.NewLayer hashes) | Cache hit path in downloadBlob skips all verification |
| Blob on disk | `ggml.Decode` | File content matches the declared digest | NO | Cache hit in downloadBlob skips verifyBlob; size-only check in copyNamedFile skips hash |
| `downloadBlob` | `verifyBlob` | Always called for all blobs | NO | `skipVerify[layer.Digest] = cacheHit` — verification skipped on cache hit |
| `ggml.Decode` | KV/tensor parsing | Input is a structurally valid GGUF file | NO | No structural limit on numKV or numTensor counts; maxArraySize=-1 in ggufLayers |
| Blob directory (disk) | Model runner | Only authorized content is on disk | NO | Directory mode 0o777 allows any local user to replace blobs |
| `copyNamedFile` | Blob store | Size match implies content integrity | NO | Explicit TODO acknowledges size-only is insufficient; attacker can replace with same-size malicious blob |

## Trust Chain Gaps (priority targets for generators)

**GAP-1: Attacker-controlled GGUF bypasses no bounds on numKV/numTensor**
- `fs/ggml/gguf.go:143` — `for i := 0; uint64(i) < llm.numKV(); i++` — numKV is read directly from the file header (uint64); maximum not capped. A crafted file claiming billions of KV pairs causes an unbounded allocation/read loop. The only guard is `maxArraySize` which controls *element storage* within arrays, not the number of KV iterations. With `maxArraySize=-1` (used in ggufLayers), ALL array elements are allocated.

**GAP-2: Cache hit skips verifyBlob — integrity bypass via stat-only check**
- `server/download.go:478-491` — `os.Stat` success returns `cacheHit=true`; `images.go:640-641` skips `verifyBlob`. An attacker who can write to the blobs directory (mode 0o777 in new cache, CVE documented) can swap a blob. On next pull the poisoned blob is loaded into `ggml.Decode` without any hash check.

**GAP-3: Size-only integrity in copyNamedFile**
- `server/internal/cache/blob/cache.go:459` — `info.Size() == size` is the sole integrity check. Any blob replacement with a same-size malicious file bypasses hash verification in the DiskCache path.

**GAP-4: TOCTOU between stat and model load**
- `downloadBlob` stat at line 478 → `verifyBlob` skipped → manifest written → later `ggml.Decode` at model load time. Window for file replacement between stat and load.

**GAP-5: No symlink protection in blob path resolution**
- `manifest/paths.go:50` — `filepath.Join(envconfig.Models(), "blobs", digest)` uses `os.Stat` not `os.Lstat`. A symlink in the blobs directory is followed transparently, redirecting a cache hit to attacker-controlled content.

**GAP-6: intermediateBlobs map is not thread-safe and not persistent**
- `server/model.go:20` — `intermediateBlobs` is a plain `map[string]string` accessed in the HTTP handler goroutine; concurrent POST requests to `/api/blobs/:digest` could race on map operations (read in line 1501, delete in line 1510, no mutex).

**GAP-7: maxArraySize=-1 in ggufLayers triggers unbounded heap allocation**
- `server/create.go:684` — `ggml.Decode(blob, -1)` collects all arrays; `readGGUFArray` at gguf.go:424 creates `newArray[T](int(n), -1)` where n is attacker-controlled uint64 cast to int. On 64-bit systems int is 64-bit, so `make([]T, n)` can be called with an arbitrarily large n.

**GAP-8: Unsigned integer cast in readGGUFString allows large alloc**
- `fs/ggml/gguf.go:359-361` — `length := int(llm.ByteOrder.Uint64(buf))` — a value near MaxUint64 wraps to a large positive int on 64-bit (no wrap) or a negative int on 32-bit, then `make([]byte, length)` is called. No upper bound check on string length before allocation.
