# Round 1 Hypotheses: Backward-Reasoner-03 (Pre-Mortem / Abductive)

## Reasoning Approach
Working backward from catastrophic outcomes: crash, OOM, code execution, integrity bypass. For each, trace which preconditions are necessary and whether the code satisfies those preconditions today.

---

## PH-01: OOM via unbounded array allocation in GGUF KV section

**Outcome**: Server OOM / process crash (DoS)
**Target**: `fs/ggml/gguf.go:437` — `newArray[uint8](int(n), llm.maxArraySize)` within `readGGUFArray`
**Attack input**: Crafted GGUF file with a KV entry of type `ggufTypeArray` where the array element count `n` is set to e.g. 0x00000000FFFFFFF0 (4GB worth of uint8), uploaded via POST /api/blobs/:digest then referenced in POST /api/create

**Preconditions needed**:
1. Attacker can upload arbitrary bytes as a blob — YES (CreateBlobHandler accepts any body)
2. The blob passes content-type check — YES if GGUF magic bytes (0x47 0x47 0x55 0x46) are present
3. `ggml.Decode` is called with maxArraySize=-1 — YES in ggufLayers (create.go:684)
4. `newArray` allocates when maxArraySize < 0 — YES: `if maxSize < 0 || size <= maxSize` → `make([]T, size)`
5. `int(n)` on 64-bit where n = 0x00000000FFFFFFF0 → 4294967280 → `make([]byte, 4294967280)` — 4GB allocation triggered

**Code path**: `POST /api/blobs/:digest` → `manifest.NewLayer` (writes blob) → `POST /api/create` → `convertModelFromFiles` → `ggufLayers` → `ggml.Decode(blob, -1)` → `containerGGUF.Decode` → `readGGUFArray` → `newArray[uint8](4294967280, -1)` → `make([]byte, 4294967280)`

**Sanitizers on path**: None that limit array element count. The tensor bounds check (gguf.go:258-262) only applies to tensor data, not KV arrays.

**Security consequence**: Remote DoS — single unauthenticated HTTP request can exhaust server memory
**Severity estimate**: HIGH
**Validation status**: VALIDATED — all preconditions met by code inspection
**CVE lineage**: Extends CVE-2025-0315 (unlimited memory allocation), CVE-2025-66960 (unchecked string-length)

---

## PH-02: Panic via negative int conversion in readGGUFString allocation

**Outcome**: Server panic (nil pointer / invalid argument to make)
**Target**: `fs/ggml/gguf.go:361` — `buf = make([]byte, length)` where `length := int(llm.ByteOrder.Uint64(buf))`
**Attack input**: Crafted GGUF blob where a string length field is set to 0x8000000000000000 (2^63) — when interpreted as int on 64-bit, this is MinInt64 (-9223372036854775808)

**Preconditions needed**:
1. Attacker controls blob content — YES
2. GGUF magic present — YES
3. String length field at the right offset set to 0x8000000000000000 — YES (attacker controls all bytes)
4. `int(0x8000000000000000)` on 64-bit Go: since uint64 0x8000000000000000 = 9223372036854775808 which exceeds MaxInt64, converted to int gives -9223372036854775808
5. `make([]byte, -9223372036854775808)` — Go runtime panics: "makeslice: len out of range"

**Code path**: Same upload path → `readGGUFString` at gguf.go:348 → `length := int(llm.ByteOrder.Uint64(buf))` → length is negative → `make([]byte, length)` → runtime panic

**Sanitizers on path**: None. The only check is `if length > len(llm.scratch)` which is false for negative values — but then the else branch uses `llm.scratch[:length]` which would panic with "index out of range" if length is negative.

Wait — re-reading: `if length > len(llm.scratch)` where length is negative int: negative < 16384, so the else branch executes: `buf = llm.scratch[:length]` where length is negative → panic: "runtime error: slice bounds out of range"

**Security consequence**: Server crash (panic) — remote DoS via single unauthenticated upload + create request
**Severity estimate**: HIGH
**Validation status**: VALIDATED
**CVE lineage**: CVE-2024-39720 (OOB read from 4-byte malformed GGUF)

---

## PH-03: Integrity bypass via blob replacement after cache-hit stat

**Outcome**: Unverified malicious GGUF loaded into model runner
**Target**: `server/download.go:478-491` — `os.Stat` returns success → `cacheHit=true` → `skipVerify[layer.Digest] = true`
**Attack input**: Local attacker replaces an existing blob file in the models/blobs directory with a crafted GGUF

**Preconditions needed**:
1. Blob directory has mode 0o777 (new DiskCache) or group-writable — YES for new cache (cache.go:79-85)
2. Attacker has filesystem access to blobs directory — YES on multi-user system
3. A valid model manifest exists pointing to the target digest — YES (any previously pulled model)
4. On next `ollama pull`, `os.Stat(fp)` succeeds → cacheHit=true — YES
5. `skipVerify[layer.Digest] = true` → `verifyBlob` not called — YES (images.go:640-641)
6. `ggml.Decode` is called on the replaced file — YES (model load)

**Code path**: `PullModel` → `downloadBlob` → `os.Stat(fp)` succeeds → `cacheHit=true` → `images.go:634` `skipVerify[digest]=true` → `images.go:640-641` skip `verifyBlob` → model load → `ggml.Decode`

**Sanitizers on path**: None between cache hit and model load. `verifyBlob` is the only integrity gate and it is explicitly skipped.

**Security consequence**: Malicious GGUF content fed to the parser without any hash verification. Combined with parser vulnerabilities (PH-01, PH-02), this becomes a local privilege escalation via model poisoning.
**Severity estimate**: HIGH
**Validation status**: VALIDATED

---

## PH-04: Size-only integrity bypass in copyNamedFile enables same-size blob swap

**Outcome**: Malicious blob content accepted as valid by DiskCache
**Target**: `server/internal/cache/blob/cache.go:459` — `if err == nil && info.Size() == size { return nil }`
**Attack input**: Attacker replaces a cached blob with a file of exactly the same size but different (malicious) content

**Preconditions needed**:
1. Attacker can write to the blobs/manifests directory — YES (0o777 permissions)
2. Replacement file has identical size to original — YES (attacker crafts or pads file)
3. `copyNamedFile` is called with the file at the target path — YES when DiskCache.Put/Link is called with existing blob
4. `info.Size() == size` check passes — YES since sizes match
5. `checkWriter` SHA-256 verification is NOT reached — YES, function returns nil at line 465

**Code path**: `DiskCache.Put(d, r, size)` → `copyNamedFile` → `os.Stat(name)` → `info.Size() == size` → `return nil`

**Sanitizers on path**: TODO comment explicitly acknowledges this gap. No hash check is performed.

**Security consequence**: Same as PH-03 but through the DiskCache path. The "newer" blob cache system has the same fundamental weakness as the legacy path.
**Severity estimate**: HIGH
**Validation status**: VALIDATED

---

## PH-05: Symlink substitution for cache hit attack (no Lstat)

**Outcome**: Attacker-controlled content loaded as "verified" cache hit
**Target**: `server/download.go:478` — `fi, err := os.Stat(fp)` follows symlinks
**Attack input**: Attacker creates a symlink at the expected blob path pointing to attacker-controlled GGUF file

**Preconditions needed**:
1. Attacker can create a symlink in the blobs directory — YES (0o777)
2. The target blob has not yet been pulled (no existing regular file) — attacker pre-creates symlink before pull
3. OR attacker replaces existing file with symlink — YES if directory is writable
4. `os.Stat` follows symlinks and returns success — YES
5. `cacheHit=true` returned — YES

**Code path**: Attacker creates symlink `models/blobs/sha256-<digest>` → `/tmp/evil.gguf` → `downloadBlob` → `os.Stat(fp)` succeeds (follows symlink) → `cacheHit=true` → skip verify → model load reads from /tmp/evil.gguf

**Sanitizers on path**: None. No `os.Lstat` call exists anywhere in the blob cache hit path.

**Security consequence**: Attacker-controlled file loaded as model. If combined with GGUF parser vulns (PH-01/PH-02), leads to server crash or worse.
**Severity estimate**: HIGH
**Validation status**: VALIDATED

---

## PH-06: TOCTOU race — blob replaced between stat and model load

**Outcome**: Crafted GGUF loaded despite valid blob existing at time of stat
**Target**: Gap between `downloadBlob` (download.go:478) and `ggml.Decode` (model.go:64 or create.go:684)
**Attack input**: Attacker times a file replacement to occur after `os.Stat` returns success but before the blob is opened for parsing

**Preconditions needed**:
1. Attacker can write to blobs directory — YES (0o777)
2. Time window exists between stat and open — YES; multiple seconds can elapse between PullModel completing and model load
3. No file locking prevents replacement — YES; no flock or O_EXCL is used

**Code path**: `downloadBlob` → `os.Stat` (t0) → `cacheHit=true` → manifest written → user triggers model load → `manifest.BlobsPath` → `os.Open` (t1) → attacker replaced file between t0 and t1

**Sanitizers on path**: None. The stat and open are separated by significant processing time with no lock held.

**Security consequence**: Same as PH-03/PH-05 but exploitable by a concurrent local process rather than persistent file replacement.
**Severity estimate**: MEDIUM (requires timing; local attacker needed)
**Validation status**: VALIDATED

---

## PH-07: Unbounded numKV loop causes CPU exhaustion (algorithmic DoS)

**Outcome**: CPU exhaustion / server hang
**Target**: `fs/ggml/gguf.go:143` — `for i := 0; uint64(i) < llm.numKV(); i++`
**Attack input**: Crafted GGUF where numKV = 0xFFFFFFFFFFFFFFFF (max uint64), but each KV entry is crafted to be a single byte type causing immediate io.EOF

**Preconditions needed**:
1. numKV is read directly from file: `llm.V3.NumKV` is a uint64 from the file — YES
2. The loop count is controlled by attacker — YES
3. Each iteration calls `readGGUFString` → `io.ReadFull` → returns error on EOF — YES
4. Loop terminates on first error — YES: `if err != nil { return err }`

**Assessment**: The loop terminates on first I/O error, so pure loop count is not exploitable unless each iteration succeeds. However, an attacker can set numKV to a value that is realistic given the file size (each KV needing minimum ~10 bytes), causing significant CPU and memory usage. For a 100MB file with minimal KV entries, numKV could be set to ~10M, each consuming 16 bytes from scratch buffer.

**Security consequence**: Moderate CPU exhaustion; bounded by file size. Less severe than PH-01 since file I/O limits iteration.
**Severity estimate**: MEDIUM
**Validation status**: NEEDS-DEEPER (bounded by actual file content but still a concern for large uploads)

---

## PH-08: Concurrent map access race condition in intermediateBlobs

**Outcome**: Server crash via concurrent map write/delete panic
**Target**: `server/model.go:20` — `intermediateBlobs map[string]string` + `server/routes.go:1501,1510`
**Attack input**: Two concurrent POST /api/blobs/:digest requests for different digests

**Preconditions needed**:
1. `intermediateBlobs` is a plain Go map — YES
2. HTTP handlers run in goroutines — YES (gin uses goroutine per request)
3. Concurrent read (line 1501: `if ib, ok := intermediateBlobs[c.Param("digest")]`) and delete (line 1510: `delete(intermediateBlobs, c.Param("digest")]`) cause a race

**Assessment**: Go maps are not safe for concurrent read+write. Two goroutines concurrently accessing the map — even if one is reading and one is deleting different keys — constitutes a data race. Go's race detector would catch this. In production, this can cause a "concurrent map read and map write" panic.

**Security consequence**: Server panic/crash — DoS via two concurrent blob upload requests
**Severity estimate**: MEDIUM
**Validation status**: VALIDATED (structural race; needs runtime confirmation)

---

## PH-09: Large tensor shape product overflow in Tensor.Elements()

**Outcome**: Integer overflow in tensor size calculation leading to incorrect bounds check
**Target**: `fs/ggml/ggml.go:505-511` — `Tensor.Elements()` multiplies shape dimensions
**Attack input**: Crafted GGUF tensor with shape `[0x100000000, 0x100000000]` (4B x 4B)

**Preconditions needed**:
1. Tensor shape values are read as uint64 from file — YES (gguf.go:207-212)
2. `Elements()` multiplies without overflow check: `count *= n` — YES
3. 0x100000000 * 0x100000000 = 0 (overflow to 0 in uint64) — YES
4. `Size() = Elements() * typeSize / blockSize = 0 * ... = 0`
5. `tensorEnd = tensorOffset + offset + 0` which is likely < fileSize — bounds check PASSES
6. Tensor with zero-computed size but declared at large offset passes the bounds check

**Code path**: `readGGUF[uint64](llm, rs)` for shape → `Tensor.Elements()` overflows → `Tensor.Size() = 0` → `tensorEnd <= fileSize` passes → tensor with fraudulent shape accepted

**Security consequence**: Tensor with attacker-controlled shape but zero computed size bypasses bounds check and is stored in tensor list. Downstream consumers of the tensor (the C++ llama.cpp backend) will compute the actual size differently and may OOB read/write tensor data.
**Severity estimate**: HIGH (if llama.cpp backend trusts Go-parsed shape without independent validation)
**Validation status**: NEEDS-DEEPER (depends on whether llama.cpp re-validates shape)
