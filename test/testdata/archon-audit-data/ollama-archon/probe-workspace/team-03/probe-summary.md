# Deep Probe Summary: Team-03 (DFD-4 + CFD-3)

Status: complete
Loops: 1
Total hypotheses: 19 (9 round-1, 8 round-2, 6 round-3; counting unique PH IDs)
Validated: 16
Needs-Deeper: 3 (PH-07, PH-R3-06; PH-14/PH-15 invalidated)
Stop reason: all entry points covered; no fragile items requiring re-investigation; one downstream NEEDS-DEEPER for Phase 8

---

## Validated Hypotheses

### PH-02 / PH-R3-02: 32-byte GGUF File Causes Immediate Server Panic
- Reasoning-Model: Backward-Reasoner + Causal-Verifier
- Target: `fs/ggml/gguf.go:359-364` — `readGGUFString`
- Attack input: 32-byte crafted GGUF where the first KV key-length field is set to 0x8000000000000000 (high bit set), followed by POST /api/create referencing that blob's digest
- Code path: `POST /api/blobs/:digest` -> `manifest.NewLayer` (writes blob to disk) -> `POST /api/create` with digest -> `ggufLayers` -> `ggml.Decode(blob, -1)` -> `containerGGUF.Decode` -> KV loop -> `readGGUFString` at gguf.go:348 -> `length := int(llm.ByteOrder.Uint64(buf))` -> length = MinInt64 -> `buf = llm.scratch[:MinInt64]` at line 363 -> runtime panic "slice bounds out of range"
- Sanitizers on path: None. No upper-bound or sign check on the length field.
- Security consequence: Process crash (panic) — remote unauthenticated DoS
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-01 / PH-R3-01: OOM via Unbounded Array Allocation (maxArraySize=-1)
- Reasoning-Model: Backward-Reasoner + Causal-Verifier
- Target: `fs/ggml/gguf.go:437` — `newArray[uint8](int(n), llm.maxArraySize)` within `readGGUFArray`
- Attack input: Crafted GGUF with KV entry type=ggufTypeArray, element_type=ggufTypeUint8, n=0x40000000; actual array data (1GB) provided in file body
- Code path: `POST /api/blobs/:digest` -> blob stored -> `POST /api/create` -> `convertModelFromFiles` -> `ggufLayers` -> `ggml.Decode(blob, -1)` at create.go:684 -> `readGGUFArray` -> `newArray[uint8](1073741824, -1)` -> `make([]byte, 1073741824)` -> 1GB heap allocation
- Sanitizers on path: None. `newArray` with maxArraySize=-1 allocates for any size. No upload body limit in `CreateBlobHandler`.
- Security consequence: Remote DoS via memory exhaustion. Note: requires uploading actual array data (up to disk quota); no upload size limit amplifies the attack.
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-R3-04: general.alignment=0 Triggers Divide-By-Zero in ggufPadding
- Reasoning-Model: Causal-Verifier (new finding during causal analysis)
- Target: `fs/ggml/gguf.go:238,245` — `alignment := llm.kv.Uint("general.alignment", 32)` + `ggufPadding(offset, int64(alignment))`
- Attack input: GGUF file with KV entry `general.alignment` set to 0 (uint32)
- Code path: `ggml.Decode` -> `containerGGUF.Decode` -> KV loop processes `general.alignment=0` -> `alignment = 0` at line 238 -> `ggufPadding(offset, 0)` at line 245 -> `offset % 0` -> panic: integer divide by zero
- Sanitizers on path: None. `kv.Uint` returns 0 when key is explicitly 0. No `max(alignment, 1)` guard exists.
- Security consequence: Server panic (crash) — remote unauthenticated DoS. Minimal file size.
- Severity estimate: HIGH
- CVE lineage: Same class as CVE-2025-0317 (divide-by-zero via block_count=0)
- Evidence file: round-1-evidence.md

### PH-09 / PH-16 / PH-R3-03: Tensor Bounds Check Bypass via Shape Product Overflow and Unknown Kind
- Reasoning-Model: Backward-Reasoner + Contradiction-Reasoner + Causal-Verifier
- Target: `fs/ggml/ggml.go:505-515` — `Tensor.Elements()` and `Tensor.Size()` + `fs/ggml/gguf.go:258-262` — tensor bounds check
- Attack input A (shape overflow): GGUF tensor with shape=[0x8000000000000000, 1], Kind=TensorTypeF32 — Elements overflows uint64: 0x8000000000000000 × 4 = 0 for Size (F32 typeSize=4, blockSize=1; 0x8000000000000000 * 4 overflows to 0x0000000000000000) -> Size()=0 -> bounds check passes
- Attack input B (unknown Kind): GGUF tensor with Kind=0xFFFFFFFF — TypeSize()=0 (default case), BlockSize()=256 (default case), Size()=0 -> bounds check passes trivially
- Code path: `ggufLayers` -> `ggml.Decode` -> `containerGGUF.Decode` -> tensor loop -> `readGGUF[uint32](llm, rs)` for Kind -> `readGGUF[uint64](llm, rs)` for Shape -> stored in Tensor struct -> `tensorEnd = llm.tensorOffset + tensor.Offset + tensor.Size()` at line 259 -> Size()=0 -> passes file size check -> tensor stored in `llm.tensors`
- Sanitizers on path: None. The bounds check added as a CVE fix is defeated by the overflow/unknown-Kind cases. No shape product overflow check. No unknown-Kind rejection.
- Security consequence: Tensor with fraudulent shape/type accepted. Downstream llama.cpp backend receives malformed tensor metadata — behavior undefined (potential OOB access). Full impact requires Phase 8 investigation of runner/ package.
- Severity estimate: HIGH (bounds check bypass confirmed); downstream severity CRITICAL if llama.cpp trusts Go-parsed shapes
- Evidence file: round-1-evidence.md

### PH-03 / PH-10: Blob Integrity Bypass on Cache Hit (verifyBlob Skip)
- Reasoning-Model: Backward-Reasoner + Contradiction-Reasoner
- Target: `server/download.go:478-491` — `downloadBlob` stat-only check + `server/images.go:634,640-641` — skipVerify pattern
- Attack input: Local attacker (with write access to blobs directory) replaces a cached blob file; legitimate user runs `ollama pull <model>`
- Code path: `PullModel` -> `downloadBlob` -> `os.Stat(fp)` succeeds -> `return true, nil` (cacheHit=true) -> `skipVerify[layer.Digest] = true` -> `if skipVerify[layer.Digest] { continue }` -> verifyBlob NOT called -> manifest written -> model loaded with unverified content
- Sanitizers on path: None between stat and model load. `verifyBlob` is the only content integrity check and it is explicitly skipped. The UI message "verifying sha256 digest" is displayed regardless.
- Security consequence: Locally-poisoned blobs are loaded without any integrity verification. Enables delivery of PH-01/PH-02/PH-R3-04 payloads to a victim's model runner.
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-04: Size-Only Integrity in DiskCache.copyNamedFile
- Reasoning-Model: Backward-Reasoner
- Target: `server/internal/cache/blob/cache.go:459` — `if err == nil && info.Size() == size { return nil }`
- Attack input: Replace cached blob with same-size malicious file; trigger DiskCache.Put/Link
- Code path: `DiskCache.Put(d, r, size)` -> `copyNamedFile(targetPath, reader, digest, size)` -> `os.Stat(name)` -> `info.Size() == size` -> `return nil` (checkWriter never created)
- Sanitizers on path: The `checkWriter` SHA-256 verification at line 489 is only reached for new or size-changed files. A TODO comment explicitly acknowledges this gap.
- Security consequence: Same-size blob replacement bypasses hash verification in the newer DiskCache code path. Parallel to PH-03.
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-05: No Symlink Protection in Blob Path (os.Stat follows symlinks)
- Reasoning-Model: Backward-Reasoner
- Target: `server/download.go:478` — `os.Stat(fp)` + `manifest/layer.go:106` — `os.Open(blob)`
- Attack input: Create symlink at expected blob path (in 0o777 blobs directory) pointing to attacker-controlled GGUF file
- Code path: Attacker creates symlink `models/blobs/sha256-<digest>` -> `downloadBlob` -> `os.Stat` follows symlink -> success -> `cacheHit=true` -> skip verify -> model load -> `os.Open(blob)` follows symlink -> `ggml.Decode` reads attacker's file
- Sanitizers on path: None. No `os.Lstat` call at any point in the cache hit path. No O_NOFOLLOW on file opens.
- Security consequence: Attacker directs model loading to arbitrary file content without needing to write into the blobs directory directly. Delivery mechanism for PH-01/PH-02 payloads.
- Severity estimate: HIGH
- Evidence file: round-1-evidence.md

### PH-17: 0o777 Blob Directory Permissions (Prerequisite Amplifier)
- Reasoning-Model: Contradiction-Reasoner
- Target: `server/internal/cache/blob/cache.go:79,85` — `os.MkdirAll(dir, 0o777)`
- Attack input: Local user on multi-user system with umask=0 (Docker containers) accesses the world-writable blob directory
- Code path: `DiskCache.Open(dir)` -> `os.MkdirAll(dir, 0o777)` -> actual permissions 0o777 (if umask=0) -> any local user can write
- Sanitizers on path: umask provides partial mitigation in default Linux/macOS configurations (umask=022 → actual 0o755). In container environments with umask=0, full 0o777 applies.
- Security consequence: Enables PH-03, PH-04, PH-05 attacks by any local user. Inconsistent with `manifest/paths.go:56` which uses 0o755 explicitly.
- Severity estimate: HIGH (in container environments); MEDIUM in default desktop environments
- Evidence file: round-1-evidence.md

### PH-08 / PH-13: Data Race on intermediateBlobs Map
- Reasoning-Model: Backward-Reasoner + Contradiction-Reasoner
- Target: `server/model.go:20` — `var intermediateBlobs map[string]string` + `server/routes.go:1501,1510`
- Attack input: Two concurrent POST /api/blobs/:digest HTTP requests
- Code path: Goroutine-1 reads `intermediateBlobs[digest]` (line 1501) concurrently with Goroutine-2 deletes `delete(intermediateBlobs, digest)` (line 1510) -> Go runtime panic "concurrent map read and map write"
- Sanitizers on path: None. No mutex, no sync.Map, no channel-based access.
- Security consequence: DoS via concurrent blob upload requests. Go race detector would catch this. In production without race detector, behavior is undefined.
- Severity estimate: MEDIUM
- Evidence file: round-1-evidence.md

### PH-12: Memory Amplification via KV Map Growth
- Reasoning-Model: Contradiction-Reasoner
- Target: `fs/ggml/gguf.go:143,190` — KV loop + `llm.kv[k] = v`
- Attack input: GGUF with numKV=1,000,000, each KV being a minimal uint32 (cheap to include)
- Code path: 1M iterations of readGGUFString + type read + value read + `llm.kv[k] = v` -> 1M Go map entries -> ~100MB map overhead from a 24MB file (8-byte keys × 1M + map bucket overhead)
- Sanitizers on path: None. numKV is uncapped. Map growth is unbounded.
- Security consequence: Memory amplification DoS — Go map overhead amplifies small file into large memory footprint
- Severity estimate: MEDIUM-HIGH
- Evidence file: round-1-evidence.md

### PH-R3-05: No Upload Body Size Limit in CreateBlobHandler
- Reasoning-Model: Causal-Verifier
- Target: `server/routes.go:1538` — `manifest.NewLayer(c.Request.Body, "")`
- Attack input: Upload a blob of arbitrary size (e.g., filling disk)
- Code path: `CreateBlobHandler` -> `manifest.NewLayer(c.Request.Body, "")` -> `io.Copy(io.MultiWriter(temp, sha256sum), r)` -> reads entire body to disk with no limit
- Sanitizers on path: None. No `http.MaxBytesReader`. No Content-Length check before writing.
- Security consequence: Disk exhaustion. Also amplifies PH-01 (attacker must provide actual array data but there is no size limit preventing them from doing so).
- Severity estimate: MEDIUM-HIGH
- Evidence file: round-1-evidence.md

---

## NEEDS-DEEPER

### PH-07: CPU Exhaustion via Large numKV Loop Count
- Why unresolved: The KV iteration loop terminates on first I/O error (io.ReadFull returns error on EOF). The loop count is bounded by actual file content. Pure loop-count abuse is not viable without providing actual bytes. The memory amplification aspect is captured by PH-12.
- Suggested follow-up: Assess whether a specially crafted stream that never EOF-terminates (e.g., a slow-loris style upload) can keep the loop running indefinitely.

### PH-R3-06: llama.cpp Downstream Trust of Go-Parsed Tensor Metadata
- Why unresolved: The runner/ and llm/ packages were not reviewed. It is unknown whether llama.cpp independently re-parses the GGUF file (making the Go parser's acceptance irrelevant) or trusts the Go-parsed tensor Shape/Kind metadata for memory addressing.
- Suggested follow-up: Phase 8 should review `runner/` package — specifically how `Tensor.Shape` and `Tensor.Kind` from Go's GGML package are passed to the C++ inference backend. If shapes are passed through directly, PH-09/PH-R3-03 escalate to CRITICAL.

### PH-06: TOCTOU Between Blob Stat and Model Load
- Why unresolved: Timing window is confirmed structurally but practical exploitability depends on whether the window is wide enough for reliable exploitation. In automated pipelines (pull → immediate run), the window may be very short.
- Suggested follow-up: Measure actual elapsed time between downloadBlob stat and ggml.Decode call in a production setup. If > 1 second, the race is reliably exploitable by a local attacker.

---

## Coverage Summary

| Entry Point | backward-reasoner | contradiction-reasoner | causal-verifier |
|---|:---:|:---:|:---:|
| `CreateBlobHandler` POST /api/blobs/:digest | PH-02, PH-05, PH-08 | PH-13 | PH-R3-02, PH-R3-05 |
| `CreateHandler` + `ggufLayers` (POST /api/create) | PH-01, PH-02, PH-09 | PH-12, PH-16 | PH-R3-01, PH-R3-03, PH-R3-04 |
| `downloadBlob` cache hit skip | PH-03, PH-05, PH-06 | PH-10, PH-11 | NONE (covered) |
| `DiskCache.copyNamedFile` | PH-04 | PH-15 (invalidated) | PH-R3-01 |
| `DiskCache.Open` 0o777 permissions | PH-03 (amplifier) | PH-17 | NONE |
| `ggml.Decode` → `readGGUFString` | PH-02 | NONE | PH-R3-02 |
| `ggml.Decode` → `readGGUFArray` | PH-01 | PH-12 | PH-R3-01 |
| `ggml.Decode` → ggufPadding | PH-07 (partial) | NONE | PH-R3-04 |
| Tensor bounds check | PH-09 | PH-16 | PH-R3-03 |
| intermediateBlobs map | PH-08 | PH-13 | NONE |
| Symlink / Lstat gap | PH-05 | NONE | NONE (structural) |
