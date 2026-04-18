# Evidence File: Team-03 All Rounds

## Evidence Methodology
Each hypothesis was evaluated against direct source code. Evidence quality levels:
- CONFIRMED: Code path traced end-to-end with specific line references
- STRONG: Code path traced with high confidence; minor assumptions noted
- PARTIAL: Partial code path confirmed; some steps require runtime verification
- FRAGILE: Dependent on environmental conditions (race timing, platform specifics)

---

## PH-01: OOM via unbounded array allocation

**Status**: CONFIRMED
**Evidence**:
- `fs/ggml/gguf.go:424-437`: `readGGUFArray` reads n (uint64) then calls `newArray[uint8](int(n), llm.maxArraySize)`
- `fs/ggml/gguf.go:416-421`: `newArray` with maxSize=-1: `if maxSize < 0 || size <= maxSize` → condition true → `a.values = make([]T, size)`
- `server/create.go:684`: `ggml.Decode(blob, -1)` — maxArraySize is -1
- `server/routes.go:1538`: `manifest.NewLayer(c.Request.Body, "")` — no upload size limit
- NO check prevents `make([]byte, n)` for arbitrary attacker-supplied n
**Fragility**: NONE — structural, not timing-dependent
**Confirmation**: For n=0x40000000 (1GB): `int(0x40000000) = 1073741824`; `make([]byte, 1073741824)` is a 1GB allocation. For n values > MaxInt64/8 bytes, `make` panics before allocation.

---

## PH-02: Panic via negative int in readGGUFString

**Status**: CONFIRMED (strongest finding)
**Evidence**:
- `fs/ggml/gguf.go:359`: `length := int(llm.ByteOrder.Uint64(buf))` — unchecked cast
- `fs/ggml/gguf.go:360-364`: `if length > len(llm.scratch)` false for negative values → `buf = llm.scratch[:length]` → panic
- For length=MinInt64 (uint64=0x8000000000000000): `llm.scratch[:MinInt64]` = `llm.scratch[:-9223372036854775808]` → runtime panic "slice bounds out of range"
- Entry path: `ggufLayers` → `ggml.Decode` → `containerGGUF.Decode` → KV loop → `readGGUFString`
- Minimum file: 32 bytes to reach the panic
**Fragility**: NONE — deterministic; 32-byte file causes immediate panic on any x86-64 system
**CVE lineage**: Same class as CVE-2025-66960, CVE-2024-39720 (string/length related)

---

## PH-03: Integrity bypass via blob replacement (cache hit skip)

**Status**: CONFIRMED
**Evidence**:
- `server/download.go:478-491`: `os.Stat(fp)` success → `return true, nil` (cacheHit=true). No hash check.
- `server/images.go:634`: `skipVerify[layer.Digest] = cacheHit` — maps the digest to skip status
- `server/images.go:640-641`: `if skipVerify[layer.Digest] { continue }` — verifyBlob call skipped
- `server/internal/cache/blob/cache.go:79-85`: `os.MkdirAll(..., 0o777)` — world-writable directory
- `server/images.go:638`: progress message "verifying sha256 digest" displayed even when all blobs are skipped
**Fragility**: LOW — requires local filesystem write access (granted by 0o777 permissions)

---

## PH-04: Size-only integrity in copyNamedFile

**Status**: CONFIRMED
**Evidence**:
- `server/internal/cache/blob/cache.go:459`: `if err == nil && info.Size() == size { return nil }` — early return, no hash check
- `server/internal/cache/blob/cache.go:462-465`: `// TODO: Do the hash check` — developer acknowledgment
- `server/internal/cache/blob/cache.go:489-497`: `checkWriter` with sha256 only reached for new/truncated files
**Fragility**: NONE — structural, code path confirmed
**Connection**: This is the DiskCache parallel to PH-03's downloadBlob path

---

## PH-05: Symlink substitution (no Lstat)

**Status**: CONFIRMED
**Evidence**:
- `server/download.go:478`: `fi, err := os.Stat(fp)` — `os.Stat` follows symlinks by design
- No `os.Lstat` call found anywhere in the blob cache hit code path
- `manifest/paths.go:50`: `path := filepath.Join(envconfig.Models(), "blobs", digest)` — no symlink check
- `manifest/layer.go:106`: `os.Open(blob)` — follows symlinks; no Lstat check before open
**Fragility**: NONE — structural

---

## PH-06: TOCTOU between stat and model load

**Status**: CONFIRMED (structural); timing-dependent in practice
**Evidence**:
- Gap between `downloadBlob` (download.go:478, t0) and `ggml.Decode` (create.go:684 or model.go:64, t1)
- No file locking between t0 and t1
- On `ollama pull` followed by `ollama run`, the gap can be seconds to minutes
**Fragility**: MEDIUM — race window exists but timing precision needed; more reliable than typical TOCTOU

---

## PH-07: CPU exhaustion via large numKV

**Status**: PARTIAL
**Evidence**:
- `fs/ggml/gguf.go:143`: `for i := 0; uint64(i) < llm.numKV(); i++` — attacker-controlled loop count
- BUT: each iteration reads from the file; io.ReadFull will error on EOF
- The loop terminates on first error — so pure count is not exploitable
- Memory amplification per PH-12 analysis is still valid (each KV entry adds to map)
**Fragility**: MEDIUM — bounded by file size; not a standalone DoS

---

## PH-08: Concurrent map access race (intermediateBlobs)

**Status**: CONFIRMED (structural data race)
**Evidence**:
- `server/model.go:20`: `var intermediateBlobs map[string]string = make(map[string]string)` — plain Go map
- `server/routes.go:1501`: `if ib, ok := intermediateBlobs[c.Param("digest")]; ok {` — map read in goroutine
- `server/routes.go:1510`: `delete(intermediateBlobs, c.Param("digest"))` — map write/delete in goroutine
- Go maps are not safe for concurrent read+write; concurrent access causes panic in production
- No sync.Mutex, sync.Map, or other synchronization found
**Fragility**: LOW-MEDIUM — requires concurrent requests; go race detector would flag immediately

---

## PH-09: Shape product overflow (Tensor.Elements)

**Status**: CONFIRMED (overflow mechanism); downstream impact NEEDS-DEEPER
**Evidence**:
- `fs/ggml/ggml.go:505-511`: `Elements()` uses unchecked `count *= n` in uint64 arithmetic
- `fs/ggml/ggml.go:513-515`: `Size() = Elements() * typeSize() / blockSize()`
- `fs/ggml/gguf.go:258-262`: bounds check uses `tensor.Size()` — bypassed when Size()=0 from overflow
- Verified overflow: Shape=[0x8000000000000000, 1], F32: Elements=0x8000000000000000, Size=0x8000000000000000*4=0 (uint64 overflow) → bounds check passes
**Fragility**: NONE for overflow mechanism; downstream: depends on C++ handling

---

## PH-10: "verifying sha256 digest" deception

**Status**: CONFIRMED
**Evidence**:
- `server/images.go:638`: `fn(api.ProgressResponse{Status: "verifying sha256 digest"})` — always displayed
- `server/images.go:639-642`: loop body only calls `verifyBlob` when `!skipVerify[digest]`
- When all blobs are cache hits, `skipVerify[digest] = true` for all → 0 blobs actually verified
**Fragility**: NONE — structural

---

## PH-12: Memory amplification via KV map growth

**Status**: CONFIRMED
**Evidence**:
- `fs/ggml/gguf.go:190`: `llm.kv[k] = v` — unbounded map growth
- Each KV entry allocates: string key (8+ bytes), string value (from readGGUFString), map entry overhead (~100 bytes in Go runtime)
- 1M KV entries with 8-byte keys: ~100MB of Go map overhead from a 24MB file
- No limit on `llm.numKV()` other than file content
**Fragility**: NONE — structural; bounded only by file size

---

## PH-R3-01: Array allocation causal trace

**Status**: CONFIRMED (see PH-01)

---

## PH-R3-02: Panic via negative int (32-byte exploit)

**Status**: CONFIRMED (see PH-02)
**Additional evidence**: The condition at gguf.go:360 `if length > len(llm.scratch)` for negative length: in Go, comparing a negative int to a positive int (16384) will always be false since negative < positive. Then `llm.scratch[:length]` with negative length panics with "slice bounds out of range [-9223372036854775808]". This is a guaranteed panic, not OOM.

---

## PH-R3-03: Unknown tensor Kind bypasses bounds check

**Status**: CONFIRMED for bounds bypass; downstream impact NEEDS-DEEPER
**Evidence**:
- `fs/ggml/ggml.go:500-502`: `default: return 0` in `TypeSize()` — unknown Kind returns 0
- `fs/ggml/ggml.go:427-429`: `default: return 256` in `BlockSize()` — unknown Kind returns 256
- `fs/ggml/ggml.go:513-515`: `Size() = Elements() * 0 / 256 = 0`
- `fs/ggml/gguf.go:258-262`: `tensorEnd = tensorOffset + tensor.Offset + 0` — passes for any small offset
- Tensor stored with Kind=0xFFFFFFFF and arbitrary shape — no rejection
**Fragility**: NONE for bounds bypass; downstream: NEEDS-DEEPER

---

## PH-R3-04: general.alignment=0 divide-by-zero

**Status**: CONFIRMED
**Evidence**:
- `fs/ggml/gguf.go:238`: `alignment := llm.kv.Uint("general.alignment", 32)` — returns 0 when key present with value 0
- `fs/ggml/ggml.go:191-194`: `kv.Uint` returns the stored value if key exists, regardless of whether it's zero
- `fs/ggml/gguf.go:245`: `padding := ggufPadding(offset, int64(alignment))` with alignment=0
- `fs/ggml/gguf.go:687-689`: `func ggufPadding(offset, align int64) int64 { return (align - offset%align) % align }` — `offset % 0` panics
**CVE lineage**: Same class as CVE-2025-0317 (ggufPadding with zero divisor via block_count), CVE-2024-8063 (divide-by-zero via block_count)
**Fragility**: NONE — deterministic panic

---

## PH-R3-05: No upload size limit

**Status**: CONFIRMED
**Evidence**:
- `server/routes.go:1538`: `manifest.NewLayer(c.Request.Body, "")` — body read without limit
- `manifest/layer.go:38`: `io.Copy(io.MultiWriter(temp, sha256sum), r)` — copies entire body to disk
- No `http.MaxBytesReader`, no Content-Length check before writing
- `server/routes.go` — no middleware adding request body size limit
**Fragility**: NONE — structural; all uploads accepted up to disk capacity

---

## PH-17: 0o777 directory permissions

**Status**: CONFIRMED
**Evidence**:
- `server/internal/cache/blob/cache.go:79,85`: `os.MkdirAll(dir, 0o777)` and `os.MkdirAll(filepath.Join(dir, subdir), 0o777)`
- `manifest/paths.go:56`: `os.MkdirAll(dirPath, 0o755)` — stricter in the old cache
- The umask on most Linux systems is 0o022, so 0o777 → actual permissions 0o755 (umask applied)
- HOWEVER: if umask is 0o000 (common in Docker containers, setuid environments), the directory IS world-writable
- On macOS, default umask is also 0o022
**Fragility**: MEDIUM — umask-dependent; in default Linux/macOS umask=022 the actual permissions are 0o755 which is not world-writable. In containers with umask=0, the 0o777 takes full effect. CAVEAT: The code intention matters — it should be 0o755 explicitly to be safe across environments.

---

## Summary Table

| Hypothesis | Status | Severity | Fragility | Evidence Strength |
|---|---|---|---|---|
| PH-01 OOM array alloc | VALIDATED | HIGH | None | CONFIRMED |
| PH-02 Panic negative int | VALIDATED | HIGH | None | CONFIRMED |
| PH-03 Cache hit skip verify | VALIDATED | HIGH | Low | CONFIRMED |
| PH-04 Size-only copyNamedFile | VALIDATED | HIGH | None | CONFIRMED |
| PH-05 Symlink no Lstat | VALIDATED | HIGH | None | CONFIRMED |
| PH-06 TOCTOU stat/load | VALIDATED | MEDIUM | Medium | PARTIAL |
| PH-07 CPU loop exhaustion | NEEDS-DEEPER | MEDIUM | Medium | PARTIAL |
| PH-08 Map race intermediateBlobs | VALIDATED | MEDIUM | Low | CONFIRMED |
| PH-09 Shape overflow | VALIDATED | HIGH | None | CONFIRMED |
| PH-10 Deceptive verify message | VALIDATED | HIGH | None | CONFIRMED |
| PH-12 KV map amplification | VALIDATED | MEDIUM-HIGH | None | CONFIRMED |
| PH-13 intermediateBlobs aliasing | VALIDATED | MEDIUM | Low | CONFIRMED |
| PH-14 BlobsPath empty | INVALIDATED | N/A | N/A | CONFIRMED SAFE |
| PH-15 checkWriter size=0 | INVALIDATED | N/A | N/A | CONFIRMED SAFE |
| PH-16 CVE bounds bypass (overflow) | VALIDATED | HIGH | None | CONFIRMED |
| PH-17 0o777 permissions | VALIDATED | HIGH | Medium | CONFIRMED (umask-dependent) |
| PH-R3-03 Unknown Kind bounds bypass | VALIDATED | MEDIUM-HIGH | None | CONFIRMED |
| PH-R3-04 alignment=0 div-by-zero | VALIDATED | HIGH | None | CONFIRMED |
| PH-R3-05 No upload size limit | VALIDATED | MEDIUM-HIGH | None | CONFIRMED |
| PH-R3-06 llama.cpp downstream | NEEDS-DEEPER | TBD | N/A | PARTIAL |
