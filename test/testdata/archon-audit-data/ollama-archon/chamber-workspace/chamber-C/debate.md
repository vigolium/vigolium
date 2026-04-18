# Review Chamber: chamber-C

Cluster: GGUF Parser + Blob Integrity (DFD-4: Blob Upload -> GGUF Parse -> Crash; CFD-3: Blob Integrity cache hit skip, size-only check)
DFD Slices: DFD-4, CFD-3
NNN Range: p8-040 to p8-049
Started: 2026-04-07T00:00:00Z
Status: CLOSED

---

## Round 1 -- Ideation

### [IDEATOR] Hypotheses -- 2026-04-07

Based on deep probe results (team-03) and SAST findings, the following hypotheses are pre-seeded and prioritized for this chamber:

#### H-01: readGGUFString Panic via Negative Length (PH-02/PH-R3-02)
- **Target**: `fs/ggml/gguf.go:359` -- `length := int(llm.ByteOrder.Uint64(buf))`
- **Attack**: Craft 32-byte GGUF with key-length = 0x8000000000000000. Uint64 -> int cast produces MinInt64. `llm.scratch[:MinInt64]` panics.
- **Entry point**: `POST /api/blobs/:digest` then `POST /api/create`
- **Severity estimate**: HIGH (remote unauthenticated DoS)

#### H-02: OOM via Unbounded Array Allocation with maxArraySize=-1 (PH-01/PH-R3-01)
- **Target**: `fs/ggml/gguf.go:418` -- `if maxSize < 0 || size <= maxSize` -> allocates any size
- **Attack**: Craft GGUF with array n=0x40000000 (1GB), element_type=uint8, provide 1GB body via `POST /api/blobs/:digest`
- **Entry point**: `POST /api/create` -> `ggml.Decode(blob, -1)`
- **Severity estimate**: HIGH (remote DoS via OOM)

#### H-03: Divide-by-Zero in ggufPadding via general.alignment=0 (PH-R3-04)
- **Target**: `fs/ggml/gguf.go:238,245,688` -- alignment=0 -> `offset % 0` -> panic
- **Attack**: Craft GGUF with KV entry `general.alignment=0` (uint32)
- **Entry point**: `POST /api/create` -> `ggml.Decode`
- **Severity estimate**: HIGH (remote unauthenticated DoS, minimal file size)

#### H-04: Tensor Elements()/Size() Overflow Bypasses Bounds Check (PH-09/PH-16/PH-R3-03)
- **Target**: `fs/ggml/ggml.go:505-514` -- uint64 multiplication wraps; unknown Kind -> typeSize()=0 -> Size()=0
- **Attack**: Craft tensor with shape=[0x8000000000000000,1] or Kind=0xFFFFFFFF -> Size()=0 -> passes `tensorEnd > fileSize` check
- **Entry point**: `POST /api/create` -> `ggml.Decode` -> tensor loop
- **Severity estimate**: HIGH (bounds check bypass; downstream OOB in llama.cpp)

#### H-05: Blob Cache Poisoning via skipVerify + Size-Only Check (PH-03/PH-04/PH-05)
- **Target**: `server/images.go:634,640` (skipVerify), `server/internal/cache/blob/cache.go:459` (size-only check), `server/download.go:478` (os.Stat follows symlinks)
- **Attack**: Local attacker replaces cached blob with same-size malicious GGUF; legitimate user runs `ollama pull` -> verifyBlob skipped -> malicious model loaded
- **Entry point**: Local file system access to blobs directory (amplified by 0o777 permissions in containers)
- **Severity estimate**: HIGH (local privilege escalation to model poisoning)

#### H-06: Data Race on intermediateBlobs Map (PH-08/PH-13)
- **Target**: `server/model.go:21` -- `var intermediateBlobs map[string]string` + `server/routes.go:1501,1510`
- **Attack**: Two concurrent `POST /api/blobs/:digest` requests trigger concurrent map read+write -> Go runtime panic
- **Entry point**: `POST /api/blobs/:digest` (concurrent)
- **Severity estimate**: MEDIUM (remote DoS via race condition)

#### H-07: No Upload Body Size Limit in CreateBlobHandler (PH-R3-05)
- **Target**: `server/routes.go:1538` -- `manifest.NewLayer(c.Request.Body, "")`
- **Attack**: Upload arbitrarily large blob -> disk exhaustion
- **Entry point**: `POST /api/blobs/:digest`
- **Severity estimate**: MEDIUM (remote DoS via disk exhaustion)

---

## Round 2 -- Tracing

### [TRACER] Evidence for H-01 (readGGUFString Panic) -- 2026-04-07

**Code path confirmed**:
1. `POST /api/blobs/:digest` -> `server/routes.go:1538` -> `manifest.NewLayer(c.Request.Body, "")` stores blob to disk
2. `POST /api/create` -> `server/create.go` -> `ggufLayers()` -> `ggml.Decode(blob, -1)`
3. `ggml.Decode` -> `containerGGUF.Decode` (gguf.go:46) -> KV loop -> `readGGUFString` (gguf.go:348)
4. `readGGUFString` reads 8 bytes -> `length := int(llm.ByteOrder.Uint64(buf))` (line 359)
5. If Uint64 returns 0x8000000000000000, `int()` cast on 64-bit produces -9223372036854775808 (MinInt64)
6. Line 360: `if length > len(llm.scratch)` -- MinInt64 < len(scratch), so falls through to line 362
7. Line 363: `buf = llm.scratch[:MinInt64]` -- negative slice index -> **runtime panic: slice bounds out of range**

**Sanitizers on path**: NONE. No sign check, no upper-bound check on length before slice operation.
**Attacker control**: Full. The 8-byte length field is read directly from user-supplied GGUF binary.
**Trust boundary**: Network -> file system -> parser. Unauthenticated API.
**Evidence verdict**: REACHABLE

### [TRACER] Evidence for H-02 (OOM via Unbounded Array) -- 2026-04-07

**Code path confirmed**:
1. Same upload path as H-01 to get blob on disk
2. `ggml.Decode(blob, -1)` -- note the `-1` passed as maxArraySize
3. `containerGGUF.Decode` -> KV loop -> `readGGUFArray` (gguf.go:424)
4. Reads type (uint32) and n (uint64) from file -> `newArray[uint8](int(n), llm.maxArraySize)` (line 437)
5. `newArray` (line 416-422): `maxSize = -1`, so `maxSize < 0` is true -> `a.values = make([]T, size)` always executes
6. With n=0x40000000 (1GB for uint8), Go allocates 1GB. Repeated with larger values -> OOM.

**Sanitizers on path**: The `maxArraySize` parameter was intended as a limit, but passing `-1` disables it entirely. No http.MaxBytesReader on upload body.
**Attacker control**: Full. Array size n is read from GGUF binary. Attacker must provide matching bytes in file body (io.ReadFull will fail otherwise), but no upload size limit prevents this.
**Trust boundary**: Network -> parser -> heap allocation. Unauthenticated API.
**Evidence verdict**: REACHABLE

### [TRACER] Evidence for H-03 (Divide-by-Zero alignment=0) -- 2026-04-07

**Code path confirmed**:
1. Same upload path to get GGUF on disk
2. `containerGGUF.Decode` processes KV entries. If key is `general.alignment` with value 0 (uint32), it is stored in `llm.kv`
3. Line 238: `alignment := llm.kv.Uint("general.alignment", 32)` -- returns 0 when key explicitly set to 0
4. Line 245: `ggufPadding(offset, int64(alignment))` -> `ggufPadding(offset, 0)`
5. Line 688: `(align - offset%align) % align` -> `offset % 0` -> **panic: integer divide by zero**

**Sanitizers on path**: NONE. `kv.Uint` returns the stored value without validation. No `max(alignment, 1)` guard.
**Attacker control**: Full. The alignment value is a standard KV entry in GGUF format.
**Trust boundary**: Network -> parser -> arithmetic. Unauthenticated API.
**CVE lineage**: Same bug class as CVE-2025-0317 and CVE-2024-8063 (divide-by-zero in GGUF padding).
**Evidence verdict**: REACHABLE

### [TRACER] Evidence for H-04 (Tensor Size() Overflow) -- 2026-04-07

**Code path confirmed**:
1. Same upload path
2. `containerGGUF.Decode` -> tensor loop reads Shape (uint64[]) and Kind (uint32) from file
3. `Tensor.Elements()` (ggml.go:505-510): multiplies all shape dimensions as uint64. Shape=[0x8000000000000000, 2] -> 0x8000000000000000 * 2 = 0 (overflow)
4. `Tensor.Size()` (ggml.go:513-514): `Elements() * typeSize() / blockSize()`. With Elements()=0, Size()=0.
5. Alternative: Kind=0xFFFFFFFF (unknown) -> `typeSize()` returns 0 (default case at ggml.go:500-502) -> Size()=0 regardless of Elements().
6. Line 259: `tensorEnd := llm.tensorOffset + tensor.Offset + tensor.Size()` -> tensorEnd = tensorOffset + Offset + 0
7. Line 260: `tensorEnd > uint64(fileSize)` -- passes trivially since tensor claims zero size
8. Tensor accepted with fraudulent metadata. Downstream llama.cpp runner receives this metadata.

**Sanitizers on path**: The bounds check at line 258-262 was added as a CVE fix but is defeated by Size()=0.
**Attacker control**: Full. Shape and Kind are read from GGUF binary.
**Downstream impact**: NEEDS-DEEPER (PH-R3-06). If llama.cpp trusts Go-parsed shapes for memory addressing, this is CRITICAL. The runner/ package was not fully traced.
**Evidence verdict**: REACHABLE (bounds check bypass confirmed; downstream severity uncertain)

### [TRACER] Evidence for H-05 (Blob Cache Poisoning) -- 2026-04-07

**Code path confirmed (three independent mechanisms)**:

**Mechanism A: skipVerify on cache hit**
1. `server/images.go:625`: `downloadBlob()` returns `cacheHit=true` if `os.Stat(fp)` succeeds (file exists)
2. Line 634: `skipVerify[layer.Digest] = true`
3. Line 638: UI shows "verifying sha256 digest" (misleading)
4. Line 640: `if skipVerify[layer.Digest] { continue }` -- verifyBlob() NEVER called
5. Attacker who modifies the blob file before this point -> modified content loaded as model

**Mechanism B: DiskCache size-only check**
1. `cache.go:458-464`: `copyNamedFile` checks `info.Size() == size` -> returns nil if match
2. The TODO comment acknowledges this gap explicitly
3. Same-size replacement bypasses SHA-256 verification

**Mechanism C: Symlink following**
1. `os.Stat` follows symlinks. No `os.Lstat` used anywhere in cache path.
2. Attacker creates symlink at blob path -> points to attacker-controlled file
3. `downloadBlob` -> stat succeeds -> cache hit -> skip verify -> model loaded from symlink target

**Prerequisite**: Write access to blobs directory. Amplified by `os.MkdirAll(dir, 0o777)` in `cache.go:79,85` (effective 0o777 in containers with umask=0).

**Sanitizers on path**: NONE. verifyBlob is the only integrity check and it is skipped.
**Attacker control**: Local attacker with filesystem access (same machine or container).
**Trust boundary**: Local filesystem -> model loading pipeline.
**Evidence verdict**: REACHABLE

### [TRACER] Evidence for H-06 (Data Race on intermediateBlobs) -- 2026-04-07

**Code path confirmed**:
1. `server/model.go:21`: `var intermediateBlobs map[string]string = make(map[string]string)` -- package-level unprotected map
2. `server/routes.go:1501`: `if ib, ok := intermediateBlobs[c.Param("digest")]; ok {` -- read in HTTP handler goroutine
3. `server/routes.go:1510`: `delete(intermediateBlobs, c.Param("digest"))` -- delete in same handler, different goroutine
4. Two concurrent requests -> concurrent map read + write -> Go runtime fatal error

**Sanitizers on path**: NONE. No mutex, sync.Map, or channel protection.
**Attacker control**: Full. Send two concurrent POST /api/blobs/:digest requests.
**Trust boundary**: Network -> server crash. Unauthenticated.
**Evidence verdict**: REACHABLE

### [TRACER] Evidence for H-07 (No Upload Size Limit) -- 2026-04-07

**Code path confirmed**:
1. `server/routes.go:1538`: `manifest.NewLayer(c.Request.Body, "")` -- reads entire body
2. No `http.MaxBytesReader` wrapper on `c.Request.Body`
3. No `Content-Length` check before writing
4. `manifest.NewLayer` calls `io.Copy` to temp file -- unbounded

**Sanitizers on path**: NONE.
**Attacker control**: Full. Attacker controls upload size.
**Trust boundary**: Network -> disk. Unauthenticated.
**Evidence verdict**: REACHABLE

---

## Round 3 -- Challenge

### [ADVOCATE] Defense Briefs -- 2026-04-07

#### Defense for H-01 (readGGUFString Panic)

1. **Framework protection**: No HTTP framework middleware catches panics before they crash the process. Gin has a default Recovery middleware, but this occurs in a background goroutine during model creation, not in the HTTP handler goroutine itself.
2. **Input validation**: No validation on the uint64 -> int conversion. No check for negative result after cast.
3. **Existing CVE patches**: CVE-2025-66960 (CWE-400) addresses "unchecked GGUF string-length read" but the code at line 359 still has no sign check. The current code added the scratch buffer optimization but not bounds validation.
4. **Alternate mitigation**: None found. The code path is direct: read 8 bytes -> cast -> slice.
5. **FP pattern check**: NOT a false positive. The bug is structurally identical to CVE-2024-39720 (OOB read from malformed GGUF).

**Defense verdict**: No blocking protection found. VALID.

#### Defense for H-02 (OOM via Unbounded Array)

1. **Framework protection**: No memory limits in Go runtime by default. No cgroup memory limit assumed.
2. **maxArraySize parameter**: The `-1` sentinel value is explicitly passed by `ggml.Decode(blob, -1)` in `create.go:684`. This is intentional -- the create path wants full data. However, this means NO allocation limit.
3. **Upload body limit**: No `http.MaxBytesReader`. Attacker must provide actual bytes (io.ReadFull will error on short reads), but nothing prevents uploading multi-GB files.
4. **Existing CVE**: CVE-2025-0315 (CWE-770, unlimited memory allocation from GGUF) -- same bug class. Current code has `maxArraySize` but passing `-1` defeats it.
5. **FP pattern check**: NOT a false positive. The allocation is real and unbounded.

**Defense verdict**: No blocking protection found. The maxArraySize mechanism exists but is intentionally disabled for the attack-relevant code path. VALID.

#### Defense for H-03 (Divide-by-Zero alignment=0)

1. **Framework protection**: None. Go integer division by zero causes unrecoverable panic.
2. **Input validation**: `kv.Uint()` returns the raw value. No `max(alignment, 1)` or alignment validation.
3. **Existing CVE**: CVE-2025-0317 (divide-by-zero in ggufPadding via block_count=0) and CVE-2024-8063 (same class). Despite TWO prior CVEs for the same bug class, no systematic alignment validation was added.
4. **FP pattern check**: NOT a false positive. Direct arithmetic on attacker-controlled value.

**Defense verdict**: No blocking protection found. VALID. Structural recurrence of patched CVEs.

#### Defense for H-04 (Tensor Size() Overflow)

1. **Bounds check**: The check at gguf.go:258-262 was added as a CVE fix, but it compares `tensorEnd > fileSize` where tensorEnd includes `tensor.Size()`. When Size()=0, the check passes trivially.
2. **Shape validation**: No check that shape dimensions are non-zero or that their product doesn't overflow.
3. **Kind validation**: No rejection of unknown tensor types. Default returns typeSize=0, blockSize=256.
4. **Downstream impact**: The Go parser stores the tensor metadata. The runner/ package passes this to llama.cpp. If llama.cpp re-parses the GGUF independently, the Go overflow is irrelevant. However, even if llama.cpp re-parses, accepting the malformed file is a defense-in-depth failure.
5. **FP pattern check**: The bounds check bypass is real. Whether downstream exploitation occurs depends on llama.cpp's independent validation.

**Defense verdict**: Bounds check bypass confirmed. Downstream exploitation uncertain (NEEDS-DEEPER on runner/ package). The finding is VALID as a bounds check bypass; severity depends on downstream trust model.

#### Defense for H-05 (Blob Cache Poisoning)

1. **File permissions**: Default umask on Linux/macOS (022) results in 0o755 directories, not 0o777. However, Docker containers commonly have umask=0, making directories truly world-writable.
2. **Local access required**: This requires the attacker to be on the same machine or in the same container. Not remotely exploitable alone.
3. **skipVerify mechanism**: This is by design -- performance optimization to avoid re-hashing large files. But it creates a TOCTOU window.
4. **Symlink protection**: No `os.Lstat` or `O_NOFOLLOW` anywhere in the blob path.
5. **FP pattern check**: NOT a false positive for local threat model. This is a local privilege escalation / model poisoning vector.

**Defense verdict**: Local access required (not remote). In container/multi-user environments, this is exploitable. VALID with local attacker model.

#### Defense for H-06 (Data Race on intermediateBlobs)

1. **Concurrency protection**: None. The map is a package-level variable accessed from HTTP handler goroutines.
2. **Go race detector**: Would catch this in testing, but race detector is not enabled in production builds.
3. **Practical exploitation**: Requires precise timing of concurrent requests with the same digest. The map is small and rarely accessed, making the race window narrow.
4. **Impact**: Go runtime panic is unrecoverable (kills process). This is equivalent to a crash DoS.
5. **FP pattern check**: NOT a false positive. Go's concurrent map access is explicitly undefined behavior.

**Defense verdict**: No protection found. Race window is narrow but the map access is unprotected. VALID at MEDIUM.

#### Defense for H-07 (No Upload Size Limit)

1. **HTTP body limits**: No `http.MaxBytesReader` on the upload endpoint. Go's default `http.Server` has no body size limit.
2. **Disk space**: This is bounded by available disk space, which is an infrastructure concern rather than application security.
3. **Rate limiting**: No evidence of rate limiting on the blob upload endpoint.
4. **Severity**: Disk exhaustion DoS. Common in many upload APIs. Standard mitigation is infrastructure-level (reverse proxy body size limit, disk quotas).
5. **FP pattern check**: This is a real issue but may be considered a deployment concern rather than application vulnerability.

**Defense verdict**: Real but LOW-to-MEDIUM severity. Infrastructure-level mitigation expected. Borderline VALID/DROP.

---

## Round 4 -- Synthesis

### [SYNTHESIZER] Verdict for H-01 -- 2026-04-07

**Prosecution summary**: Tracer confirmed that `readGGUFString` at gguf.go:359 casts `Uint64` to `int` without sign check. A GGUF file with key-length=0x8000000000000000 produces MinInt64, causing `llm.scratch[:MinInt64]` to panic with slice bounds out of range. The parsing occurs in a background goroutine (create.go:99) without `recover()`, so the panic kills the entire server process. Gin Recovery middleware does not protect background goroutines.

**Defense summary**: Advocate found no blocking protection. No input validation on the uint64->int conversion. No sign check. No upper bound. Same bug class as CVE-2024-39720 and CVE-2025-66960. Despite prior CVEs, the sign check was never added.

**Pre-FP Gate**: all checks passed
- Attacker control verified: yes (8-byte length field from GGUF binary)
- Framework protection searched: yes (Gin Recovery does not cover background goroutine)
- Trust boundary crossing confirmed: yes (network -> parser crash)
- Normal attacker position: yes (unauthenticated API)
- Ships to production: yes (fs/ggml/gguf.go is core parser)

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Remote unauthenticated DoS via crafted GGUF file; panics in unprotected background goroutine crashes entire server; no sanitizers exist despite prior CVEs in same code.

**Finding draft written to**: archon/findings-draft/p8-040-gguf-string-length-panic.md
**Registry updated**: AP-040 GGUF unchecked uint64-to-int cast in parser

---

### [SYNTHESIZER] Verdict for H-02 -- 2026-04-07

**Prosecution summary**: Tracer confirmed that `ggml.Decode(blob, -1)` passes maxArraySize=-1, which causes `newArray` at gguf.go:418 to allocate any requested size (the `maxSize < 0` check is true, so the allocation always proceeds). An attacker can craft a GGUF with a 1GB+ array, upload it via the unauthenticated blob API, and trigger OOM when `POST /api/create` parses it.

**Defense summary**: Advocate found no blocking protection. The `maxArraySize` mechanism exists but is intentionally disabled (-1) for the create path. No `http.MaxBytesReader` on upload. Same bug class as CVE-2025-0315 (CWE-770).

**Pre-FP Gate**: all checks passed
- Attacker control verified: yes (array size n from GGUF binary)
- Framework protection searched: yes (no memory limits, no upload limits)
- Trust boundary crossing confirmed: yes (network -> heap exhaustion)
- Normal attacker position: yes (unauthenticated API)
- Ships to production: yes

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Remote unauthenticated OOM DoS via unbounded GGUF array allocation; maxArraySize=-1 sentinel disables the only protection; structural recurrence of CVE-2025-0315.

**Finding draft written to**: archon/findings-draft/p8-041-gguf-oom-unbounded-array.md
**Registry updated**: AP-041 GGUF unbounded allocation via disabled size limit

---

### [SYNTHESIZER] Verdict for H-03 -- 2026-04-07

**Prosecution summary**: Tracer confirmed that setting `general.alignment=0` in GGUF KV metadata causes `ggufPadding(offset, 0)` at gguf.go:245, which executes `offset % 0` at gguf.go:688 and panics with integer divide by zero. Same background goroutine without recover() as H-01. Minimal file size required (~100 bytes).

**Defense summary**: Advocate found no blocking protection. No validation that alignment > 0. Despite CVE-2025-0317 and CVE-2024-8063 (both divide-by-zero in same component), no systematic guard was added for the alignment KV entry.

**Pre-FP Gate**: all checks passed

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Remote unauthenticated DoS via minimal crafted GGUF; divide-by-zero in unprotected goroutine crashes server; structural recurrence of two prior CVEs in same code path.

**Finding draft written to**: archon/findings-draft/p8-042-gguf-div-by-zero-alignment.md
**Registry updated**: AP-042 GGUF divide-by-zero via attacker-controlled alignment

---

### [SYNTHESIZER] Verdict for H-04 -- 2026-04-07

**Prosecution summary**: Tracer confirmed two mechanisms to produce Size()=0, bypassing the tensor bounds check at gguf.go:258-262: (A) shape product overflow (uint64 wraps to 0), (B) unknown Kind where typeSize()=0. Both cause `tensorEnd = tensorOffset + offset + 0`, trivially passing the `> fileSize` check. The tensor with fraudulent metadata is accepted and stored.

**Defense summary**: Advocate confirmed the bounds check bypass is real. The check was added as a CVE fix but is defeated by overflow/unknown-Kind. Downstream exploitation via llama.cpp is uncertain (NEEDS-DEEPER) but the Go-level bounds check bypass is independently valuable as a defense-in-depth failure that enables further attack.

**Pre-FP Gate**: all checks passed (bounds check bypass is confirmed; downstream impact is uncertain but the bypass itself is the finding)

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: CVE-fix bounds check for tensor validation is bypassed via uint64 overflow or unknown tensor Kind; accepts malformed tensors that may cause OOB access in downstream C++ backend.

**Finding draft written to**: archon/findings-draft/p8-043-gguf-tensor-bounds-bypass.md
**Registry updated**: AP-043 GGUF tensor size overflow bypasses bounds check

---

### [SYNTHESIZER] Verdict for H-05 -- 2026-04-07

**Prosecution summary**: Tracer confirmed three independent mechanisms: (A) skipVerify on cache hit skips verifyBlob entirely, (B) DiskCache.copyNamedFile size-only check with explicit TODO acknowledging the gap, (C) os.Stat follows symlinks without os.Lstat protection. All three allow a local attacker with filesystem access to poison cached blobs. The 0o777 directory permissions (in containers with umask=0) amplify the attack surface.

**Defense summary**: Advocate confirmed local access is required (not remotely exploitable alone). Default umask provides partial mitigation on desktop but not in containers. This is a local privilege escalation / model poisoning vector that enables delivery of H-01/H-02/H-03 payloads to other users.

**Pre-FP Gate**: all checks passed
- Attacker control verified: yes (filesystem write)
- Framework protection searched: yes (no integrity check on cache hit)
- Trust boundary crossing confirmed: yes (local user -> model poisoning of another user)
- Normal attacker position: yes (local user on multi-user/container system)
- Ships to production: yes

**Verdict: VALID**
**Severity: HIGH**
**Rationale**: Three independent mechanisms allow local blob cache poisoning with no integrity verification; enables delivery of parser exploit payloads; amplified by world-writable directory permissions in container environments.

**Finding draft written to**: archon/findings-draft/p8-044-blob-cache-poisoning.md
**Registry updated**: AP-044 Blob cache integrity bypass via skip-verify + size-only check

---

### [SYNTHESIZER] Verdict for H-06 -- 2026-04-07

**Prosecution summary**: Tracer confirmed that `intermediateBlobs` is a package-level `map[string]string` accessed from HTTP handler goroutines without any synchronization. Concurrent `POST /api/blobs/:digest` requests can trigger concurrent map read+write. In Go, this causes a fatal `throw` (not a recoverable panic), killing the process even if Gin Recovery is active.

**Defense summary**: Advocate found no protection. The race window is narrow (requires concurrent requests with specific digest patterns), but the map is accessed on every blob upload request.

**Pre-FP Gate**: all checks passed

**Verdict: VALID**
**Severity: MEDIUM**
**Rationale**: Unprotected concurrent map access causes unrecoverable Go runtime fatal error; remotely triggerable via concurrent blob upload requests; narrow race window prevents upgrade to HIGH.

**Finding draft written to**: archon/findings-draft/p8-045-intermediate-blobs-race.md
**Registry updated**: no new pattern (standard concurrent map access bug)

---

### [SYNTHESIZER] Verdict for H-07 -- 2026-04-07

**Prosecution summary**: Tracer confirmed no `http.MaxBytesReader` or Content-Length check on the blob upload endpoint. Attackers can upload arbitrarily large files to exhaust disk.

**Defense summary**: Advocate notes this is a common deployment concern mitigated by infrastructure (reverse proxy body limits, disk quotas). The severity is LOW-to-MEDIUM as it requires sustained upload to exhaust disk and is typically mitigated at the infrastructure layer.

**Pre-FP Gate**: failed on check-4: requires sustained upload and is typically mitigated by deployment infrastructure (reverse proxy, disk quotas). This is a hardening recommendation rather than a distinct vulnerability.

**Verdict: DROP**
**Severity: --**
**Rationale**: Disk exhaustion via large upload is a deployment-level concern typically mitigated by infrastructure; low severity does not meet finding threshold.

**Finding draft written to**: --
**Registry updated**: no new pattern

---

## Chamber Summary

| Hypothesis | Verdict | Severity | Finding Draft |
|-----------|---------|----------|---------------|
| H-01 readGGUFString panic | VALID | HIGH | p8-040-gguf-string-length-panic.md |
| H-02 OOM unbounded array | VALID | HIGH | p8-041-gguf-oom-unbounded-array.md |
| H-03 Div-by-zero alignment | VALID | HIGH | p8-042-gguf-div-by-zero-alignment.md |
| H-04 Tensor bounds bypass | VALID | HIGH | p8-043-gguf-tensor-bounds-bypass.md |
| H-05 Blob cache poisoning | VALID | HIGH | p8-044-blob-cache-poisoning.md |
| H-06 intermediateBlobs race | VALID | MEDIUM | p8-045-intermediate-blobs-race.md |
| H-07 No upload size limit | DROP | -- | -- |

Findings written: 6
Patterns added to registry: 4
Variant candidates: 0

Chamber closed: 2026-04-07T01:00:00Z
