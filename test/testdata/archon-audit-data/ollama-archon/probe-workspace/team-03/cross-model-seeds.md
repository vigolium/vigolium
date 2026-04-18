# Cross-Model Seeds: Team-03

## Method
Each seed identifies a pair of hypotheses (one from round-1, one from round-2) that share the same file/function, trust boundary, or where one's attack input flows through the other's vulnerable path. Speculative connections are excluded.

---

## CROSS-01: OOM Allocation + Memory Amplification via KV Map (PH-01 + PH-12)

**Source-A**: PH-01 (backward-reasoner) — unbounded array allocation in `readGGUFArray` when maxArraySize=-1
**Source-B**: PH-12 (contradiction-reasoner) — unbounded KV map growth; maxArraySize controls per-array storage but NOT loop count or key allocation

**Connection**: Both target the KV decoding loop in `gguf.go:143`. PH-01 attacks the per-array allocation path (`newArray[T](int(n), -1)`). PH-12 attacks the outer loop accumulation into `llm.kv` (map). They are COMPOSABLE: a single crafted GGUF can trigger both simultaneously — a large numKV where some entries are large arrays (PH-01 effect) and the rest are cheap types that fill the map (PH-12 effect). The combined effect is multiplicative memory exhaustion.

**Combined hypothesis**: A crafted GGUF with numKV=100,000 where 10 entries are arrays of 400MB uint8 data would trigger: (a) 10 × 400MB = 4GB array allocations, (b) 99,990 map entries accumulating Go map overhead, (c) all within a single `ggml.Decode(blob, -1)` call from `ggufLayers`. Total memory impact: 4GB+ from a file that can be as small as ~40MB of actual data (the array data dominates).

**Test direction for causal-verifier**: Construct a minimal GGUF file (valid magic, Version=3, numTensor=0) with numKV=2, where KV entry 1 is of type ggufTypeArray/ggufTypeUint8 with n=0x10000000 (256M elements). Call `ggml.Decode(reader, -1)`. Confirm: (a) `make([]byte, 268435456)` is called, (b) process memory increases by 256MB, (c) no error is returned before the allocation. Cross-check: call `ggml.Decode(reader, 1000)` (bounded maxArraySize) — confirm allocation is skipped.

---

## CROSS-02: Shape Overflow Bypasses CVE Bounds Check + Enables Parser Exploitation (PH-09 + PH-16)

**Source-A**: PH-09 (backward-reasoner) — integer overflow in `Tensor.Elements()` causes `Size()=0`, bypassing the tensor bounds check
**Source-B**: PH-16 (contradiction-reasoner) — the CVE-patched bounds check at gguf.go:258-262 uses `tensor.Size()` which can overflow to 0

**Connection**: Both identify the EXACT SAME overflow in `Tensor.Elements()` at `ggml.go:505-511` and both conclude it defeats the bounds check at `gguf.go:258-262`. This is strong cross-model confirmation. PH-09 provides the specific overflow inputs; PH-16 identifies the structural contradiction with the CVE fix.

**Combined hypothesis**: The CVE-patched tensor bounds check (`tensorEnd := llm.tensorOffset + tensor.Offset + tensor.Size()`) is bypassable via shape product overflow. A tensor with shape `[0x4000000000000001, 2]` would have:
- Elements = 0x4000000000000001 × 2 = 0x8000000000000002 (overflows uint64? No — 0x8000000000000002 is a valid uint64)
- For F32 (typeSize=4, blockSize=1): Size = 0x8000000000000002 × 4 = 0x8 (overflow to 8)
- But for F16 (typeSize=2, blockSize=1): Size = 0x8000000000000002 × 2 = 0x4 (overflow to 4)
- Bounds check: tensorEnd = tensorOffset + 0 + 4 — passes easily
- Downstream: llama.cpp sees shape [0x4000000000000001, 2] and tries to mmap/read ~73PB of tensor data

To get clean overflow: shape [0x8000000000000000, 1] → Elements = 0x8000000000000000 → Size (F32) = 0x8000000000000000 × 4 = 0x0 (overflow!) → bounds check passes.

**Test direction for causal-verifier**: Construct GGUF with one tensor, shape=[0x8000000000000000, 1], kind=TensorTypeF32, offset=0. Set tensor data to 4 bytes (minimal). Verify: (a) `Tensor.Elements()` returns 0x8000000000000000, (b) `Tensor.Size()` returns 0, (c) `tensorEnd = tensorOffset + 0 + 0 <= fileSize` passes, (d) tensor is stored with fraudulent shape. Confirm the bounds check fix does NOT prevent this.

---

## CROSS-03: Integrity Bypass Chain — 0o777 + Cache Hit Skip + GGUF Parser (PH-03 + PH-10 + PH-17)

**Source-A**: PH-03 (backward-reasoner) — blob replacement after cache-hit stat bypasses verifyBlob
**Source-B**: PH-10 (contradiction-reasoner) — "verifying sha256 digest" message displayed even when all blobs are skipped

**Connection**: PH-03 provides the MECHANISM (replace blob, trigger pull) and PH-10 provides the DECEPTION ASPECT (user/operator sees "verifying sha256 digest" and believes blobs are verified). PH-17 provides the ENABLER (0o777 permissions). All three share the same entry point (downloadBlob → PullModel path) and the same trust boundary (disk → GGUF parser).

**Combined hypothesis**: The complete attack chain is:
1. Attacker has any local user account on a multi-user system running ollama (enabled by 0o777 dirs)
2. Attacker replaces a cached model blob with crafted GGUF content (of same or different size)
3. Legitimate user triggers `ollama pull <model>` — sees "verifying sha256 digest" in output
4. ALL blobs show as cacheHit=true — skipVerify for all — ZERO blobs actually verified
5. Model is loaded with crafted GGUF
6. Combined with PH-01/PH-02: remote OOM/panic OR with PH-09/PH-16: incorrect tensor shape accepted

The deception (step 3) is particularly severe because operators monitoring logs would see only the "verifying sha256 digest" message and conclude the model is safe.

**Test direction for causal-verifier**: On a system with a pulled model: (1) replace a blob file with `dd if=/dev/urandom of=<blob_path> bs=1 count=$(stat -f%z <blob_path>)`, (2) run `ollama pull <model>`, (3) observe "verifying sha256 digest" in output, (4) confirm model loads without error (or GGUF parse error — confirm which). This validates both the integrity bypass and the deceptive UI.

---

## CROSS-04: Size-Only Check Enables Same-Size Malicious GGUF Injection (PH-04 + PH-12)

**Source-A**: PH-04 (backward-reasoner) — `copyNamedFile` size-only check in DiskCache skips hash verification for same-size replacement
**Source-B**: PH-12 (contradiction-reasoner) — memory amplification via KV map growth

**Connection**: PH-04 provides the bypass mechanism (same-size replacement). PH-12 identifies a specific payload that can fit in ANY file size: a crafted GGUF where KV entries with small arrays replace the original blob's content. The attacker doesn't need to know the original content — they only need to construct a malicious GGUF of exactly the same byte size as the target blob. Given GGUF's flexible KV section, this is achievable by padding KV string values to fill the required bytes.

**Combined hypothesis**: An attacker constructs a GGUF file of EXACTLY the same byte count as the target model blob. The crafted file contains a KV entry of type uint8 array with n large enough to cause 2GB+ memory allocation when decoded. When `DiskCache.copyNamedFile` is called (via `Put`), the size match causes immediate return without hash check. The poisoned blob is stored and loaded by `ggml.Decode`.

**Test direction for causal-verifier**: (1) Determine size S of a legitimate cached blob; (2) construct a crafted GGUF of exactly S bytes with an array KV entry claiming n=0x40000000 elements; (3) call `copyNamedFile(targetPath, craftedReader, legitimateDigest, S)` — confirm it returns nil without calling checkWriter; (4) attempt to load the crafted blob via `ggml.Decode`.

---

## CROSS-05: Symlink + Cache Hit → GGUF Parser Attack (PH-05 + PH-01)

**Source-A**: PH-05 (backward-reasoner) — symlink substitution at blob path causes cache hit with attacker-controlled content; no Lstat check
**Source-B**: PH-01 (backward-reasoner) — OOM via array allocation when blob is decoded with maxArraySize=-1

Both are validated. The connection: PH-05 provides a DELIVERY MECHANISM for PH-01's payload. A symlink pointing to an attacker-crafted GGUF (stored in /tmp or any writable location) causes that crafted GGUF to be loaded by `ggml.Decode` without any hash verification. The combined attack does not require the attacker to write into the actual blobs directory — a symlink anywhere in a 0o777 blobs directory suffices.

**Combined hypothesis**: Attacker creates `/var/ollama/models/blobs/sha256-<target_digest>` as a symlink to `/tmp/evil.gguf`. `/tmp/evil.gguf` contains valid GGUF magic + numKV=1 + array KV with n=0x40000000. User runs `ollama run <model>` → `downloadBlob` → `os.Stat` follows symlink → cacheHit=true → model load → `ggml.Decode` → 1GB allocation.

**Test direction for causal-verifier**: Create symlink in a test blobs directory. Confirm `os.Stat` follows it. Confirm `downloadBlob` returns cacheHit=true. Confirm `ggml.Decode` opens and parses the symlink target. Confirm no Lstat call exists in the entire path from downloadBlob through model load.
