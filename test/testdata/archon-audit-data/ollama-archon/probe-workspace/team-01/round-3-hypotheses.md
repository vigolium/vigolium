# Round 3 Hypotheses: Causal Verifier (Counterfactual / Interventional)

Reasoning approach: For each cross-model seed and NEEDS-DEEPER item, determine whether the causal chain is confirmed, refuted, or requires further evidence. Apply counterfactual tests: "If protection X were present, would the attack fail?"

---

## PH-19: CONFIRMED — registry.Local is an Unconditional Middleware Bypass (from CROSS-01)

**Causal verification**:
Counterfactual test: "If I add a new gin middleware `r.Use(newAuthMiddleware)`, would it protect `/api/pull` and `/api/delete`?"

Answer: NO. The proof is in `GenerateRoutes` lines 1727-1736: when `rc != nil`, the returned `http.Handler` is `registry.Local{Fallback: r}`, NOT `r` itself. Any middleware added to `r` via `r.Use()` only protects requests that reach `r.ServeHTTP`, which only happens after `registry.Local.serveHTTP`'s switch statement falls through to the `default` case. Requests to `/api/delete` and `/api/pull` never fall through to `default` — they are handled and returned at lines 118-121.

**Causal chain confirmed**: `GenerateRoutes(rc != nil)` → returns `registry.Local` as root handler → `/api/pull` request hits `serveHTTP:117` → switch matches `/api/pull` → `handlePull` executes → returns `false, nil` → function returns (Fallback.ServeHTTP never called).

Intervention that would fix this: Apply `allowedHostsMiddleware` inside `registry.Local.ServeHTTP` itself before the switch statement, OR return `r` as the root handler and have `registry.Local` registered as specific route handlers within gin.

**Status**: VALIDATED — causal chain confirmed by code structure
**Severity**: HIGH

---

## PH-20: CONFIRMED — New Cache (DiskCache) Has Same Symlink Attack Surface as Old Cache (from CROSS-02)

**Causal verification**:
The new `DiskCache.Get` (cache.go:259) calls `os.Stat(name)` — this follows symlinks. If `name` is a symlink to a malicious file of matching size, `Get` returns the symlink target's size as if it were a legitimate blob. In `Registry.Pull` (registry.go:515-518):
```go
info, err := c.Get(l.Digest)
if err == nil && info.Size == l.Size {
    update(l.Size, ErrCached)
    continue  // <-- layer download and verification SKIPPED
}
```

If attacker places symlink at `c.GetFile(l.Digest)` pointing to malicious GGUF of the same size as `l.Size`, `c.Get` succeeds, `info.Size == l.Size` matches, and the layer is marked as cached — no download, no `Chunked` write, no `checkWriter` hash verification.

**Critical amplification from CROSS-02**: The `copyNamedFile` size-check bypass (PH-05) requires attacker-controlled file to be SAME SIZE as the legitimate blob. The symlink attack (PH-11) has NO size constraint — the symlink can point to ANY file. A symlink pointing to a same-size file bypasses the new cache's `c.Get` size check. A symlink pointing to a different-size file would fail the size check but would still bypass the OLD `downloadBlob` path's `os.Stat` check (which has no size comparison at all — just existence).

**Confirmed two-tier bypass**:
- Old path (`PullModel` non-tensor code): `downloadBlob:478` → `os.Stat(fp)` → cacheHit=true (NO size check) → any symlink target size works
- New path (`Registry.Pull` tensor code): `c.Get(l.Digest)` → `os.Stat(name)` → `info.Size == l.Size` → symlink target must match expected size

**Status**: VALIDATED — `os.Stat` (not `os.Lstat`) confirmed in both paths; no `O_NOFOLLOW` anywhere in blob open path
**Severity**: HIGH

---

## PH-21: CONFIRMED — GGUF ggufPadding Divide-by-Zero via general.alignment=0 (from CROSS-04 / PH-04)

**Causal verification**:
Go runtime panics on integer divide-by-zero (not a no-op or recoverable error). Test:
```go
alignment := uint64(0) // from KV
padding := ggufPadding(offset, int64(alignment)) // int64(0) = 0
// ggufPadding: (align - offset%align) % align = (0 - offset%0) % 0
// offset % 0 → PANIC: runtime error: integer divide by zero
```

`kv.Uint("general.alignment", 32)` at line 238: the default 32 only applies when the key is absent from the map. If the GGUF KV section contains `general.alignment` with value 0, `kv.Uint` returns 0, which is passed as `align` to `ggufPadding`.

Counterfactual: "Would the panic be caught by a recover?" — The GGUF parser runs in the same goroutine as the HTTP handler. There is no `defer recover()` between the handler and `gguf.Decode`. Go's default panic behavior terminates the process (or at minimum the goroutine chain). The gin framework does have a recovery middleware, but `gin.Default()` is used at line 1666, which includes gin's recovery middleware — so the panic would be caught by gin and return a 500, NOT crash the process. However, this creates a reliable DoS per-request (each malicious GGUF parse → 500 with panic recovery) rather than a full-process crash.

**Status**: VALIDATED — divide-by-zero confirmed; gin recovery middleware prevents process crash but still causes per-request DoS
**Revised severity**: MEDIUM-HIGH (reliable DoS but not process crash due to gin recovery)

---

## PH-22: CONFIRMED — GGUF Unbounded String Allocation (from CROSS-04 / PH-03)

**Causal verification**:
`readGGUFString` at line 359-361:
```go
length := int(llm.ByteOrder.Uint64(buf))  // from file header
if length > len(llm.scratch) {             // scratch = 16KB
    buf = make([]byte, length)             // UNBOUNDED ALLOCATION
}
```

Counterfactual: "Is there any OOM guard?" — `make([]byte, length)` with `length` up to `math.MaxInt64` (2^63-1 on 64-bit). Go's runtime will attempt the allocation and return a non-nil slice or call `runtime.throw("out of memory")`. An OOM error from `make` causes a runtime panic. Again, gin's recovery middleware will catch this panic, but the goroutine dies and the request fails with a 500. On a system with limited memory, repeated requests with large string lengths could exhaust memory across multiple goroutines before gin recovery fires.

**AMPLIFICATION**: `readGGUFString` is called for EVERY KV key AND for every KV value of type string. If `numKV` is large (PH-12), an attacker can cause many large allocations in sequence before any individual one triggers OOM.

**Status**: VALIDATED — unbounded `make([]byte, length)` at line 361 confirmed; no guard
**Severity**: HIGH (reliable OOM/DoS)

---

## PH-23: CONFIRMED — pullWithTransfer Skips verifyBlob BUT x/transfer package DOES hash-verify on fresh download (from CROSS-05 / PH-16)

**Causal verification**:
`x/imagegen/transfer/download.go:188-198`:
```go
h := sha256.New()
n, err := d.copy(ctx, f, r, h)
...
if got := fmt.Sprintf("sha256:%x", h.Sum(nil)); got != blob.Digest {
    os.Remove(tmp)
    return n, fmt.Errorf("digest mismatch")
}
```
The `transfer.Download` package DOES verify SHA-256 on fresh downloads. So PH-16's "if x/transfer skips verification" conditional is FALSE — verification happens.

**However**: The cache-hit skip at `x/imagegen/transfer/download.go:57-64` uses the same size-match-only pattern:
```go
if fi, _ := os.Stat(filepath.Join(opts.DestDir, digestToPath(b.Digest))); fi != nil && fi.Size() == b.Size {
    // already exists
    alreadyCompleted += b.Size
    continue  // SKIP download and SKIP hash verification
}
```

The `x/transfer` package also uses `os.Stat` (symlink-following) and size-match-only for cache hits — same vulnerability as PH-20 / CROSS-02.

**Status**: PH-16 MODIFIED — fresh downloads ARE verified; but cache-hit skip in x/transfer has the SAME size-match-only pattern as the old code. Symlink attack (PH-20) extends to x/transfer's Download function as well.

**Severity**: HIGH (extends CROSS-02 to cover pullWithTransfer path; symlink attack covers ALL pull code paths)

---

## PH-24: CONFIRMED — Registry.Pull Cache Hit Is Also Size-Match-Only (from CROSS-02 deep dive)

**Causal verification**:
`registry.go:515-518`:
```go
info, err := c.Get(l.Digest)
if err == nil && info.Size == l.Size {
    update(l.Size, ErrCached)
    continue  // layer skipped entirely
}
```

`c.Get` (DiskCache.Get at cache.go:257-271) does `os.Stat` only — returns `Entry{Size: info.Size()}`. No hash check. The size comparison `info.Size == l.Size` is the only content validation for cached blobs in the new pull path.

Combined with the `copyNamedFile` TODO comment at line 461: `// TODO: Do the hash check, but give caller a way to skip it.` — the developers acknowledge this is a known gap.

**Counterfactual**: "Would adding `os.Lstat` instead of `os.Stat` fix this?" — Partially. `os.Lstat` would detect symlinks and return an error (since it would return the symlink entry, not a regular file). But for regular file replacement (same-size malicious GGUF overwrite), `os.Lstat` provides no protection. A full fix requires hashing the file content on every cache hit check.

**Status**: VALIDATED — both `DiskCache.Get` and `copyNamedFile` confirmed to use size-match-only for cache hit
**Severity**: HIGH

---

## PH-25: CONFIRMED — ollama.Registry.Pull Validates Model Name (resolves PH-07/PH-15 NEEDS-DEEPER)

**Causal verification**:
`Registry.Pull` (registry.go:464) calls `r.Resolve(ctx, name)`, which internally calls `r.parseNameExtended(name)`. This function (lines 1124-1153):
- Validates scheme: must be in `["http", "https", "https+insecure"]`
- Validates digest format via `blob.ParseDigest` (typed, binary)
- Validates name via `r.parseName(name)` — calls into the `names` package

The scheme validation means HTTP is explicitly supported (unlike the old `PullModel` path which rejects HTTP unless `regOpts.Insecure == true`). A model name with scheme `http://` would be ACCEPTED by `registry.Local.handlePull` without requiring an `insecure` flag, whereas the old `PullHandler` → `PullModel` path would reject it at images.go:597.

**PH-15 CONFIRMED**: `registry.Local.handlePull` → `s.Client.Pull` accepts HTTP scheme model names without any explicit insecure opt-in. The old path's TLS enforcement (images.go:597) is bypassed.

**PH-07 PARTIALLY RESOLVED**: Name validation via `parseName` exists, but it is different from `parseNormalizePullModelRef`. The normalization step (which includes cloud-model suffix handling and existing-name resolution) is absent from the registry.Local path.

**Status**: PH-15 VALIDATED (HTTP pull without insecure flag via registry.Local); PH-07 PARTIALLY VALIDATED (normalization absent)
**Severity**: MEDIUM-HIGH (HTTP pull enables MITM on pull; combined with PH-20 symlink attack enables unverified model injection)

---

## PH-26: CONFIRMED — numKV and numTensor Loops Have No Max Guard (from CROSS-04 / PH-12)

**Causal verification**:
`gguf.Decode` lines 143-191: `for i := 0; uint64(i) < llm.numKV(); i++` — if `numKV()` returns 2^63, this loop runs until it hits EOF on every read attempt. Each iteration calls `readGGUFString` (which itself may allocate) and `readGGUF[uint32]`. With gin's recovery middleware, the process won't crash, but the goroutine will spin reading beyond EOF, with each read returning an error that propagates upward only through the inner switch, eventually returning.

More precisely: when EOF is hit inside `readGGUFString`, `io.ReadFull` returns `io.ErrUnexpectedEOF`, which propagates up through the `readGGUFString` call, through the switch, and is returned from `Decode`. So the loop does NOT spin indefinitely — it exits on first read error.

**Revision**: A large `numKV` causes the loop to attempt many reads until EOF, but does NOT cause an infinite loop. The CPU cost is proportional to min(numKV, file_size / min_kv_size). The real DoS vector is the combination: large `numKV` with each KV having a valid type but garbage data causes many small reads until EOF — this is bounded by file I/O, not CPU.

**Status**: CONFIRMED as DoS but less severe than initially stated — bounded by file size, not by numKV value directly
**Severity**: MEDIUM (DoS bounded by file size)
