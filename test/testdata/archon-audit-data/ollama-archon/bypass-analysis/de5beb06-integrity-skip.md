# Bypass Analysis: de5beb06 — Blob Integrity Verification Skipped on Cache Hit

**Cluster ID**: blob-integrity-skip
**Undisclosed tag**: [undisclosed]

## Patch Summary

Commit `de5beb06` modifies `downloadBlob()` to return a `cacheHit bool` when
a blob file already exists on disk (determined solely by `os.Stat` succeeding).
In `PullModel()`, blobs marked as cache hits skip `verifyBlob()`, which would
otherwise re-hash the file and compare against the expected SHA-256 digest.

The stated rationale is performance: avoid re-hashing multi-gigabyte model files
on every pull when they already exist.

## Bypass Verdict: **bypassable**

The skip-verify-on-cache-hit pattern creates a concrete integrity gap exploitable
under several scenarios.

## Evidence

### 1. Cache hit trusts path existence, not content

`downloadBlob()` lines 349-359: if `os.Stat(fp)` succeeds (file exists with any
content), `cacheHit=true` is returned. No hash check occurs. The file could
contain arbitrary data.

### 2. No symlink protection

`BlobsPath()` in `manifest/paths.go` constructs the path via `filepath.Join` and
calls `os.MkdirAll` on the parent. Neither `BlobsPath` nor `downloadBlob` check
for symlinks (no `os.Lstat`, no `O_NOFOLLOW`). An attacker with write access to
the blobs directory (or a path traversal elsewhere) could replace a blob file
with a symlink to attacker-controlled content. On the next pull, this would be
a "cache hit" and load unverified.

### 3. TOCTOU between download check and model load

The flow is: `downloadBlob` (stat check) -> skip verify -> write manifest ->
later, model load reads the blob. Between the stat check and model load, the
blob file can be replaced. Since verification was skipped, the substituted
content is loaded directly.

### 4. DiskCache.copyNamedFile has the same pattern

`cache/blob/cache.go` line 458-465: `copyNamedFile` also skips hash verification
when file exists with matching size:
```
if err == nil && info.Size() == size {
    // File already exists with correct size. This is good enough.
    // We can skip expensive hash checks.
    return nil
}
```
This means the newer blob cache layer has the **same weakness**: size-match is
treated as sufficient, with no content verification. An attacker who replaces a
blob with a same-size malicious file bypasses both the old and new code paths.

### 5. No at-load-time integrity verification in GGUF parser

The GGUF parser (`ggml/gguf.go` and related) reads model tensors from the blob
file at load time. It validates structural fields (magic number, version, tensor
shapes) but does **not** re-verify the SHA-256 digest of the entire file. A
corrupted or malicious file that maintains valid GGUF header structure would be
loaded without detection.

### 6. Blob directory permissions

The blobs directory is created with mode `0o777` (`cache.go:85`) and `0o755`
(`paths.go:56`). The `0o777` in the newer cache layer means any local user on a
shared system can write to the blobs directory, enabling blob replacement attacks
without requiring elevated privileges.

## Attack Scenarios

**Local privilege scenario**: On a multi-user system, attacker replaces a cached
blob file (same size) with a crafted GGUF containing malicious tensor data or
exploiting a parser vulnerability. Next model load uses the tampered file without
any integrity check.

**Supply chain scenario**: If an attacker gains transient write access to the
models directory (via a separate vulnerability, shared mount, or container
escape), they can poison cached blobs. The integrity skip ensures the poisoned
blob persists across future pulls of the same model.

## Recommendations

1. Always verify blob integrity on load, at minimum for the first load after process start (amortize cost with an in-memory verified set).
2. Add `os.Lstat` checks to reject symlinks in the blob path.
3. Fix `copyNamedFile` to not skip hash checks when file size matches — or at minimum add a TODO with a security note.
4. Consider `0o755` (not `0o777`) for blob directory creation in `cache.go`.
