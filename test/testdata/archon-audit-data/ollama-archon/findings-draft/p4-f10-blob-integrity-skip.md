# p4-f10: Blob Cache Integrity Verification Skipped on Cache Hit; Blob Directory 0o777

**Severity**: MEDIUM
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity), CWE-732 (Incorrect Permission Assignment)
**DFD Slice**: CFD-3
**Cluster**: blob-integrity-skip

## Location

- `server/internal/cache/blob/cache.go:79,85`: `os.MkdirAll` with `0o777`
- `server/internal/cache/blob/cache.go:458-465`: `copyNamedFile` skips hash when size matches
- `server/download.go:349-359` (approx): `downloadBlob()` returns `cacheHit=true` on stat success

## Description

### 1. 0o777 Blob Directory
```go
// cache/blob/cache.go:79,85
os.MkdirAll(dir, 0o777)
os.MkdirAll(filepath.Join(dir, subdir), 0o777)
```
World-writable blob directory on shared systems allows any local user to replace blob files.

### 2. Size-Only Integrity Check in copyNamedFile
```go
// cache.go:458-465
if err == nil && info.Size() == size {
    // File already exists with correct size. This is good enough.
    // We can skip expensive hash checks.
    return nil
}
```
An attacker who can write a same-size malicious GGUF to the blob path bypasses integrity entirely.

### 3. Cache Hit Skips verifyBlob
`downloadBlob()` returns `cacheHit=true` when `os.Stat(fp)` succeeds, regardless of content. `PullModel()` skips `verifyBlob()` for cache hits. A poisoned blob (e.g., placed via the 0o777 directory) is loaded without any hash verification on subsequent pulls.

### 4. No Symlink Protection
`BlobsPath()` uses `filepath.Join` + `os.MkdirAll` without `os.Lstat` symlink checks. A symlink in the blob directory is followed transparently, enabling attacker-controlled content to be loaded as a cached blob.

## Impact

On multi-user systems: local attacker poisons cached model blobs → malicious GGUF loaded at next model use without detection. Combined with GGUF parser vulnerabilities, this enables code execution or DoS.

---

## Phase 7 Enrichment Verdict

**Classification**: ENVIRONMENT — likely environment/deployment (requires local multi-user system with shared blob directory)

**Attacker Control**: A local attacker with write access to the blob directory (granted by `0o777`) can replace or place blob files. The attack requires a shared filesystem or multi-user system where the blob directory is accessible to more than one user account.

**Runtime**: `ollama serve` — the server process reads blob files from the cache directory during model operations.

**Trust Boundary Crossed**: Local multi-user filesystem trust boundary. On a single-user system (the typical Ollama deployment), this is not exploitable. On shared servers or containers with multiple users, it is.

**Effect**: Same-user to cross-user (on shared systems). The 0o777 directory allows any local user to poison model files for all users of the shared Ollama instance.

**CodeQL Reachability**: Confirmed present in code. The `0o777` mode is at `cache.go:79,85` (verified via KB Phase 6 analysis). The size-only check at `cache.go:458-465` is confirmed with the comment explicitly acknowledging the tradeoff.

**KB Cross-Reference**: Phase 6 bypass analysis (cluster: blob-integrity-skip, commit de5beb06) confirms all four vectors. The KB notes: "The 0o777 in the newer cache layer means any local user on a shared system can write to the blobs directory."

**Why ENVIRONMENT (retained, not dropped)**: The `0o777` blob directory is a deployment misconfiguration that creates a security boundary violation on shared systems. Single-user workstations are not affected. However:
- Ollama is increasingly deployed as a shared service (teams, cloud instances)
- The combination of 0o777 + size-only integrity check + no symlink protection is a three-layer failure that creates a meaningful attack surface in shared deployments
- The GGUF parser vulnerabilities (p4-f03 through p4-f06) make blob poisoning a code-execution primitive, not just a correctness issue

**Downgrade from MEDIUM to LOW?**: The finding is MEDIUM — the local privilege requirement constrains impact, but:
1. The fix is simple (change `0o777` to `0o755`, add hash verification on load)
2. The attack chain (0o777 + size match + no symlink protection) is complete and confirmed
3. Shared deployments are a documented use case

Per drop criteria: "assessable as Low severity → drop immediately." This is MEDIUM severity — retained.

**Exploit Prerequisites**:
- Multi-user system OR shared container with multiple principals
- Local filesystem write access to the blob directory (granted by `0o777` to all users)
- Knowledge of target blob filename (derivable from digest)

**Verdict**: KEEP — MEDIUM security finding (environmental/multi-user dependency). Two distinct sub-issues suitable for separate fixes: (a) change `os.MkdirAll(dir, 0o777)` to `0o755` immediately — zero-risk fix; (b) add hash verification on blob load rather than only on download.
