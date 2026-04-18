# CVE-2024-37032 — Digest Validation Bypass Analysis

**Commit**: 2a21363b
**CVE**: CVE-2024-37032
**Cluster ID**: digest-path-traversal

## Patch Summary

The original fix added regex validation (`^sha256[:-][0-9a-fA-F]{64}$`) to `GetBlobsPath()` (now `manifest.BlobsPath()`) to prevent path traversal via crafted digest strings like `../sha256-...`. The function is used by HTTP API handlers that accept digest parameters from clients.

## Current State

The codebase has evolved significantly since the original patch:

1. **`manifest.BlobsPath()`** (manifest/paths.go:40): Retains the regex validation from the original fix. Used by HTTP route handlers (`server/routes.go:1486,1520`) that accept `c.Param("digest")` from user input. **Sound.**

2. **`blob.DiskCache`** (server/internal/cache/blob/): Uses a typed `Digest` struct backed by `[32]byte`. Path construction (`GetFile()`) formats from the binary hash: `fmt.Sprintf("sha256-%x", d.sum)`. User input never reaches the filesystem path. **Sound by design.**

3. **`blob.ParseDigest()`** (server/internal/cache/blob/digest.go:31): Validates prefix is exactly `"sha256"`, separator is `:` or `-`, hex portion is exactly 64 chars, and hex-decodes into fixed `[32]byte`. Rejects all malformed input. **Sound.**

## Bypass Hypotheses

### 1. Alternate entry points — POTENTIAL CONCERN in x/imagegen/transfer

`x/imagegen/transfer/digestToPath()` (transfer.go:151) performs NO validation — it only replaces `:` with `-` at position 6. The `Blob.Digest` field is a raw `string` that originates from JSON-deserialized manifest data (`manifest.Layer.Digest`).

**Mitigating factor**: `download.go:196` verifies the SHA256 hash after download. A traversal digest like `../../evil` would fail hash verification, and the temp file is removed via `os.Remove(tmp)`. However, `os.Create(tmp)` at line 181 writes to the traversed path *before* verification — this is a write-then-verify pattern that temporarily creates files at attacker-controlled paths.

**Severity**: Low. The `x/imagegen/transfer` package is in `x/` (experimental), the digest comes from a registry manifest (server-supplied, not direct user input), and the file is removed on hash mismatch. But a malicious registry could exploit this for temporary arbitrary file creation.

### 2. Config-gated checks — NOT BYPASSABLE

The validation in `manifest.BlobsPath()` and `blob.ParseDigest()` is unconditional. No config flag disables it.

### 3. Default-state gaps (non-sha256 digests) — SOUND

Both `manifest.BlobsPath()` and `blob.ParseDigest()` hardcode `sha256` as the only accepted prefix. No other digest algorithm is accepted. The regex requires exactly 64 hex chars (matching SHA-256 output). If future algorithms are added, the validation would need updating.

### 4. Parser differentials (URL encoding, double encoding) — NOT APPLICABLE

The digest arrives as a Go string (from Gin's `c.Param()` which already URL-decodes). The regex operates on the decoded string. No double-encoding bypass is possible since `%2F` would be decoded to `/` before regex matching, and `/` is not in `[0-9a-fA-F]`.

### 5. Missing normalization (case, Unicode) — NOT BYPASSABLE

The regex accepts `[a-fA-F]` (case-insensitive hex). The prefix check requires lowercase `sha256` exactly. `blob.ParseDigest()` uses `hex.Decode()` which normalizes to binary, eliminating any case variation in the stored form. Unicode homoglyphs would fail hex decoding.

## Bypass Verdict: **sound** (main paths), **minor concern** (x/imagegen/transfer)

The core fix in `manifest.BlobsPath()` and the newer `blob.DiskCache` architecture are both sound. The `x/imagegen/transfer` package has a weaker validation pattern (write-then-verify with raw string digest) but the practical impact is limited due to hash verification and the experimental nature of the package.

## Evidence

- `manifest/paths.go:40-47` — regex validation on all HTTP-facing digest paths
- `server/internal/cache/blob/digest.go:31-49` — typed digest with binary storage
- `server/internal/cache/blob/cache.go:325-327` — path constructed from binary hash
- `x/imagegen/transfer/transfer.go:151-155` — unvalidated `digestToPath()` 
- `x/imagegen/transfer/download.go:177-199` — write-then-verify pattern
