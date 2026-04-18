Phase: 8
Sequence: 044
Slug: blob-cache-poisoning
Verdict: VALID
Rationale: Three independent mechanisms (skipVerify on cache hit, size-only DiskCache check, symlink following) allow local blob cache poisoning with no integrity verification; enables delivery of GGUF parser exploit payloads to other users; amplified by 0o777 directory permissions in container environments. Advocate confirmed local access required but no integrity protection exists on the cache-hit path.
Severity-Original: HIGH
PoC-Status: pending
Pre-FP-Flag: none
Debate: archon/chamber-workspace/chamber-C/debate.md

## Summary

The Ollama blob caching system has three independent integrity bypass mechanisms that allow a local attacker to substitute malicious model files:

1. **skipVerify on cache hit** (server/images.go:634,640): When `downloadBlob` returns cacheHit=true (file exists via os.Stat), `verifyBlob` is skipped entirely. A modified blob is loaded without SHA-256 verification.

2. **Size-only DiskCache check** (server/internal/cache/blob/cache.go:459): `copyNamedFile` skips SHA-256 verification if a file with matching size already exists. A TODO comment explicitly acknowledges this gap.

3. **Symlink following** (server/download.go:478, manifest/layer.go:106): `os.Stat` follows symlinks. No `os.Lstat` or `O_NOFOLLOW` is used. An attacker can create a symlink at the expected blob path pointing to arbitrary content.

These mechanisms are amplified by `os.MkdirAll(dir, 0o777)` in cache.go:79,85, which creates world-writable blob directories in container environments (umask=0).

## Location

- **skipVerify**: `server/images.go:623-642` -- cache hit skips verifyBlob
- **Size-only check**: `server/internal/cache/blob/cache.go:457-464` -- `info.Size() == size` returns nil
- **Symlink gap**: `server/download.go:478` -- `os.Stat(fp)` follows symlinks
- **Permissions**: `server/internal/cache/blob/cache.go:79,85` -- `os.MkdirAll(dir, 0o777)`

## Attacker Control

Local attacker with write access to the blobs directory can:
- Replace a cached blob file with a same-size malicious file (mechanisms 1 and 2)
- Create a symlink at a blob path pointing to attacker-controlled content (mechanism 3)
- In container environments with umask=0, the 0o777 permissions grant any local user write access

## Trust Boundary Crossed

Local filesystem (attacker-writable) -> model loading pipeline -> GGUF parser / inference runtime. A local attacker can poison models loaded by other users or automated pipelines on the same system.

## Impact

- **Integrity**: Model files loaded without SHA-256 verification on cache hit path
- **Chaining**: Enables delivery of H-01 (panic), H-02 (OOM), H-03 (div-by-zero) payloads to victims
- **Container risk**: In Docker/container environments with umask=0, any process can write to blob directories
- **Deception**: UI displays "verifying sha256 digest" even when verification is skipped (images.go:638)

## Evidence

1. `server/images.go:634` -- `skipVerify[layer.Digest] = cacheHit` (true when file exists)
2. `server/images.go:640` -- `if skipVerify[layer.Digest] { continue }` (verifyBlob bypassed)
3. `server/images.go:638` -- `fn(api.ProgressResponse{Status: "verifying sha256 digest"})` (misleading UI)
4. `server/internal/cache/blob/cache.go:459` -- `if err == nil && info.Size() == size { return nil }`
5. `server/internal/cache/blob/cache.go:463` -- `// TODO: Do the hash check, but give caller a way to skip it.`
6. `server/internal/cache/blob/cache.go:79` -- `os.MkdirAll(dir, 0o777)` (world-writable in containers)
7. Deep probe PH-03, PH-04, PH-05, PH-17 validated all mechanisms independently

## Reproduction Steps

1. Start Ollama server and pull a model (`ollama pull llama3.2`)
2. Identify the blob file path: `~/.ollama/models/blobs/sha256-<digest>`
3. Create a malicious GGUF file of the same size as the legitimate blob
4. Replace the blob file: `cp malicious.gguf ~/.ollama/models/blobs/sha256-<digest>`
5. Run `ollama pull llama3.2` again -- observe "verifying sha256 digest" message but no actual verification
6. The malicious GGUF is loaded as the model. If it contains a panic-inducing payload (H-01/H-03), the server crashes.
7. Alternative (symlink): `ln -sf /path/to/malicious.gguf ~/.ollama/models/blobs/sha256-<digest>`
